use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::{watch, Notify};

#[derive(Clone)]
pub struct ProcessSupervisor {
    inner: Arc<Inner>,
}

struct Inner {
    state: Mutex<State>,
    idle: Notify,
}

fn lock_state(inner: &Inner) -> MutexGuard<'_, State> {
    match inner.state.lock() {
        Ok(state) => state,
        Err(poisoned) => {
            let mut state = poisoned.into_inner();
            // Recover enough state to finish shutdown, but never permit new engine work.
            state.cleanup_healthy = false;
            state
        }
    }
}

struct State {
    shutting_down: bool,
    shutdown_complete: bool,
    cleanup_healthy: bool,
    next_operation_id: u64,
    active: HashMap<u64, watch::Sender<bool>>,
}

pub struct OperationLease {
    id: u64,
    inner: Arc<Inner>,
    cancellation: watch::Receiver<bool>,
}

impl Default for ProcessSupervisor {
    fn default() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    shutting_down: false,
                    shutdown_complete: false,
                    cleanup_healthy: true,
                    next_operation_id: 1,
                    active: HashMap::new(),
                }),
                idle: Notify::new(),
            }),
        }
    }
}

impl ProcessSupervisor {
    pub fn begin_operation(&self) -> Result<OperationLease, String> {
        let (sender, receiver) = watch::channel(false);
        let mut state = lock_state(&self.inner);

        if state.shutting_down {
            return Err("The application is shutting down; no new engine process may start.".to_string());
        }
        if !state.cleanup_healthy {
            return Err("Engine startup is blocked because previous process or temporary-file cleanup was not confirmed.".to_string());
        }

        let id = state.next_operation_id;
        state.next_operation_id = state.next_operation_id.wrapping_add(1).max(1);
        state.active.insert(id, sender);

        Ok(OperationLease {
            id,
            inner: Arc::clone(&self.inner),
            cancellation: receiver,
        })
    }

    /// Prevents new operations and signals every active operation to stop.
    /// Returns true only for the first caller that begins shutdown.
    pub fn request_shutdown(&self) -> bool {
        let senders = {
            let mut state = lock_state(&self.inner);
            if state.shutting_down {
                return false;
            }
            state.shutting_down = true;
            state.active.values().cloned().collect::<Vec<_>>()
        };

        for sender in senders {
            sender.send_replace(true);
        }
        self.inner.idle.notify_waiters();
        true
    }

    /// Waits until all registered engine operations have completed their cleanup.
    /// New work is rejected from the moment request_shutdown is called.
    pub async fn wait_for_idle(&self) -> bool {
        loop {
            let notified = self.inner.idle.notified();
            let mut state = lock_state(&self.inner);

            if state.active.is_empty() {
                state.shutdown_complete = true;
                return state.cleanup_healthy;
            }

            drop(state);
            notified.await;
        }
    }

    pub fn shutdown_complete(&self) -> bool {
        lock_state(&self.inner).shutdown_complete
    }

    pub fn cleanup_healthy(&self) -> bool {
        lock_state(&self.inner).cleanup_healthy
    }

    pub(crate) fn mark_cleanup_unhealthy(&self) {
        lock_state(&self.inner).cleanup_healthy = false;
    }
}

impl OperationLease {
    pub fn is_cancelled(&self) -> bool {
        *self.cancellation.borrow()
    }

    pub async fn cancelled(&mut self) {
        if self.is_cancelled() {
            return;
        }
        let _ = self.cancellation.changed().await;
    }

    pub fn mark_cleanup_unhealthy(&self) {
        lock_state(&self.inner).cleanup_healthy = false;
    }
}

impl Drop for OperationLease {
    fn drop(&mut self) {
        let became_idle = {
            let mut state = lock_state(&self.inner);
            state.active.remove(&self.id);
            state.active.is_empty()
        };

        if became_idle {
            self.inner.idle.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_cancels_active_operations_and_waits_for_cleanup() {
        let supervisor = ProcessSupervisor::default();
        let operation = supervisor.begin_operation().expect("operation lease");
        let mut operation = operation;

        assert!(supervisor.request_shutdown());
        assert!(operation.is_cancelled());
        assert!(supervisor.begin_operation().is_err());
        assert!(!supervisor.shutdown_complete());

        drop(operation);
        assert!(supervisor.wait_for_idle().await);
        assert!(supervisor.shutdown_complete());
    }

    #[tokio::test]
    async fn cleanup_failure_keeps_future_engine_startup_blocked() {
        let supervisor = ProcessSupervisor::default();
        let operation = supervisor.begin_operation().expect("operation lease");
        operation.mark_cleanup_unhealthy();
        drop(operation);

        assert!(supervisor.begin_operation().is_err());
        assert!(supervisor.request_shutdown());
        assert!(!supervisor.wait_for_idle().await);
        assert!(!supervisor.cleanup_healthy());
    }

    #[test]
    fn shutdown_request_is_idempotent() {
        let supervisor = ProcessSupervisor::default();

        assert!(supervisor.request_shutdown());
        assert!(!supervisor.request_shutdown());
        assert!(supervisor.begin_operation().is_err());
    }

    #[tokio::test]
    async fn shutdown_waits_until_a_cancelled_child_is_killed_and_waited() {
        use std::process::Stdio;
        use tokio::process::Command;
        use tokio::time::{sleep, timeout, Duration};

        let supervisor = ProcessSupervisor::default();
        let mut operation = supervisor.begin_operation().expect("operation lease");

        let worker = tokio::spawn(async move {
            #[cfg(windows)]
            let mut child = Command::new("cmd")
                .args(["/C", "ping", "-n", "30", "127.0.0.1"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .expect("start test child");

            #[cfg(unix)]
            let mut child = Command::new("sh")
                .args(["-c", "sleep 30"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .expect("start test child");

            tokio::select! {
                _ = operation.cancelled() => {
                    child.kill().await.expect("kill and wait for test child");
                }
                _ = child.wait() => {}
            }
            drop(operation);
        });

        sleep(Duration::from_millis(100)).await;
        assert!(supervisor.request_shutdown());
        assert!(timeout(Duration::from_secs(5), supervisor.wait_for_idle())
            .await
            .expect("supervisor drain timeout"));
        worker.await.expect("worker task");
    }
}
