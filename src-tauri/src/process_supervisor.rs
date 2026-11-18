use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{watch, Notify};

#[derive(Clone)]
pub struct ProcessSupervisor {
    inner: Arc<Inner>,
}

struct Inner {
    state: Mutex<State>,
    idle: Notify,
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
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| "The process supervisor state is unavailable.".to_string())?;

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
            let Ok(mut state) = self.inner.state.lock() else {
                return false;
            };
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
            let Ok(mut state) = self.inner.state.lock() else {
                return false;
            };

            if state.active.is_empty() {
                state.shutdown_complete = true;
                return state.cleanup_healthy;
            }

            drop(state);
            notified.await;
        }
    }

    pub fn shutdown_complete(&self) -> bool {
        self.inner
            .state
            .lock()
            .map(|state| state.shutdown_complete)
            .unwrap_or(false)
    }

    pub fn cleanup_healthy(&self) -> bool {
        self.inner
            .state
            .lock()
            .map(|state| state.cleanup_healthy)
            .unwrap_or(false)
    }

    fn mark_cleanup_unhealthy(&self) {
        if let Ok(mut state) = self.inner.state.lock() {
            state.cleanup_healthy = false;
        }
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
        if let Ok(mut state) = self.inner.state.lock() {
            state.cleanup_healthy = false;
        }
    }
}

impl Drop for OperationLease {
    fn drop(&mut self) {
        let became_idle = self
            .inner
            .state
            .lock()
            .map(|mut state| {
                state.active.remove(&self.id);
                state.active.is_empty()
            })
            .unwrap_or(false);

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
}
