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
    #[cfg(windows)]
    job: Option<WindowsJobObject>,
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


#[cfg(windows)]
struct WindowsJobObject {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

// Windows kernel handles may be used by multiple threads when the owning Rust
// object is shared; the handle is closed exactly once in Drop.
#[cfg(windows)]
unsafe impl Send for WindowsJobObject {}
#[cfg(windows)]
unsafe impl Sync for WindowsJobObject {}

#[cfg(windows)]
impl WindowsJobObject {
    fn new() -> Result<Self, String> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, SetInformationJobObject,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JobObjectExtendedLimitInformation,
        };

        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(format!(
                "CreateJobObjectW failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION =
            unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };

        if configured == 0 {
            let error = std::io::Error::last_os_error();
            unsafe { CloseHandle(handle) };
            return Err(format!("SetInformationJobObject failed: {error}"));
        }

        Ok(Self { handle })
    }

    fn assign_pid(&self, pid: u32) -> Result<(), String> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
        };

        let process = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid) };
        if process.is_null() {
            return Err(format!(
                "OpenProcess({pid}) failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let assigned = unsafe { AssignProcessToJobObject(self.handle, process) };
        let error = if assigned == 0 {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        unsafe { CloseHandle(process) };

        match error {
            Some(error) => Err(format!("AssignProcessToJobObject failed: {error}")),
            None => Ok(()),
        }
    }
}

#[cfg(windows)]
impl Drop for WindowsJobObject {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        // Closing the final handle applies JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
        unsafe { CloseHandle(self.handle) };
    }
}

pub struct OperationLease {
    id: u64,
    inner: Arc<Inner>,
    cancellation: watch::Receiver<bool>,
}

impl Default for ProcessSupervisor {
    fn default() -> Self {
        // On Windows, create the kill-on-close job before any engine operation
        // is allowed to start. A failed containment setup fails closed.
        #[cfg(windows)]
        let job = WindowsJobObject::new().ok();
        #[cfg(windows)]
        let cleanup_healthy = job.is_some();
        #[cfg(not(windows))]
        let cleanup_healthy = true;

        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    shutting_down: false,
                    shutdown_complete: false,
                    cleanup_healthy,
                    next_operation_id: 1,
                    active: HashMap::new(),
                }),
                idle: Notify::new(),
                #[cfg(windows)]
                job,
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
            return Err("Engine startup is blocked because Windows process containment or previous runtime cleanup is unavailable.".to_string());
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

    /// Assigns a newly spawned engine child to the app-owned Windows Job Object.
    /// The job is configured with KILL_ON_JOB_CLOSE, so Windows terminates assigned
    /// children if the app process exits unexpectedly and its final job handle closes.
    pub async fn assign_child(
        &self,
        child: &mut tokio::process::Child,
    ) -> Result<(), String> {
        #[cfg(windows)]
        {
            let assignment = match (self.inner.job.as_ref(), child.id()) {
                (Some(job), Some(pid)) => job.assign_pid(pid),
                (None, _) => Err("The Windows process-containment Job Object is unavailable.".to_string()),
                (_, None) => Err("The newly spawned engine process has no process identifier.".to_string()),
            };

            if let Err(error) = assignment {
                let termination_confirmed = if child.start_kill().is_ok() {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(4),
                        child.wait(),
                    )
                    .await
                    {
                        Ok(Ok(_)) => true,
                        _ => false,
                    }
                } else {
                    false
                };

                self.mark_cleanup_unhealthy();
                return Err(if termination_confirmed {
                    format!("Could not place the engine process under Windows Job Object ownership ({error}); the child was stopped, and further engine work is disabled for this session.")
                } else {
                    format!("Could not place the engine process under Windows Job Object ownership ({error}), and its termination could not be confirmed; further engine work is disabled for this session.")
                });
            }
        }

        #[cfg(not(windows))]
        {
            let _ = child;
        }

        Ok(())
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
        self.inner.idle.notify_one();
        true
    }

    /// Waits until all registered engine operations have completed their cleanup.
    /// New work is rejected from the moment request_shutdown is called.
    pub async fn wait_for_idle(&self) -> bool {
        // Keep this API safe if a future caller forgets to start shutdown explicitly.
        self.request_shutdown();
        loop {
            // Keep the synchronous mutex guard in its own lexical scope. A
            // MutexGuard is not Send and must never live across this await.
            let notified = self.inner.idle.notified();
            let (is_idle, cleanup_healthy) = {
                let mut state = lock_state(&self.inner);
                if state.active.is_empty() {
                    state.shutdown_complete = true;
                    (true, state.cleanup_healthy)
                } else {
                    (false, state.cleanup_healthy)
                }
            };

            if is_idle {
                return cleanup_healthy;
            }
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
            self.inner.idle.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[cfg(windows)]
    #[tokio::test]
    async fn closing_job_object_terminates_assigned_child() {
        use std::process::Stdio;
        use tokio::process::Command;
        use tokio::time::{timeout, Duration};

        let supervisor = ProcessSupervisor::default();
        let operation = supervisor.begin_operation().expect("register test operation");
        let mut child = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("start test child");
        supervisor
            .assign_child(&mut child)
            .await
            .expect("assign child through process supervisor");
        drop(operation);

        // Simulate the app losing its last job handle during abrupt termination.
        drop(supervisor);
        let status = timeout(Duration::from_secs(5), child.wait())
            .await
            .expect("job close should terminate the child")
            .expect("wait for job-terminated child");
        assert!(!status.success(), "the job-owned child should be terminated");
    }

    #[tokio::test]
    async fn shutdown_cancels_active_operations_and_waits_for_cleanup() {
        let supervisor = ProcessSupervisor::default();
        let operation = supervisor.begin_operation().expect("operation lease");

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
            let mut child = Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 30"])
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
