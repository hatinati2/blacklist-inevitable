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

    /// Assigns a process whose initial thread was created suspended, then resumes
    /// that thread only after Job Object membership is established.
    fn assign_suspended_pid(&self, pid: u32) -> Result<(), String> {
        use windows_sys::Win32::System::Threading::ResumeThread;

        assign_suspended_thread(
            pid,
            find_suspended_primary_thread,
            |process_id| self.assign_pid(process_id),
            |thread| {
                let previous_suspend_count = unsafe { ResumeThread(thread.0) };
                if previous_suspend_count == u32::MAX {
                    Err(format!(
                        "ResumeThread for contained process {pid} failed: {}",
                        std::io::Error::last_os_error()
                    ))
                } else {
                    Ok(previous_suspend_count)
                }
            },
        )
    }
}


fn assign_suspended_thread<T>(
    pid: u32,
    find_thread: impl FnOnce(u32) -> Result<T, String>,
    assign_process: impl FnOnce(u32) -> Result<(), String>,
    resume_thread: impl FnOnce(&T) -> Result<u32, String>,
) -> Result<(), String> {
    let thread = find_thread(pid)?;
    assign_process(pid)?;
    let previous_suspend_count = resume_thread(&thread)?;

    if previous_suspend_count != 1 {
        return Err(format!(
            "Process {pid} had an unexpected initial-thread suspend count ({previous_suspend_count}); it was not allowed to continue."
        ));
    }

    Ok(())
}

#[cfg(windows)]
struct SuspendedThreadHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for SuspendedThreadHandle {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        unsafe { CloseHandle(self.0) };
    }
}

#[cfg(windows)]
fn find_suspended_primary_thread(pid: u32) -> Result<SuspendedThreadHandle, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessIdOfThread, OpenThread, THREAD_QUERY_LIMITED_INFORMATION,
        THREAD_SUSPEND_RESUME,
    };

    // CREATE_SUSPENDED prevents the image's primary thread from running. Before it
    // is resumed, the process must have exactly one thread: its initial thread.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot as isize == -1 {
        return Err(format!(
            "CreateToolhelp32Snapshot failed while locating process {pid}'s suspended initial thread: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut thread_id = None;
    let mut failure = None;

    if unsafe { Thread32First(snapshot, &mut entry) } == 0 {
        failure = Some(format!(
            "Thread32First failed while locating process {pid}'s suspended initial thread: {}",
            std::io::Error::last_os_error()
        ));
    } else {
        loop {
            if entry.th32OwnerProcessID == pid {
                if thread_id.replace(entry.th32ThreadID).is_some() {
                    failure = Some(format!(
                        "Process {pid} had more than one thread before its initial thread was resumed."
                    ));
                    break;
                }
            }

            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            if unsafe { Thread32Next(snapshot, &mut entry) } == 0 {
                let error = unsafe { GetLastError() };
                // ERROR_NO_MORE_FILES is the normal end of the Tool Help snapshot.
                if error != 18 {
                    failure = Some(format!(
                        "Thread32Next failed while locating process {pid}'s suspended initial thread (Win32 error {error})."
                    ));
                }
                break;
            }
        }
    }

    unsafe { CloseHandle(snapshot) };

    if let Some(error) = failure {
        return Err(error);
    }

    let thread_id = thread_id.ok_or_else(|| {
        format!("No initial thread was found for suspended process {pid}.")
    })?;
    let thread = unsafe {
        OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
            0,
            thread_id,
        )
    };
    if thread.is_null() {
        return Err(format!(
            "OpenThread({thread_id}) failed for suspended process {pid}: {}",
            std::io::Error::last_os_error()
        ));
    }

    // A Tool Help snapshot contains IDs, not pinned handles. Verify that the
    // opened thread still belongs to the child PID before it can be resumed.
    let owner_pid = unsafe { GetProcessIdOfThread(thread) };
    if owner_pid != pid {
        unsafe { CloseHandle(thread) };
        return Err(format!(
            "The initial thread handle no longer belongs to suspended process {pid}."
        ));
    }

    Ok(SuspendedThreadHandle(thread))
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

    /// Configure an engine command so its primary thread cannot execute before
    /// Windows Job Object assignment is confirmed by assign_child.
    pub fn prepare_child_command(&self, command: &mut tokio::process::Command) {
        command.kill_on_drop(true);
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;
            command.creation_flags(CREATE_SUSPENDED);
        }
    }

    /// Assigns a suspended engine child to the app-owned Windows Job Object and
    /// resumes it only after containment is confirmed. On failure the child is
    /// terminated while still suspended wherever possible.
    pub async fn assign_child(
        &self,
        child: &mut tokio::process::Child,
    ) -> Result<(), String> {
        #[cfg(windows)]
        {
            let assignment = match (self.inner.job.as_ref(), child.id()) {
                (Some(job), Some(pid)) => job.assign_suspended_pid(pid),
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

    #[test]
    fn suspended_launch_stops_when_initial_thread_discovery_fails() {
        use std::cell::Cell;

        let assigned = Cell::new(false);
        let resumed = Cell::new(false);
        let result = assign_suspended_thread(
            42,
            |_| Err::<u32, _>("thread discovery failed".to_string()),
            |_| {
                assigned.set(true);
                Ok(())
            },
            |_| {
                resumed.set(true);
                Ok(1)
            },
        );

        assert!(result.unwrap_err().contains("thread discovery failed"));
        assert!(!assigned.get(), "a process without a verified thread must not be assigned");
        assert!(!resumed.get(), "a process without a verified thread must never be resumed");
    }

    #[test]
    fn suspended_launch_stops_when_job_assignment_fails() {
        use std::cell::Cell;

        let resumed = Cell::new(false);
        let result = assign_suspended_thread(
            42,
            |_| Ok::<u32, String>(7),
            |_| Err("Job Object assignment failed".to_string()),
            |_| {
                resumed.set(true);
                Ok(1)
            },
        );

        assert!(result.unwrap_err().contains("Job Object assignment failed"));
        assert!(!resumed.get(), "a process must not be resumed after failed Job Object assignment");
    }

    #[test]
    fn suspended_launch_stops_when_resume_fails() {
        let result = assign_suspended_thread(
            42,
            |_| Ok::<u32, String>(7),
            |_| Ok(()),
            |_| Err("ResumeThread failed".to_string()),
        );

        assert!(result.unwrap_err().contains("ResumeThread failed"));
    }

    #[test]
    fn suspended_launch_rejects_an_unexpected_suspend_count() {
        for previous_suspend_count in [0, 2] {
            let result = assign_suspended_thread(
                42,
                |_| Ok::<u32, String>(7),
                |_| Ok(()),
                |_| Ok(previous_suspend_count),
            );

            assert!(
                result.unwrap_err().contains("unexpected initial-thread suspend count"),
                "suspend count {previous_suspend_count} must not be accepted"
            );
        }
    }

    #[test]
    fn suspended_launch_assigns_before_resuming_and_requires_count_one() {
        use std::cell::RefCell;

        let calls = RefCell::new(Vec::new());
        assign_suspended_thread(
            42,
            |pid| {
                calls.borrow_mut().push(format!("find:{pid}"));
                Ok::<u32, String>(7)
            },
            |pid| {
                calls.borrow_mut().push(format!("assign:{pid}"));
                Ok(())
            },
            |thread| {
                calls.borrow_mut().push(format!("resume:{thread}"));
                Ok(1)
            },
        )
        .expect("a verified suspended launch should succeed");

        assert_eq!(
            calls.into_inner(),
            vec!["find:42", "assign:42", "resume:7"]
        );
    }

    #[cfg(windows)]
    fn supervisor_without_job_for_test() -> ProcessSupervisor {
        ProcessSupervisor {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    shutting_down: false,
                    shutdown_complete: false,
                    cleanup_healthy: false,
                    next_operation_id: 1,
                    active: HashMap::new(),
                }),
                idle: Notify::new(),
                job: None,
            }),
        }
    }


    #[cfg(windows)]
    #[tokio::test]
    async fn closing_job_object_terminates_assigned_child() {
        use std::process::Stdio;
        use tokio::process::Command;
        use tokio::time::{timeout, Duration};

        let supervisor = ProcessSupervisor::default();
        let operation = supervisor.begin_operation().expect("register test operation");
        let mut command = Command::new("powershell.exe");
        command
            .args(["-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        supervisor.prepare_child_command(&mut command);
        let mut child = command.spawn().expect("start suspended test child");
        supervisor
            .assign_child(&mut child)
            .await
            .expect("assign child through process supervisor");
        // Ensure the command is genuinely still running before releasing the final job handle.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            child
                .try_wait()
                .expect("check test child before job close")
                .is_none(),
            "test child should still be alive before job close"
        );
        drop(operation);

        // Simulate the app losing its last job handle during abrupt termination.
        drop(supervisor);
        // KILL_ON_JOB_CLOSE guarantees termination, not a particular process exit code.
        timeout(Duration::from_secs(5), child.wait())
            .await
            .expect("job close should terminate the child")
            .expect("wait for job-terminated child");
    }


    #[cfg(windows)]
    const MARKER_CHILD_ENV: &str = "BLACKLIST_INEVITABLE_TEST_MARKER_PATH";

    #[cfg(windows)]
    #[test]
    fn write_marker_child_process() {
        if let Some(path) = std::env::var_os(MARKER_CHILD_ENV) {
            std::fs::write(path, b"started").expect("write child marker");
        }
    }

    #[cfg(windows)]
    fn marker_child_command(marker: &std::path::Path) -> tokio::process::Command {
        use std::process::Stdio;
        use tokio::process::Command;

        let executable = std::env::current_exe().expect("resolve current test executable");
        let mut command = Command::new(executable);
        command
            .args([
                "--exact",
                "process_supervisor::tests::write_marker_child_process",
                "--nocapture",
            ])
            .env(MARKER_CHILD_ENV, marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn suspended_engine_child_cannot_execute_before_job_assignment() {
        use tokio::time::{sleep, timeout, Duration};

        let supervisor = ProcessSupervisor::default();

        // Repeat the launch sequence to exercise thread discovery, job assignment,
        // and resume under normal Windows process churn.
        for _ in 0..8 {
            let marker = std::env::temp_dir().join(format!(
                "blacklist-inevitable-contained-start-{}.txt",
                uuid::Uuid::new_v4()
            ));
            let mut command = marker_child_command(&marker);
            supervisor.prepare_child_command(&mut command);
            let mut child = command.spawn().expect("start suspended marker child");

            sleep(Duration::from_millis(250)).await;
            assert!(
                !marker.exists(),
                "engine child executed before Job Object assignment"
            );

            supervisor
                .assign_child(&mut child)
                .await
                .expect("assign child before allowing its first instruction");

            let status = timeout(Duration::from_secs(10), child.wait())
                .await
                .expect("marker child completion timeout")
                .expect("wait for marker child");
            assert!(status.success(), "marker child exited unsuccessfully: {status}");
            assert!(marker.is_file(), "child should run after safe resume");
            std::fs::remove_file(marker).expect("remove marker file");
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn unavailable_job_terminates_suspended_child_before_execution() {
        use tokio::time::{sleep, Duration};

        let supervisor = supervisor_without_job_for_test();
        let marker = std::env::temp_dir().join(format!(
            "blacklist-inevitable-uncontained-start-{}.txt",
            uuid::Uuid::new_v4()
        ));
        let mut command = marker_child_command(&marker);
        supervisor.prepare_child_command(&mut command);
        let mut child = command.spawn().expect("start suspended child without a job");

        sleep(Duration::from_millis(250)).await;
        assert!(
            !marker.exists(),
            "child executed before Job Object assignment was attempted"
        );

        let error = supervisor
            .assign_child(&mut child)
            .await
            .expect_err("job absence must fail closed");
        assert!(error.contains("child was stopped"));
        assert!(!marker.exists(), "uncontained child must never execute");
        assert!(!supervisor.cleanup_healthy());
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
