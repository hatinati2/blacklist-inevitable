//! Read-only route/interface change invalidation for future VPN egress transactions.
//!
//! Notifications only advance a process-wide generation counter. Callback code
//! never dereferences OS-owned row pointers, allocates, locks, or calls cancellation
//! APIs. A caller snapshots the generation after registration, calculates its
//! physical-interface inventory and endpoint routes, then checks the generation
//! again immediately before any future policy transaction.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkEpoch {
    generation: u64,
}

impl NetworkEpoch {
    pub fn generation(self) -> u64 {
        self.generation
    }
}

struct GenerationClock {
    generation: AtomicU64,
    exhausted: AtomicBool,
}

impl GenerationClock {
    const fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            exhausted: AtomicBool::new(false),
        }
    }

    fn mark_changed(&self) {
        if self
            .generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| value.checked_add(1))
            .is_err()
        {
            // Never let generation wraparound make an old snapshot current (ABA).
            self.exhausted.store(true, Ordering::Release);
        }
    }

    fn snapshot(&self) -> Option<NetworkEpoch> {
        if self.exhausted.load(Ordering::Acquire) {
            return None;
        }
        let generation = self.generation.load(Ordering::Acquire);
        if self.exhausted.load(Ordering::Acquire) {
            return None;
        }
        Some(NetworkEpoch { generation })
    }

    fn is_current(&self, snapshot: NetworkEpoch) -> bool {
        !self.exhausted.load(Ordering::Acquire)
            && self.generation.load(Ordering::Acquire) == snapshot.generation
            && !self.exhausted.load(Ordering::Acquire)
    }
}

static NETWORK_GENERATION: GenerationClock = GenerationClock::new();

#[cfg(windows)]
mod windows {
    use super::{NetworkEpoch, NETWORK_GENERATION};
    use std::ffi::c_void;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
        MIB_NOTIFICATION_TYPE, NotifyIpInterfaceChange, NotifyRouteChange2,
    };

    const AF_UNSPEC: u16 = 0;

    unsafe extern "system" fn route_changed(
        _caller_context: *const c_void,
        _row: *const MIB_IPFORWARD_ROW2,
        _notification_type: MIB_NOTIFICATION_TYPE,
    ) {
        // The row memory belongs to Windows and is intentionally not read.
        NETWORK_GENERATION.mark_changed();
    }

    unsafe extern "system" fn interface_changed(
        _caller_context: *const c_void,
        _row: *const MIB_IPINTERFACE_ROW,
        _notification_type: MIB_NOTIFICATION_TYPE,
    ) {
        NETWORK_GENERATION.mark_changed();
    }

    /// Owns IPv4/IPv6 route and IP-interface subscriptions.
    ///
    /// Both registrations use AF_UNSPEC so IPv4 and IPv6 changes invalidate the
    /// same snapshot. InitialNotification is false: callers take their initial
    /// snapshot only after both registrations have succeeded.
    pub struct NetworkChangeMonitor {
        handles: [HANDLE; 2],
        active: bool,
    }

    impl NetworkChangeMonitor {
        pub fn start() -> Result<Self, String> {
            let mut monitor = Self {
                handles: [null_mut(); 2],
                active: false,
            };

            let route_status = unsafe {
                NotifyRouteChange2(
                    AF_UNSPEC,
                    Some(route_changed),
                    std::ptr::null(),
                    false,
                    &mut monitor.handles[0],
                )
            };
            if route_status != 0 || monitor.handles[0].is_null() {
                let detail = if route_status != 0 {
                    format!("Windows error {route_status}")
                } else {
                    "Windows returned a null route notification handle".into()
                };
                drop(monitor);
                return Err(format!("Could not subscribe to IPv4/IPv6 route changes: {detail}."));
            }

            let interface_status = unsafe {
                NotifyIpInterfaceChange(
                    AF_UNSPEC,
                    Some(interface_changed),
                    std::ptr::null(),
                    false,
                    &mut monitor.handles[1],
                )
            };
            if interface_status != 0 || monitor.handles[1].is_null() {
                let detail = if interface_status != 0 {
                    format!("Windows error {interface_status}")
                } else {
                    "Windows returned a null IP-interface notification handle".into()
                };
                drop(monitor);
                return Err(format!(
                    "Could not subscribe to IPv4/IPv6 IP-interface changes: {detail}."
                ));
            }

            monitor.active = true;
            Ok(monitor)
        }

        /// Capture the current invalidation generation after subscriptions are live.
        pub fn snapshot(&self) -> Result<NetworkEpoch, String> {
            if !self.active {
                return Err("The Windows network change monitor is not active.".into());
            }
            NETWORK_GENERATION.snapshot().ok_or_else(|| {
                "The network change generation is exhausted; refusing to trust a route snapshot."
                    .into()
            })
        }

        /// Returns true only when no observed route/interface notification has
        /// occurred since the supplied snapshot and the monitor is still active.
        ///
        /// This is a point-in-time guard, not a lock on the Windows route table.
        pub fn is_current(&self, snapshot: NetworkEpoch) -> bool {
            self.active && NETWORK_GENERATION.is_current(snapshot)
        }

        /// Explicitly unregister both callbacks. Call outside notification callbacks.
        /// On failure, Drop makes a best-effort retry and the caller must fail closed.
        pub fn shutdown(mut self) -> Result<(), String> {
            self.cancel_registered_handles()
        }

        fn cancel_registered_handles(&mut self) -> Result<(), String> {
            let mut failures = Vec::new();
            for (index, handle) in self.handles.iter_mut().enumerate().rev() {
                if handle.is_null() {
                    continue;
                }
                let status = unsafe { CancelMibChangeNotify2(*handle) };
                if status == 0 {
                    *handle = null_mut();
                } else {
                    failures.push(format!(
                        "CancelMibChangeNotify2 failed for notification {index} with Windows error {status}"
                    ));
                }
            }
            self.active = false;
            if failures.is_empty() {
                Ok(())
            } else {
                Err(failures.join("; "))
            }
        }
    }

    impl Drop for NetworkChangeMonitor {
        fn drop(&mut self) {
            // The callbacks never own this object and never cancel themselves.
            // Cancellation from the notification callback thread can deadlock.
            let _ = self.cancel_registered_handles();
        }
    }
}

#[cfg(windows)]
pub use windows::NetworkChangeMonitor;

#[cfg(test)]
mod tests {
    use super::GenerationClock;

    #[test]
    fn route_or_interface_change_invalidates_previous_snapshot() {
        let clock = GenerationClock::new();
        let before = clock.snapshot().unwrap();
        assert!(clock.is_current(before));

        clock.mark_changed();
        assert!(!clock.is_current(before));

        let after = clock.snapshot().unwrap();
        assert!(clock.is_current(after));
        assert!(after.generation() > before.generation());
    }

    #[test]
    fn repeated_changes_keep_generations_monotonic() {
        let clock = GenerationClock::new();
        let first = clock.snapshot().unwrap();
        for _ in 0..10 {
            clock.mark_changed();
        }
        let latest = clock.snapshot().unwrap();
        assert_eq!(latest.generation(), first.generation() + 10);
        assert!(!clock.is_current(first));
        assert!(clock.is_current(latest));
    }

    #[test]
    fn generation_exhaustion_poisoning_never_wraps_to_a_valid_snapshot() {
        let clock = GenerationClock {
            generation: std::sync::atomic::AtomicU64::new(u64::MAX),
            exhausted: std::sync::atomic::AtomicBool::new(false),
        };
        clock.mark_changed();
        assert!(clock.snapshot().is_none());
        assert!(!clock.is_current(super::NetworkEpoch { generation: u64::MAX }));
    }
}
