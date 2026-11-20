use std::sync::{Mutex, MutexGuard};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ConnectionPhase {
    Disconnected,
    Preparing,
    StartingEngine,
    ConfiguringNetwork,
    Connected,
    Disconnecting,
    Recovering,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSnapshot {
    pub phase: ConnectionPhase,
    pub session_id: Option<u64>,
    pub profile_id: Option<String>,
    pub detail: Option<String>,
    pub cleanup_healthy: bool,
}

/// Evidence the privileged Agent must gather from the operating system before
/// it may report a VPN session as Connected. This is an internal trust-boundary
/// contract, not data that may be accepted from the unelevated UI over IPC.
///
/// Every field must be set only after checking the corresponding live OS state.
/// In particular, sing-box strict-route filters alone do not satisfy the
/// Agent-owned WFP policy requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkVerification {
    pub engine_job_contained: bool,
    pub tunnel_interface_verified: bool,
    pub ipv4_default_route_verified: bool,
    /// IPv6 is routed through the TUN, or explicitly blocked on every physical NIC.
    pub ipv6_tunneled_or_blocked: bool,
    pub encrypted_dns_path_verified: bool,
    /// A hostname bootstrap used authenticated encrypted DNS, or the endpoint
    /// was supplied as a validated numeric address; no system-DNS fallback.
    pub encrypted_endpoint_bootstrap_verified: bool,
    /// Selected routing/split-tunnel policy has no unintended Direct exceptions.
    pub routing_policy_compatible_with_leak_mode: bool,
    /// Independent Agent-owned WFP egress filters are present and active.
    pub agent_wfp_egress_policy_active: bool,
    /// WFP provider, sublayer and filters use a tested persistent/recovery design.
    pub agent_wfp_policy_persistence_verified: bool,
    /// Physical-interface leak probes found no user-data egress outside the allowlist.
    pub physical_egress_leak_probe_passed: bool,
}

impl NetworkVerification {
    pub fn missing_requirements(&self) -> Vec<&'static str> {
        let checks = [
            (self.engine_job_contained, "engine Job Object containment"),
            (self.tunnel_interface_verified, "TUN interface identity and addresses"),
            (self.ipv4_default_route_verified, "IPv4 default route"),
            (self.ipv6_tunneled_or_blocked, "IPv6 tunnel route or physical-egress block"),
            (self.encrypted_dns_path_verified, "in-tunnel encrypted DNS path"),
            (self.encrypted_endpoint_bootstrap_verified, "encrypted VPN endpoint bootstrap"),
            (self.routing_policy_compatible_with_leak_mode, "routing policy compatible with leak-prevention mode"),
            (self.agent_wfp_egress_policy_active, "independent Agent-owned WFP egress policy"),
            (self.agent_wfp_policy_persistence_verified, "persistent WFP policy and recovery behavior"),
            (self.physical_egress_leak_probe_passed, "physical-interface egress leak probes"),
        ];
        checks
            .into_iter()
            .filter_map(|(passed, name)| (!passed).then_some(name))
            .collect()
    }

    pub fn validate(&self) -> Result<(), String> {
        let missing = self.missing_requirements();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "Cannot report Connected; required security verification is missing: {}.",
                missing.join(", ")
            ))
        }
    }
}

struct Inner {
    snapshot: ConnectionSnapshot,
    next_session_id: u64,
}

pub struct ConnectionCoordinator {
    inner: Mutex<Inner>,
}

impl Default for ConnectionCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionCoordinator {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                snapshot: ConnectionSnapshot {
                    phase: ConnectionPhase::Disconnected,
                    session_id: None,
                    profile_id: None,
                    detail: None,
                    cleanup_healthy: true,
                },
                next_session_id: 1,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(inner) => inner,
            Err(poisoned) => {
                let mut inner = poisoned.into_inner();
                inner.snapshot.cleanup_healthy = false;
                inner.snapshot.phase = ConnectionPhase::Failed;
                inner.snapshot.detail = Some(
                    "The connection coordinator lock was poisoned; network cleanup must be verified before reconnecting."
                        .to_string(),
                );
                self.inner.clear_poison();
                inner
            }
        }
    }

    pub fn snapshot(&self) -> ConnectionSnapshot {
        self.lock().snapshot.clone()
    }

    /// Reserve one session. A UI request cannot start a second session while
    /// any previous connect/disconnect/recovery operation is still in progress.
    pub fn begin_connect(&self, profile_id: &str) -> Result<u64, String> {
        let profile_id = profile_id.trim();
        if profile_id.is_empty() || profile_id.len() > 128 {
            return Err("A valid profile identifier is required.".to_string());
        }

        let mut inner = self.lock();
        if !inner.snapshot.cleanup_healthy {
            return Err(
                "Connect is blocked because previous network/process cleanup is not confirmed."
                    .to_string(),
            );
        }
        if inner.snapshot.phase != ConnectionPhase::Disconnected {
            return Err(format!(
                "Connect is not allowed while the connection is {:?}.",
                inner.snapshot.phase
            ));
        }

        let session_id = inner.next_session_id;
        inner.next_session_id = inner.next_session_id.wrapping_add(1).max(1);
        inner.snapshot = ConnectionSnapshot {
            phase: ConnectionPhase::Preparing,
            session_id: Some(session_id),
            profile_id: Some(profile_id.to_string()),
            detail: None,
            cleanup_healthy: true,
        };
        Ok(session_id)
    }

    pub fn begin_engine(&self, session_id: u64) -> Result<(), String> {
        self.transition(
            session_id,
            ConnectionPhase::Preparing,
            ConnectionPhase::StartingEngine,
        )
    }

    pub fn engine_ready(&self, session_id: u64) -> Result<(), String> {
        self.transition(
            session_id,
            ConnectionPhase::StartingEngine,
            ConnectionPhase::ConfiguringNetwork,
        )
    }

    /// This transition is allowed only when the privileged Agent supplies
    /// positive evidence for every traffic-safety requirement. Never construct
    /// this proof from UI/IPC-provided booleans.
    pub fn network_verified(
        &self,
        session_id: u64,
        verification: NetworkVerification,
    ) -> Result<(), String> {
        verification.validate()?;
        self.transition(
            session_id,
            ConnectionPhase::ConfiguringNetwork,
            ConnectionPhase::Connected,
        )
    }

    fn transition(
        &self,
        session_id: u64,
        expected: ConnectionPhase,
        next: ConnectionPhase,
    ) -> Result<(), String> {
        let mut inner = self.lock();
        ensure_session(&inner.snapshot, session_id)?;
        if inner.snapshot.phase != expected {
            return Err(format!(
                "Invalid connection transition from {:?}; expected {:?}.",
                inner.snapshot.phase, expected
            ));
        }
        if !inner.snapshot.cleanup_healthy {
            return Err(
                "Connection transitions are blocked by an unhealthy cleanup state.".to_string(),
            );
        }
        inner.snapshot.phase = next;
        inner.snapshot.detail = None;
        Ok(())
    }

    /// Idempotent for repeated requests on the same session. A stale session
    /// token can never disconnect a newer session.
    pub fn begin_disconnect(&self, session_id: u64) -> Result<(), String> {
        let mut inner = self.lock();
        if inner.snapshot.phase == ConnectionPhase::Disconnected
            && inner.snapshot.session_id.is_none()
        {
            return Ok(());
        }
        ensure_session(&inner.snapshot, session_id)?;
        match inner.snapshot.phase {
            ConnectionPhase::Disconnecting => Ok(()),
            ConnectionPhase::Preparing
            | ConnectionPhase::StartingEngine
            | ConnectionPhase::ConfiguringNetwork
            | ConnectionPhase::Connected
            | ConnectionPhase::Failed => {
                inner.snapshot.phase = ConnectionPhase::Disconnecting;
                inner.snapshot.detail = None;
                Ok(())
            }
            phase => Err(format!(
                "Disconnect is not allowed while the connection is {:?}.",
                phase
            )),
        }
    }

    /// The session returns to Disconnected only after the caller has confirmed
    /// engine exit, TUN teardown, route/DNS restoration, and policy cleanup.
    pub fn finish_disconnect(
        &self,
        session_id: u64,
        cleanup_confirmed: bool,
        detail: Option<String>,
    ) -> Result<(), String> {
        let mut inner = self.lock();
        ensure_session(&inner.snapshot, session_id)?;
        if inner.snapshot.phase != ConnectionPhase::Disconnecting {
            return Err(format!(
                "Disconnect completion is invalid while the connection is {:?}.",
                inner.snapshot.phase
            ));
        }

        if cleanup_confirmed {
            inner.snapshot = disconnected_snapshot();
        } else {
            inner.snapshot.phase = ConnectionPhase::Failed;
            inner.snapshot.cleanup_healthy = false;
            inner.snapshot.detail = Some(detail.unwrap_or_else(|| {
                "Network cleanup could not be confirmed; reconnect is blocked.".to_string()
            }));
        }
        Ok(())
    }

    pub fn fail_session(
        &self,
        session_id: u64,
        detail: impl Into<String>,
        cleanup_confirmed: bool,
    ) -> Result<(), String> {
        let mut inner = self.lock();
        ensure_session(&inner.snapshot, session_id)?;
        inner.snapshot.phase = ConnectionPhase::Failed;
        inner.snapshot.cleanup_healthy = cleanup_confirmed;
        inner.snapshot.detail = Some(detail.into());
        Ok(())
    }

    /// Startup recovery is required before new sessions can be accepted when a
    /// previous process may have left network resources behind.
    pub fn begin_recovery(&self) -> Result<u64, String> {
        let mut inner = self.lock();
        if inner.snapshot.phase != ConnectionPhase::Disconnected
            && inner.snapshot.phase != ConnectionPhase::Failed
        {
            return Err(format!(
                "Recovery cannot start while the connection is {:?}.",
                inner.snapshot.phase
            ));
        }

        let recovery_id = inner.next_session_id;
        inner.next_session_id = inner.next_session_id.wrapping_add(1).max(1);
        inner.snapshot.phase = ConnectionPhase::Recovering;
        inner.snapshot.session_id = Some(recovery_id);
        inner.snapshot.profile_id = None;
        inner.snapshot.cleanup_healthy = false;
        inner.snapshot.detail = Some("Reconciling previous VPN session resources.".to_string());
        Ok(recovery_id)
    }

    pub fn finish_recovery(
        &self,
        recovery_id: u64,
        cleanup_confirmed: bool,
        detail: Option<String>,
    ) -> Result<(), String> {
        let mut inner = self.lock();
        ensure_session(&inner.snapshot, recovery_id)?;
        if inner.snapshot.phase != ConnectionPhase::Recovering {
            return Err(format!(
                "Recovery completion is invalid while the connection is {:?}.",
                inner.snapshot.phase
            ));
        }

        if cleanup_confirmed {
            inner.snapshot = disconnected_snapshot();
        } else {
            inner.snapshot.phase = ConnectionPhase::Failed;
            inner.snapshot.cleanup_healthy = false;
            inner.snapshot.detail = Some(detail.unwrap_or_else(|| {
                "Previous VPN resources could not be reconciled; Connect remains blocked."
                    .to_string()
            }));
        }
        Ok(())
    }

    pub fn clear_confirmed_failure(&self) -> Result<(), String> {
        let mut inner = self.lock();
        if inner.snapshot.phase != ConnectionPhase::Failed {
            return Err("There is no failed connection to clear.".to_string());
        }
        if !inner.snapshot.cleanup_healthy {
            return Err(
                "The failed session still has unconfirmed cleanup; recovery is required."
                    .to_string(),
            );
        }
        inner.snapshot = disconnected_snapshot();
        Ok(())
    }
}

fn disconnected_snapshot() -> ConnectionSnapshot {
    ConnectionSnapshot {
        phase: ConnectionPhase::Disconnected,
        session_id: None,
        profile_id: None,
        detail: None,
        cleanup_healthy: true,
    }
}

fn ensure_session(snapshot: &ConnectionSnapshot, session_id: u64) -> Result<(), String> {
    if snapshot.session_id == Some(session_id) {
        Ok(())
    } else {
        Err("The connection operation belongs to a stale or unknown session.".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_network_verification() -> NetworkVerification {
        NetworkVerification {
            engine_job_contained: true,
            tunnel_interface_verified: true,
            ipv4_default_route_verified: true,
            ipv6_tunneled_or_blocked: true,
            encrypted_dns_path_verified: true,
            encrypted_endpoint_bootstrap_verified: true,
            routing_policy_compatible_with_leak_mode: true,
            agent_wfp_egress_policy_active: true,
            agent_wfp_policy_persistence_verified: true,
            physical_egress_leak_probe_passed: true,
        }
    }

    #[test]
    fn refuses_connected_when_any_security_requirement_is_missing() {
        let cases: Vec<(&str, fn(&mut NetworkVerification))> = vec![
            ("engine Job Object containment", |v| v.engine_job_contained = false),
            ("TUN interface identity and addresses", |v| v.tunnel_interface_verified = false),
            ("IPv4 default route", |v| v.ipv4_default_route_verified = false),
            ("IPv6 tunnel route or physical-egress block", |v| v.ipv6_tunneled_or_blocked = false),
            ("in-tunnel encrypted DNS path", |v| v.encrypted_dns_path_verified = false),
            ("encrypted VPN endpoint bootstrap", |v| v.encrypted_endpoint_bootstrap_verified = false),
            ("routing policy compatible with leak-prevention mode", |v| v.routing_policy_compatible_with_leak_mode = false),
            ("independent Agent-owned WFP egress policy", |v| v.agent_wfp_egress_policy_active = false),
            ("persistent WFP policy and recovery behavior", |v| v.agent_wfp_policy_persistence_verified = false),
            ("physical-interface egress leak probes", |v| v.physical_egress_leak_probe_passed = false),
        ];

        for (expected, disable_check) in cases {
            let mut verification = complete_network_verification();
            disable_check(&mut verification);
            let error = verification.validate().unwrap_err();
            assert!(error.contains(expected), "missing {expected}: {error}");
        }
    }

    #[test]
    fn invalid_security_proof_cannot_advance_connection_to_connected() {
        let coordinator = ConnectionCoordinator::new();
        let session = coordinator.begin_connect("profile-1").unwrap();
        coordinator.begin_engine(session).unwrap();
        coordinator.engine_ready(session).unwrap();

        assert!(coordinator
            .network_verified(session, NetworkVerification::default())
            .is_err());
        assert_eq!(
            coordinator.snapshot().phase,
            ConnectionPhase::ConfiguringNetwork
        );

        coordinator
            .network_verified(session, complete_network_verification())
            .unwrap();
        assert_eq!(coordinator.snapshot().phase, ConnectionPhase::Connected);
    }

    #[test]
    fn accepts_only_the_ordered_connect_path() {
        let coordinator = ConnectionCoordinator::new();
        let session = coordinator.begin_connect("profile-1").unwrap();

        assert_eq!(coordinator.snapshot().phase, ConnectionPhase::Preparing);
        assert!(coordinator
            .network_verified(session, NetworkVerification::default())
            .is_err());

        coordinator.begin_engine(session).unwrap();
        assert_eq!(
            coordinator.snapshot().phase,
            ConnectionPhase::StartingEngine
        );

        coordinator.engine_ready(session).unwrap();
        assert_eq!(
            coordinator.snapshot().phase,
            ConnectionPhase::ConfiguringNetwork
        );

        coordinator
            .network_verified(session, complete_network_verification())
            .unwrap();
        assert_eq!(coordinator.snapshot().phase, ConnectionPhase::Connected);
    }

    #[test]
    fn rejects_duplicate_connect_and_stale_session_operations() {
        let coordinator = ConnectionCoordinator::new();
        let first = coordinator.begin_connect("profile-1").unwrap();

        assert!(coordinator.begin_connect("profile-2").is_err());
        assert!(coordinator.begin_engine(first.wrapping_add(1)).is_err());

        coordinator.begin_disconnect(first).unwrap();
        coordinator.finish_disconnect(first, true, None).unwrap();

        let second = coordinator.begin_connect("profile-2").unwrap();
        assert_ne!(first, second);
        assert!(coordinator.begin_disconnect(first).is_err());
    }

    #[test]
    fn repeated_disconnect_is_idempotent_but_stale_disconnect_is_rejected() {
        let coordinator = ConnectionCoordinator::new();
        let session = coordinator.begin_connect("profile-1").unwrap();

        coordinator.begin_disconnect(session).unwrap();
        coordinator.begin_disconnect(session).unwrap();
        coordinator.finish_disconnect(session, true, None).unwrap();

        assert!(coordinator.begin_disconnect(session).is_ok());
        assert_eq!(coordinator.snapshot().phase, ConnectionPhase::Disconnected);
    }

    #[test]
    fn blocks_reconnect_when_disconnect_cleanup_is_uncertain() {
        let coordinator = ConnectionCoordinator::new();
        let session = coordinator.begin_connect("profile-1").unwrap();
        coordinator.begin_disconnect(session).unwrap();
        coordinator
            .finish_disconnect(session, false, Some("route restore failed".to_string()))
            .unwrap();

        let snapshot = coordinator.snapshot();
        assert_eq!(snapshot.phase, ConnectionPhase::Failed);
        assert!(!snapshot.cleanup_healthy);
        assert!(coordinator.begin_connect("profile-2").is_err());
        assert!(coordinator.clear_confirmed_failure().is_err());

        let recovery = coordinator.begin_recovery().unwrap();
        coordinator.finish_recovery(recovery, true, None).unwrap();
        assert_eq!(coordinator.snapshot().phase, ConnectionPhase::Disconnected);
        assert!(coordinator.snapshot().cleanup_healthy);
    }

    #[test]
    fn allows_new_connect_after_a_failure_with_confirmed_cleanup() {
        let coordinator = ConnectionCoordinator::new();
        let first = coordinator.begin_connect("profile-1").unwrap();
        coordinator
            .fail_session(first, "engine rejected the profile", true)
            .unwrap();

        assert!(coordinator.clear_confirmed_failure().is_ok());
        let second = coordinator.begin_connect("profile-2").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn stale_recovery_completion_cannot_reset_a_new_connection() {
        let coordinator = ConnectionCoordinator::new();
        let recovery = coordinator.begin_recovery().unwrap();
        coordinator.finish_recovery(recovery, true, None).unwrap();

        let session = coordinator.begin_connect("profile-1").unwrap();
        let error = coordinator.finish_recovery(recovery, true, None).unwrap_err();

        assert!(error.contains("stale"));
        assert_eq!(coordinator.snapshot().session_id, Some(session));
        assert_eq!(coordinator.snapshot().phase, ConnectionPhase::Preparing);
    }

    #[test]
    fn recovery_failure_keeps_connect_blocked() {
        let coordinator = ConnectionCoordinator::new();
        let recovery = coordinator.begin_recovery().unwrap();
        coordinator
            .finish_recovery(recovery, false, Some("stale route remains".to_string()))
            .unwrap();

        assert_eq!(coordinator.snapshot().phase, ConnectionPhase::Failed);
        assert!(!coordinator.snapshot().cleanup_healthy);
        assert!(coordinator.begin_connect("profile-1").is_err());
    }

    #[test]
    fn rejects_empty_or_oversized_profile_identifiers() {
        let coordinator = ConnectionCoordinator::new();
        assert!(coordinator.begin_connect(" ").is_err());
        assert!(coordinator.begin_connect(&"x".repeat(129)).is_err());
    }
}
