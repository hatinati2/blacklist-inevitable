//! Read-only, consistency-checked composition of physical-interface discovery,
//! VPN endpoint route resolution, and route/interface change invalidation.
//!
//! This module does not install WFP filters, modify routes or DNS, change adapter
//! state, or start the VPN engine. It produces an exact route-bound policy plan
//! while retaining the change monitor that makes the snapshot invalidatable.

#[cfg(windows)]
use crate::windows_network_change::{NetworkChangeMonitor, NetworkEpoch};
#[cfg(windows)]
use crate::windows_route::ResolvedVpnEndpointEgress;
#[cfg(windows)]
use crate::wfp_policy::{EgressPolicySpec, TransportProtocol, VpnEndpoint, WfpPolicyPlan};

/// A point-in-time egress plan whose endpoint permits are pinned to the exact
/// interface selected by Windows for each numeric VPN endpoint.
#[cfg(windows)]
pub struct WindowsEgressSnapshot {
    monitor: NetworkChangeMonitor,
    epoch: NetworkEpoch,
    spec: EgressPolicySpec,
    resolved_endpoints: Vec<ResolvedVpnEndpointEgress>,
    plan: WfpPolicyPlan,
}

#[cfg(windows)]
impl WindowsEgressSnapshot {
    /// Resolve a proxy hostname through encrypted DoH, preserve the caller's
    /// exact transport tuple, then capture Windows physical routes.
    /// No system-DNS/plaintext fallback is available. The initial DoH exchange
    /// occurs before this route snapshot and before tunnel startup.
    ///
    /// The caller must supply the protocol selected by the engine adapter; this
    /// method deliberately does not infer TCP/UDP from a profile name.
    pub async fn capture_for_server(
        server: &str,
        port: u16,
        protocol: TransportProtocol,
    ) -> Result<Self, String> {
        let resolver = crate::endpoint_bootstrap::EndpointBootstrapResolver::new()?;
        let endpoints = resolver.resolve_vpn_endpoints(server, port, protocol).await?;
        Self::capture(&endpoints)
    }

    /// Capture physical candidates, resolve every endpoint, and compile a
    /// route-bound plan. Any observed change during capture rejects the result.
    pub fn capture(endpoints: &[VpnEndpoint]) -> Result<Self, String> {
        let monitor = NetworkChangeMonitor::start()?;
        let epoch = monitor.snapshot()?;

        let physical_interfaces =
            crate::windows_interfaces::discover_hardware_egress_interfaces()?;
        let resolved_endpoints =
            crate::windows_route::resolve_vpn_endpoint_egress(endpoints, &physical_interfaces)?;

        let spec = EgressPolicySpec {
            physical_interfaces,
            vpn_endpoints: endpoints.to_vec(),
        };
        let plan = spec.compile_plan_with_resolved_egress(&resolved_endpoints)?;

        if !monitor.is_current(epoch) {
            return Err("The Windows route or IP-interface table changed during egress snapshot capture; discard and retry.".into());
        }

        Ok(Self { monitor, epoch, spec, resolved_endpoints, plan })
    }

    /// Fail closed if any route/interface notification invalidated the snapshot.
    pub fn ensure_current(&self) -> Result<(), String> {
        if self.monitor.is_current(self.epoch) {
            Ok(())
        } else {
            Err("The Windows egress snapshot is stale; rediscover physical interfaces and re-resolve every VPN endpoint before WFP installation.".into())
        }
    }

    /// Return the route-bound plan only while the captured network epoch remains current.
    pub fn policy_plan(&self) -> Result<&WfpPolicyPlan, String> {
        self.ensure_current()?;
        Ok(&self.plan)
    }

    pub fn physical_interfaces(&self) -> Result<&[crate::wfp_policy::PhysicalInterface], String> {
        self.ensure_current()?;
        Ok(&self.spec.physical_interfaces)
    }

    pub fn resolved_endpoints(&self) -> Result<&[ResolvedVpnEndpointEgress], String> {
        self.ensure_current()?;
        Ok(&self.resolved_endpoints)
    }

    pub fn network_generation(&self) -> u64 {
        self.epoch.generation()
    }

    /// Explicitly unregister callbacks. Drop also performs best-effort cancellation.
    pub fn shutdown(self) -> Result<(), String> {
        self.monitor.shutdown()
    }
}
