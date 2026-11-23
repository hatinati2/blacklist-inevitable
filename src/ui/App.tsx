import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type EngineTarget = {
  kind: string;
  binaryName: string;
  integrationStage: string;
};

type AppStatus = {
  appName: string;
  version: string;
  developmentStage: string;
  connectionImplemented: boolean;
  preflightTestingImplemented: boolean;
  profileManagementImplemented: boolean;
  endpointTcpTestImplemented: boolean;
  singBoxInstalled: boolean;
  runtimeCleanupHealthy: boolean;
  engines: EngineTarget[];
};

type AgentRecoveryDisposition =
  | "verifiedClean"
  | "needsCleanup"
  | "needsRestore"
  | "conflict"
  | "unknown";

type AgentRecoveryState = "clear" | "verifiedCleanRetained" | "blocked";

type AgentRecoveryDispositionCounts = {
  verifiedClean: number;
  needsCleanup: number;
  needsRestore: number;
  conflict: number;
  unknown: number;
};

type AgentRecoverySessionStatus = {
  sessionId: number;
  revision: number;
  phase: string;
  engine: AgentRecoveryDisposition;
  tunnel: AgentRecoveryDisposition;
  routes: AgentRecoveryDispositionCounts;
  dns: AgentRecoveryDispositionCounts;
  firewallFilters: AgentRecoveryDisposition;
  verifiedClean: boolean;
};

type AgentRecoveryStatus = {
  state: AgentRecoveryState;
  journalInventoryComplete: boolean;
  totalSessions: number;
  verifiedCleanSessions: number;
  blockedSessions: number;
  omittedSessions: number;
  journalRetained: boolean;
  sessions: AgentRecoverySessionStatus[];
  diagnostics: string[];
};

type AgentConnectionPhase =
  | "disconnected"
  | "preparing"
  | "startingEngine"
  | "configuringNetwork"
  | "connected"
  | "disconnecting"
  | "recovering"
  | "failed";

type AgentConnectionSnapshot = {
  phase: AgentConnectionPhase;
  sessionId: number | null;
  profileId: string | null;
  detail: string | null;
  cleanupHealthy: boolean;
};

type AgentServiceStatus = {
  available: boolean;
  state: "running" | "unavailable" | "unsupported" | "recoveryRequired";
  detail: string;
  connection?: AgentConnectionSnapshot | null;
  recovery?: AgentRecoveryStatus | null;
};

type Profile = {
  id: string;
  name: string;
  protocol: string;
  server: string;
  port: number;
  options: Record<string, string>;
  unsupportedOptions: string[];
};

type ImportIssue = { line: number; reason: string };
type ImportResponse = { imported: Profile[]; rejected: ImportIssue[] };
type RealDelayResult = {
  profileId: string;
  name: string;
  server: string;
  port: number;
  configStatus: string;
  configDetail: string;
  realDelayMs: number | null;
  realDelayDetail: string;
  testedUrl: string | null;
};

type RealDelaySettings = {
  primaryUrl: string;
  fallbackUrl: string;
  timeoutSeconds: number;
};

type DestinationAction = "direct" | "vpn" | "block";
type TrafficRoutingMode = "global" | "rule";
type DestinationRule = {
  domains: string[];
  domainSuffixes: string[];
  ipCidrs: string[];
  action: DestinationAction;
};
type DestinationRoutingPolicy = {
  mode: TrafficRoutingMode;
  bypassPrivate: boolean;
  bypassIran: boolean;
  customRules: DestinationRule[];
};
type ApplicationRoute = "vpn" | "direct" | "block";
type SplitTunnelMode = "fullTunnel" | "directOnly" | "includeSelected" | "excludeSelected" | "custom";
type SplitTunnelApplication = { executablePath: string; action: ApplicationRoute };
type SplitTunnelPolicy = {
  mode: SplitTunnelMode;
  defaultRoute: ApplicationRoute;
  applications: SplitTunnelApplication[];
};
type RoutingSettings = {
  destination: DestinationRoutingPolicy;
  splitTunnel: SplitTunnelPolicy;
};

const DEFAULT_ROUTING_SETTINGS: RoutingSettings = {
  destination: { mode: "global", bypassPrivate: true, bypassIran: true, customRules: [] },
  splitTunnel: { mode: "fullTunnel", defaultRoute: "vpn", applications: [] },
};

function splitRoutingValues(value: string): string[] {
  return value.split(/[\r\n,;]/).map((item) => item.trim()).filter(Boolean);
}

type EndpointResult = {
  profileId: string;
  name: string;
  protocol: string;
  server: string;
  port: number;
  supported: boolean;
  reachable: boolean;
  latencyMs: number | null;
  detail: string;
};

function connectionPhaseLabel(phase: AgentConnectionPhase): string {
  switch (phase) {
    case "disconnected":
      return "Disconnected";
    case "preparing":
      return "Preparing";
    case "startingEngine":
      return "Starting engine";
    case "configuringNetwork":
      return "Configuring network";
    case "connected":
      return "Connected";
    case "disconnecting":
      return "Disconnecting";
    case "recovering":
      return "Recovery in progress";
    case "failed":
      return "Failed / blocked";
  }
}

function recoveryStateLabel(state: AgentRecoveryState): string {
  switch (state) {
    case "clear":
      return "No unresolved recovery journals";
    case "verifiedCleanRetained":
      return "Resources verified clean; journal retained";
    case "blocked":
      return "Recovery is blocked";
  }
}

function dispositionLabel(disposition: AgentRecoveryDisposition): string {
  switch (disposition) {
    case "verifiedClean":
      return "Verified clean";
    case "needsCleanup":
      return "Needs cleanup";
    case "needsRestore":
      return "Needs restore";
    case "conflict":
      return "Conflict";
    case "unknown":
      return "Unknown";
  }
}

function dispositionCountsLabel(counts: AgentRecoveryDispositionCounts): string {
  return [
    `clean ${counts.verifiedClean}`,
    `cleanup ${counts.needsCleanup}`,
    `restore ${counts.needsRestore}`,
    `conflict ${counts.conflict}`,
    `unknown ${counts.unknown}`,
  ].join(" · ");
}

function routingModeLabel(mode: SplitTunnelMode): string {
  switch (mode) {
    case "fullTunnel": return "Full Tunnel";
    case "directOnly": return "Direct Only";
    case "includeSelected": return "Include Selected";
    case "excludeSelected": return "Exclude Selected";
    case "custom": return "Custom per-app";
  }
}

export default function App() {
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [agentStatus, setAgentStatus] = useState<AgentServiceStatus | null>(null);
  const [agentStatusLoading, setAgentStatusLoading] = useState(false);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [shareText, setShareText] = useState("");
  const [endpointResults, setEndpointResults] = useState<EndpointResult[] | null>(null);
  const [realDelayResults, setRealDelayResults] = useState<RealDelayResult[] | null>(null);
  const [message, setMessage] = useState("Checking desktop runtime…");
  const [busy, setBusy] = useState(false);
  const [previewMode, setPreviewMode] = useState(false);
  const [installingEngine, setInstallingEngine] = useState(false);
  const [configResults, setConfigResults] = useState<Record<string, { valid: boolean; detail: string }>>({});
  const [realDelaySettings, setRealDelaySettings] = useState<RealDelaySettings>({
    primaryUrl: "https://www.gstatic.com/generate_204",
    fallbackUrl: "https://cp.cloudflare.com/generate_204",
    timeoutSeconds: 9,
  });
  const [settingsLoading, setSettingsLoading] = useState(true);
  const [settingsSaving, setSettingsSaving] = useState(false);
  const [routingSettings, setRoutingSettings] = useState<RoutingSettings>(DEFAULT_ROUTING_SETTINGS);
  const [routingSettingsLoading, setRoutingSettingsLoading] = useState(true);
  const [routingSettingsSaving, setRoutingSettingsSaving] = useState(false);
  const [ruleDraft, setRuleDraft] = useState({
    domains: "",
    domainSuffixes: "",
    ipCidrs: "",
    action: "direct" as DestinationAction,
  });
  const [applicationDraft, setApplicationDraft] = useState({
    executablePath: "",
    action: "vpn" as ApplicationRoute,
  });

  const refreshStatus = useCallback(async () => {
    try {
      const nextStatus = await invoke<AppStatus>("get_app_status");
      setStatus(nextStatus);
      setMessage("Native application shell is ready.");
      setPreviewMode(false);
    } catch {
      setStatus(null);
      setMessage("Browser preview mode — run the desktop app to access local profiles.");
      setPreviewMode(true);
    }
  }, []);

  const refreshAgentStatus = useCallback(async () => {
    setAgentStatusLoading(true);
    try {
      const nextStatus = await invoke<AgentServiceStatus>("get_agent_service_status");
      setAgentStatus(nextStatus);
    } catch (error) {
      setAgentStatus({
        available: false,
        state: "unavailable",
        detail: typeof error === "string" ? error : "The Agent status request failed.",
        recovery: null,
      });
    } finally {
      setAgentStatusLoading(false);
    }
  }, []);

  const refreshRuntimeStatus = useCallback(async () => {
    try {
      const nextStatus = await invoke<AppStatus>("get_app_status");
      setStatus(nextStatus);
    } catch {
      // Preserve the last known runtime status if the lightweight refresh fails.
    }
  }, []);

  const refreshProfiles = useCallback(async () => {
    try {
      const nextProfiles = await invoke<Profile[]>("get_profiles");
      setProfiles(nextProfiles);
    } catch {
      setProfiles([]);
    }
  }, []);

  const refreshRealDelaySettings = useCallback(async () => {
    setSettingsLoading(true);
    try {
      const settings = await invoke<RealDelaySettings>("get_real_delay_settings");
      setRealDelaySettings(settings);
    } catch (error) {
      setMessage(typeof error === "string" ? error : "Could not load Real Delay settings.");
    } finally {
      setSettingsLoading(false);
    }
  }, []);

  const saveRealDelaySettings = async () => {
    setSettingsSaving(true);
    try {
      const settings = await invoke<RealDelaySettings>("save_real_delay_settings", {
        settings: realDelaySettings,
      });
      setRealDelaySettings(settings);
      setMessage("Real Delay settings saved.");
    } catch (error) {
      setMessage(typeof error === "string" ? error : "Could not save Real Delay settings.");
    } finally {
      setSettingsSaving(false);
    }
  };

  const refreshRoutingSettings = useCallback(async () => {
    setRoutingSettingsLoading(true);
    try {
      const settings = await invoke<RoutingSettings>("get_routing_settings");
      setRoutingSettings(settings);
    } catch (error) {
      setMessage(typeof error === "string" ? error : "Could not load routing settings.");
    } finally {
      setRoutingSettingsLoading(false);
    }
  }, []);

  const saveRoutingSettings = async () => {
    setRoutingSettingsSaving(true);
    try {
      const settings = await invoke<RoutingSettings>("save_routing_settings", { settings: routingSettings });
      setRoutingSettings(settings);
      setMessage("Routing policies saved locally. They are not active on Windows.");
    } catch (error) {
      setMessage(typeof error === "string" ? error : "Could not save routing settings.");
    } finally {
      setRoutingSettingsSaving(false);
    }
  };

  const addDestinationRule = () => {
    const rule: DestinationRule = {
      domains: splitRoutingValues(ruleDraft.domains),
      domainSuffixes: splitRoutingValues(ruleDraft.domainSuffixes),
      ipCidrs: splitRoutingValues(ruleDraft.ipCidrs),
      action: ruleDraft.action,
    };
    if (rule.domains.length + rule.domainSuffixes.length + rule.ipCidrs.length === 0) {
      setMessage("Add at least one domain or IP/CIDR match before adding a rule.");
      return;
    }
    setRoutingSettings((current) => ({
      ...current,
      destination: { ...current.destination, customRules: [...current.destination.customRules, rule] },
    }));
    setRuleDraft({ domains: "", domainSuffixes: "", ipCidrs: "", action: "direct" });
  };

  const removeDestinationRule = (index: number) => {
    setRoutingSettings((current) => ({
      ...current,
      destination: {
        ...current.destination,
        customRules: current.destination.customRules.filter((_, itemIndex) => itemIndex !== index),
      },
    }));
  };

  const addSplitTunnelApplication = () => {
    const executablePath = applicationDraft.executablePath.trim();
    if (!executablePath) {
      setMessage("Enter an absolute Windows .exe path before adding an application.");
      return;
    }
    setRoutingSettings((current) => ({
      ...current,
      splitTunnel: {
        ...current.splitTunnel,
        applications: [...current.splitTunnel.applications, { executablePath, action: applicationDraft.action }],
      },
    }));
    setApplicationDraft({ executablePath: "", action: "vpn" });
  };

  const removeSplitTunnelApplication = (index: number) => {
    setRoutingSettings((current) => ({
      ...current,
      splitTunnel: {
        ...current.splitTunnel,
        applications: current.splitTunnel.applications.filter((_, itemIndex) => itemIndex !== index),
      },
    }));
  };

  useEffect(() => {
    void refreshStatus();
    void refreshAgentStatus();
    void refreshProfiles();
    void refreshRealDelaySettings();
    void refreshRoutingSettings();
  }, [refreshStatus, refreshAgentStatus, refreshProfiles, refreshRealDelaySettings, refreshRoutingSettings]);

  const engines = status?.engines ?? [
    { kind: "sing-box", binaryName: "sing-box", integrationStage: "implemented · preflight only" },
    { kind: "Xray-core", binaryName: "xray", integrationStage: "planned" },
    { kind: "Mihomo", binaryName: "mihomo", integrationStage: "planned" },
  ];

  const reachableCount = useMemo(
    () => endpointResults?.filter((result) => result.reachable).length ?? 0,
    [endpointResults],
  );

  const displayedProfiles = useMemo(() => {
    if (!realDelayResults) return profiles;
    const rank = new Map(realDelayResults.map((result, index) => [result.profileId, index]));
    return [...profiles].sort((left, right) =>
      (rank.get(left.id) ?? Number.MAX_SAFE_INTEGER) -
      (rank.get(right.id) ?? Number.MAX_SAFE_INTEGER),
    );
  }, [profiles, realDelayResults]);

  const importProfiles = async () => {
    if (!shareText.trim()) return;
    setBusy(true);
    try {
      const result = await invoke<ImportResponse>("import_profiles", { input: shareText });
      setShareText("");
      setEndpointResults(null);
      setRealDelayResults(null);
      setConfigResults({});
      await refreshProfiles();
      const summary = `${result.imported.length} imported, ${result.rejected.length} skipped.`;
      setMessage(summary);
    } catch (error) {
      setMessage(typeof error === "string" ? error : "Could not import these profiles.");
    } finally {
      setBusy(false);
    }
  };

  const removeProfile = async (profileId: string) => {
    setBusy(true);
    try {
      await invoke("delete_profile", { profileId });
      await refreshProfiles();
      setEndpointResults((current) => current?.filter((result) => result.profileId !== profileId) ?? null);
      setMessage("Profile removed.");
    } catch (error) {
      // Credential deletion can fail after the profile metadata has already
      // been removed. Always refresh so the UI reflects the durable profile index.
      await refreshProfiles();
      setMessage(typeof error === "string" ? error : "Could not remove this profile.");
    } finally {
      setBusy(false);
    }
  };

  const installEngine = async () => {
    setInstallingEngine(true);
    try {
      const version = await invoke<string>("install_sing_box_engine");
      setMessage(`Installed ${version} after SHA-256 verification.`);
    } catch (error) {
      setMessage(typeof error === "string" ? error : "Could not install sing-box.");
    } finally {
      await refreshRuntimeStatus();
      setInstallingEngine(false);
    }
  };

  const validateConfig = async (profileId: string) => {
    setBusy(true);
    try {
      const result = await invoke<{ profileId: string; valid: boolean; detail: string }>(
        "validate_profile_config",
        { profileId },
      );
      setConfigResults((current) => ({
        ...current,
        [profileId]: { valid: result.valid, detail: result.detail },
      }));
      setMessage(result.valid ? "Engine configuration is valid." : "Engine configuration validation failed.");
    } catch (error) {
      setConfigResults((current) => ({
        ...current,
        [profileId]: { valid: false, detail: typeof error === "string" ? error : "Validation failed." },
      }));
      setMessage(typeof error === "string" ? error : "Could not validate the configuration.");
    } finally {
      await refreshRuntimeStatus();
      setBusy(false);
    }
  };

  const testRealDelay = async () => {
    setBusy(true);
    setRealDelayResults(null);
    try {
      const results = await invoke<RealDelayResult[]>("test_all_profile_real_delays");
      setRealDelayResults(results);
      const valid = results.filter((item) => item.configStatus === "valid").length;
      const measured = results.filter((item) => item.realDelayMs !== null).length;
      setMessage(`Config checked: ${valid}/${results.length}; real delay measured: ${measured}/${results.length}.`);
    } catch (error) {
      setMessage(typeof error === "string" ? error : "Real Delay testing could not be completed.");
    } finally {
      await refreshRuntimeStatus();
      setBusy(false);
    }
  };

  const testEndpoints = async () => {
    setBusy(true);
    try {
      const results = await invoke<EndpointResult[]>("test_all_profile_endpoints");
      setEndpointResults(results);
      setMessage(`Basic endpoint check finished: ${results.filter((item) => item.reachable).length} TCP endpoints reachable.`);
    } catch (error) {
      setMessage(typeof error === "string" ? error : "Endpoint checks could not be completed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">BI</div>
          <div>
            <p className="eyebrow">WINDOWS · MULTI-ENGINE CLIENT</p>
            <h1>blacklist-inevitable</h1>
          </div>
        </div>
        <span className="stage-tag">AGENT STATUS · PREFLIGHT</span>
      </header>

      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow">PROJECT STATUS</p>
          <h2>Bring your nodes together. Check the basics first.</h2>
          <p className="hero-description">
            Import supported share links, keep credentials in Windows Credential Manager,
            validate each generated sing-box config, then measure a real request through that node.
          </p>
          <div className="runtime-line">
            <span className="runtime-dot" />
            <span>{message}</span>
          </div>
        </div>
        <div className="hero-orbit" aria-hidden="true">
          <div className="orbit orbit-one" />
          <div className="orbit orbit-two" />
          <div className="orbit-core">BI</div>
        </div>
      </section>

      {status && !status.runtimeCleanupHealthy && (
        <section className="runtime-warning" role="alert">
          <strong>Engine operations are locked for safety</strong>
          <p>
            The app cannot confirm that engine-process containment and temporary-file cleanup are safe.
            Installing sing-box, validating configurations, and Real Delay are disabled for this session.
            This does not mean sing-box is missing; do not try to reinstall it as a workaround.
          </p>
        </section>
      )}

      <section className="panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">WINDOWS PRIVILEGED AGENT</p>
            <h2>Agent service status</h2>
          </div>
          <span
            className={
              agentStatus?.state === "recoveryRequired"
                ? "result-pill failure"
                : agentStatus?.available
                  ? "result-pill success"
                  : "result-pill neutral"
            }
          >
            {agentStatusLoading && !agentStatus
              ? "Checking…"
              : agentStatus?.available
                ? "Responding"
                : agentStatus?.state === "recoveryRequired"
                  ? "Recovery required"
                  : agentStatus?.state === "unsupported"
                    ? "Windows only"
                    : "Unavailable"}
          </span>
        </div>
        <p className="panel-copy" aria-live="polite">
          {agentStatus?.detail ?? "Checking the local Agent service…"}
        </p>
        {agentStatus?.connection && (
          <div className="recovery-details" aria-live="polite">
            <div className="recovery-overview">
              <div>
                <span className="recovery-label">Agent connection state</span>
                <strong className={
                  agentStatus.connection.phase === "disconnected" && agentStatus.connection.cleanupHealthy
                    ? "recovery-state recovery-state-clear"
                    : "recovery-state recovery-state-blocked"
                }>
                  {connectionPhaseLabel(agentStatus.connection.phase)}
                </strong>
              </div>
              <div className="recovery-inventory">
                <span>
                  {agentStatus.connection.cleanupHealthy
                    ? "Cleanup state confirmed"
                    : "Cleanup state unconfirmed"}
                </span>
                <span>
                  {agentStatus.connection.sessionId === null
                    ? "No active session token"
                    : `Session ${agentStatus.connection.sessionId}`}
                </span>
              </div>
            </div>
            {agentStatus.connection.detail && (
              <p className="recovery-note">{agentStatus.connection.detail}</p>
            )}
          </div>
        )}
        {agentStatus?.recovery && (
          <div className="recovery-details" aria-live="polite">
            <div className="recovery-overview">
              <div>
                <span className="recovery-label">Recovery assessment</span>
                <strong className={
                  agentStatus.recovery.state === "clear"
                    ? "recovery-state recovery-state-clear"
                    : "recovery-state recovery-state-blocked"
                }>
                  {recoveryStateLabel(agentStatus.recovery.state)}
                </strong>
              </div>
              <div className="recovery-inventory">
                <span>{agentStatus.recovery.journalInventoryComplete ? "Complete journal inventory" : "Incomplete journal inventory"}</span>
                <span>{agentStatus.recovery.totalSessions} session(s)</span>
                <span>{agentStatus.recovery.verifiedCleanSessions} verified clean</span>
                <span>{agentStatus.recovery.blockedSessions} blocked</span>
                <span>{agentStatus.recovery.journalRetained ? "Journal retained" : "No journal retained"}</span>
              </div>
            </div>
            {agentStatus.recovery.state === "verifiedCleanRetained" && (
              <p className="recovery-retained-warning">
                The observed resources look clean, but the recovery journal is still retained.
                The Agent remains blocked until journal disposition has a separately reviewed protocol.
              </p>
            )}
            {agentStatus.recovery.sessions.map((session) => (
              <article className="recovery-session" key={`${session.sessionId}:${session.revision}`}>
                <div className="recovery-session-heading">
                  <strong>Session {session.sessionId} · revision {session.revision}</strong>
                  <span>{session.phase}</span>
                </div>
                <div className="recovery-resource-grid">
                  <div className="recovery-resource">
                    <span>Engine process</span>
                    <strong>{dispositionLabel(session.engine)}</strong>
                  </div>
                  <div className="recovery-resource">
                    <span>Tunnel interface</span>
                    <strong>{dispositionLabel(session.tunnel)}</strong>
                  </div>
                  <div className="recovery-resource">
                    <span>Routes</span>
                    <strong>{dispositionCountsLabel(session.routes)}</strong>
                  </div>
                  <div className="recovery-resource">
                    <span>DNS</span>
                    <strong>{dispositionCountsLabel(session.dns)}</strong>
                  </div>
                  <div className="recovery-resource">
                    <span>WFP filters</span>
                    <strong>{dispositionLabel(session.firewallFilters)}</strong>
                  </div>
                  <div className="recovery-resource">
                    <span>Session outcome</span>
                    <strong>{session.verifiedClean ? "Verified clean; journal still retained" : "Not verified clean"}</strong>
                  </div>
                </div>
              </article>
            ))}
            {agentStatus.recovery.omittedSessions > 0 && (
              <p className="recovery-note">
                {agentStatus.recovery.omittedSessions} additional session(s) omitted from the compact detail list; aggregate counts include them.
              </p>
            )}
            {agentStatus.recovery.diagnostics.length > 0 && (
              <div className="recovery-diagnostics">
                <span className="recovery-label">Observer diagnostics</span>
                {agentStatus.recovery.diagnostics.map((diagnostic, index) => (
                  <p className="recovery-diagnostic" key={index}>{diagnostic}</p>
                ))}
              </div>
            )}
          </div>
        )}
        <div className="panel-actions">
          <span className="hint-text">
            Read-only status channel. Connect, Disconnect, and recovery remain disabled.
          </span>
          <button
            className="quiet-button"
            onClick={() => void refreshAgentStatus()}
            disabled={previewMode || agentStatusLoading}
          >
            {agentStatusLoading ? "Checking…" : "Refresh Agent"}
          </button>
        </div>
      </section>

      <section className="workspace-grid">
        <article className="panel import-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">PROFILE IMPORT</p>
              <h2>Add server links</h2>
            </div>
            <span className="count-tag">{profiles.length} saved</span>
          </div>
          <p className="panel-copy">
            One share link per line. Supported: VLESS, VMess, Trojan, Shadowsocks SIP002,
            Hysteria2 and TUIC. Subscription URLs and plugin-based Shadowsocks links are not supported yet.
          </p>
          <textarea
            value={shareText}
            onChange={(event) => setShareText(event.target.value)}
            placeholder={"vless://…\nvmess://…\ntrojan://…"}
            rows={7}
            spellCheck={false}
            disabled={previewMode || busy}
          />
          <div className="panel-actions">
            <span className="hint-text">Credentials are not displayed in the profile list.</span>
            <button className="primary-button" onClick={() => void importProfiles()} disabled={previewMode || busy || !shareText.trim()}>
              {busy ? "Working…" : "Import links"}
            </button>
          </div>
        </article>

        <article className="panel probe-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">BASIC CONNECTIVITY</p>
              <h2>Check endpoints</h2>
            </div>
            <span className="count-tag">TCP only</span>
          </div>
          <p className="panel-copy">
            Real Delay first validates a generated sing-box config and then sends a real HTTP(S)
            request through that node. Unmapped source options are retained and block testing.
            No VPN/TUN/system proxy is enabled.
          </p>
          <div className="probe-summary">
            <div>
              <strong>{profiles.length}</strong>
              <span>saved nodes</span>
            </div>
            <div>
              <strong>{endpointResults ? reachableCount : "—"}</strong>
              <span>TCP reachable</span>
            </div>
          </div>
          <button className="secondary-button" onClick={() => void testEndpoints()} disabled={previewMode || busy || profiles.length === 0}>
            {busy ? "Working…" : "TCP reachability only"}
          </button>
          <button className="primary-button engine-install-button" onClick={() => void testRealDelay()} disabled={previewMode || busy || profiles.length === 0 || !status?.singBoxInstalled || !status?.runtimeCleanupHealthy}>
            {busy ? "Testing…" : "Test config + Real Delay"}
          </button>
          {!previewMode && status?.runtimeCleanupHealthy && !status?.singBoxInstalled && (
            <button className="primary-button engine-install-button" onClick={() => void installEngine()} disabled={installingEngine || busy}>
              {installingEngine ? "Downloading and verifying…" : "Install sing-box engine"}
            </button>
          )}
          {!previewMode && status?.singBoxInstalled && (
            <p className="engine-installed-note">sing-box { "1.14.4" } is installed. Native config validation and isolated Real Delay are available.</p>
          )}
        </article>
      </section>

      <section className="panel settings-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">REAL DELAY CONFIGURATION</p>
            <h2>Probe endpoints and timeout</h2>
          </div>
          <span className="count-tag">HTTPS · HTTP 204</span>
        </div>
        <p className="panel-copy">
          These endpoints are requested through each selected node's temporary SOCKS5 proxy.
          Only HTTP 204 is accepted; redirects are not followed and requests never fall back to the direct network.
        </p>
        <div className="settings-fields">
          <label className="setting-field">
            <span>Primary HTTPS endpoint</span>
            <input
              type="url"
              value={realDelaySettings.primaryUrl}
              onChange={(event) => setRealDelaySettings((current) => ({ ...current, primaryUrl: event.target.value }))}
              disabled={previewMode || settingsLoading || settingsSaving}
              spellCheck={false}
            />
          </label>
          <label className="setting-field">
            <span>Fallback HTTPS endpoint</span>
            <input
              type="url"
              value={realDelaySettings.fallbackUrl}
              onChange={(event) => setRealDelaySettings((current) => ({ ...current, fallbackUrl: event.target.value }))}
              disabled={previewMode || settingsLoading || settingsSaving}
              spellCheck={false}
            />
          </label>
          <label className="setting-field timeout-field">
            <span>Timeout (seconds)</span>
            <input
              type="number"
              min={2}
              max={30}
              step={1}
              value={realDelaySettings.timeoutSeconds}
              onChange={(event) => setRealDelaySettings((current) => ({
                ...current,
                timeoutSeconds: Number(event.target.value),
              }))}
              disabled={previewMode || settingsLoading || settingsSaving}
            />
          </label>
        </div>
        <div className="settings-actions">
          <span className="hint-text">
            {settingsLoading ? "Loading saved settings…" : "Timeout range: 2–30 seconds. Default: 9 seconds."}
          </span>
          <button
            className="primary-button"
            onClick={() => void saveRealDelaySettings()}
            disabled={previewMode || settingsLoading || settingsSaving}
          >
            {settingsSaving ? "Saving…" : "Save Real Delay settings"}
          </button>
        </div>
      </section>


      <section className="panel settings-panel routing-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">ROUTING POLICY EDITOR</p>
            <h2>Destination and application policies</h2>
          </div>
          <span className="count-tag">Saved locally only</span>
        </div>
        <p className="panel-copy">
          These controls edit and validate saved preferences only. They are not sent to the Agent,
          do not build or launch an engine configuration, and do not change Windows networking.
        </p>

        <div className="routing-grid">
          <article className="routing-subpanel">
            <div className="routing-subheading">
              <h3>Destination routing</h3>
              <span>{routingSettings.destination.customRules.length} custom rules</span>
            </div>
            <label className="setting-field routing-field">
              <span>Routing mode</span>
              <select
                value={routingSettings.destination.mode}
                onChange={(event) => setRoutingSettings((current) => ({
                  ...current,
                  destination: { ...current.destination, mode: event.target.value as TrafficRoutingMode },
                }))}
                disabled={previewMode || routingSettingsLoading || routingSettingsSaving}
              >
                <option value="global">Global · all destinations through VPN</option>
                <option value="rule">Rule · destination exceptions</option>
              </select>
            </label>
            <div className="routing-checks">
              <label>
                <input type="checkbox" checked={routingSettings.destination.bypassPrivate}
                  onChange={(event) => setRoutingSettings((current) => ({
                    ...current,
                    destination: { ...current.destination, bypassPrivate: event.target.checked },
                  }))}
                  disabled={previewMode || routingSettingsLoading || routingSettingsSaving || routingSettings.destination.mode !== "rule"} />
                Bypass private/local IP ranges
              </label>
              <label>
                <input type="checkbox" checked={routingSettings.destination.bypassIran}
                  onChange={(event) => setRoutingSettings((current) => ({
                    ...current,
                    destination: { ...current.destination, bypassIran: event.target.checked },
                  }))}
                  disabled={previewMode || routingSettingsLoading || routingSettingsSaving || routingSettings.destination.mode !== "rule"} />
                Bypass built-in Iran domain/IP rules
              </label>
            </div>
            <div className="routing-form">
              <label className="setting-field routing-field">
                <span>Exact domains (one per line)</span>
                <textarea rows={2} value={ruleDraft.domains} onChange={(event) => setRuleDraft((current) => ({ ...current, domains: event.target.value }))} placeholder={"example.com"} disabled={previewMode || routingSettingsLoading || routingSettingsSaving} />
              </label>
              <label className="setting-field routing-field">
                <span>Domain suffixes (one per line)</span>
                <textarea rows={2} value={ruleDraft.domainSuffixes} onChange={(event) => setRuleDraft((current) => ({ ...current, domainSuffixes: event.target.value }))} placeholder={"*.trusted.example"} disabled={previewMode || routingSettingsLoading || routingSettingsSaving} />
              </label>
              <label className="setting-field routing-field">
                <span>IP addresses / CIDRs (one per line)</span>
                <textarea rows={2} value={ruleDraft.ipCidrs} onChange={(event) => setRuleDraft((current) => ({ ...current, ipCidrs: event.target.value }))} placeholder={"203.0.113.0/24"} disabled={previewMode || routingSettingsLoading || routingSettingsSaving} />
              </label>
              <div className="routing-add-row">
                <label className="setting-field routing-field">
                  <span>Action</span>
                  <select value={ruleDraft.action} onChange={(event) => setRuleDraft((current) => ({ ...current, action: event.target.value as DestinationAction }))} disabled={previewMode || routingSettingsLoading || routingSettingsSaving}>
                    <option value="direct">Direct</option>
                    <option value="vpn">VPN</option>
                    <option value="block">Block</option>
                  </select>
                </label>
                <button className="quiet-button" onClick={addDestinationRule} disabled={previewMode || routingSettingsLoading || routingSettingsSaving}>Add rule</button>
              </div>
            </div>
            <div className="routing-list">
              {routingSettings.destination.customRules.length === 0 ? (
                <p className="routing-empty">No custom destination rules saved.</p>
              ) : routingSettings.destination.customRules.map((rule, index) => (
                <div className="routing-list-row" key={index}>
                  <div>
                    <strong>{rule.action.toUpperCase()}</strong>
                    <span>{[...rule.domains, ...rule.domainSuffixes, ...rule.ipCidrs].join(" · ")}</span>
                  </div>
                  <button className="remove-button" onClick={() => removeDestinationRule(index)} disabled={previewMode || routingSettingsLoading || routingSettingsSaving}>Remove</button>
                </div>
              ))}
            </div>
          </article>

          <article className="routing-subpanel">
            <div className="routing-subheading">
              <h3>Split tunneling</h3>
              <span>{routingSettings.splitTunnel.applications.length} applications</span>
            </div>
            <label className="setting-field routing-field">
              <span>Split-tunnel mode</span>
              <select
                value={routingSettings.splitTunnel.mode}
                onChange={(event) => setRoutingSettings((current) => ({
                  ...current,
                  splitTunnel: { ...current.splitTunnel, mode: event.target.value as SplitTunnelMode },
                }))}
                disabled={previewMode || routingSettingsLoading || routingSettingsSaving}
              >
                <option value="fullTunnel">Full Tunnel</option>
                <option value="directOnly">Direct Only</option>
                <option value="includeSelected">Include Selected</option>
                <option value="excludeSelected">Exclude Selected</option>
                <option value="custom">Custom per-app</option>
              </select>
            </label>
            <label className="setting-field routing-field">
              <span>Default for unlisted applications (Custom mode)</span>
              <select
                value={routingSettings.splitTunnel.defaultRoute}
                onChange={(event) => setRoutingSettings((current) => ({
                  ...current,
                  splitTunnel: { ...current.splitTunnel, defaultRoute: event.target.value as ApplicationRoute },
                }))}
                disabled={previewMode || routingSettingsLoading || routingSettingsSaving || routingSettings.splitTunnel.mode !== "custom"}
              >
                <option value="vpn">VPN</option>
                <option value="direct">Direct</option>
              </select>
            </label>
            <div className="routing-form">
              <label className="setting-field routing-field">
                <span>Absolute Windows executable path</span>
                <input type="text" value={applicationDraft.executablePath}
                  onChange={(event) => setApplicationDraft((current) => ({ ...current, executablePath: event.target.value }))}
                  placeholder={String.raw`C:\Program Files\App\App.exe`} spellCheck={false}
                  disabled={previewMode || routingSettingsLoading || routingSettingsSaving} />
              </label>
              <div className="routing-add-row">
                <label className="setting-field routing-field">
                  <span>Application action</span>
                  <select value={applicationDraft.action} onChange={(event) => setApplicationDraft((current) => ({ ...current, action: event.target.value as ApplicationRoute }))} disabled={previewMode || routingSettingsLoading || routingSettingsSaving}>
                    <option value="vpn">VPN</option>
                    <option value="direct">Direct</option>
                    <option value="block">Block</option>
                  </select>
                </label>
                <button className="quiet-button" onClick={addSplitTunnelApplication} disabled={previewMode || routingSettingsLoading || routingSettingsSaving}>Add app</button>
              </div>
            </div>
            <div className="routing-list">
              {routingSettings.splitTunnel.applications.length === 0 ? (
                <p className="routing-empty">No application paths saved.</p>
              ) : routingSettings.splitTunnel.applications.map((application, index) => (
                <div className="routing-list-row" key={index}>
                  <div>
                    <strong>{application.action.toUpperCase()}</strong>
                    <span>{application.executablePath}</span>
                  </div>
                  <button className="remove-button" onClick={() => removeSplitTunnelApplication(index)} disabled={previewMode || routingSettingsLoading || routingSettingsSaving}>Remove</button>
                </div>
              ))}
            </div>
            <p className="routing-footnote">{routingModeLabel(routingSettings.splitTunnel.mode)} is a saved preference; no process-path rule is active yet.</p>
          </article>
        </div>

        <div className="settings-actions">
          <span className="hint-text">
            {routingSettingsLoading ? "Loading saved routing policies…" : "Limits: 256 rules/apps; 128 match values per rule; absolute .exe paths only."}
          </span>
          <button className="primary-button" onClick={() => void saveRoutingSettings()} disabled={previewMode || routingSettingsLoading || routingSettingsSaving}>
            {routingSettingsSaving ? "Saving…" : "Save routing policies"}
          </button>
        </div>
      </section>

      <section className="section-heading">
        <div>
          <p className="eyebrow">SAVED PROFILES</p>
          <h2>Your server list</h2>
        </div>
        <button className="quiet-button" onClick={() => { void refreshStatus(); void refreshProfiles(); }} disabled={busy || previewMode}>
          Refresh
        </button>
      </section>

      <section className="profile-list">
        {profiles.length === 0 ? (
          <div className="empty-state">
            <div className="empty-mark">+</div>
            <h3>No profiles imported</h3>
            <p>Paste one or more supported share links above to create your local server list.</p>
          </div>
        ) : (
          displayedProfiles.map((profile) => {
            const result = endpointResults?.find((item) => item.profileId === profile.id);
            const delayResult = realDelayResults?.find((item) => item.profileId === profile.id);
            return (
              <article className="profile-row" key={profile.id}>
                <div className="profile-main">
                  <span className="profile-symbol">{profile.protocol.slice(0, 2).toUpperCase()}</span>
                  <div className="profile-name-block">
                    <h3>{profile.name}</h3>
                    <p>{profile.server}:{profile.port} <span>·</span> {profile.protocol}</p>
                  </div>
                </div>
                <div className="profile-status">
                  {configResults[profile.id] && (
                    <span className={configResults[profile.id].valid ? "result-pill success" : "result-pill failure"}>
                      {configResults[profile.id].valid ? "Config valid" : "Config invalid"}
                    </span>
                  )}
                  {delayResult ? (
                    <span className={delayResult.configStatus === "valid" ? "result-pill success" : "result-pill failure"}>
                      {delayResult.configStatus === "valid" ? "Config valid" : delayResult.configStatus === "unsupported" ? "Unsupported" : delayResult.configStatus === "not_checked" ? "Not checked" : "Config invalid"}
                    </span>
                  ) : null}
                  {delayResult?.realDelayMs !== null && delayResult?.realDelayMs !== undefined ? (
                    <span className="result-pill success">{delayResult.realDelayMs} ms</span>
                  ) : delayResult ? (
                    <span className="result-pill failure">Delay failed</span>
                  ) : null}
                  {result && (
                    <span className={result.reachable ? "result-pill success" : "result-pill failure"}>
                      {result.reachable ? `TCP ${result.latencyMs} ms` : "TCP unreachable"}
                    </span>
                  )}
                  {!result && !delayResult && (
                    <span className="result-pill neutral">Not tested</span>
                  )}
                  <button className="remove-button" onClick={() => void validateConfig(profile.id)} disabled={busy || previewMode || !status?.singBoxInstalled || !status?.runtimeCleanupHealthy}>
                    Validate config
                  </button>
                  <button className="remove-button" onClick={() => void removeProfile(profile.id)} disabled={busy || previewMode}>
                    Remove
                  </button>
                </div>
                {delayResult && <p className="profile-detail">{delayResult.configDetail} · {delayResult.realDelayDetail}</p>}
                {profile.unsupportedOptions?.length > 0 && <p className="profile-detail">Unmapped source options: {profile.unsupportedOptions.join(", ")}</p>}
                {delayResult?.testedUrl && <p className="profile-detail">Measured via {delayResult.testedUrl}</p>}
                {result && <p className="profile-detail">{result.detail}</p>}
                {configResults[profile.id] && <p className="profile-detail">{configResults[profile.id].detail}</p>}
              </article>
            );
          })
        )}
      </section>

      <section className="notice">
        <div className="notice-icon">i</div>
        <div>
          <h3>TCP reachability is not Real Delay</h3>
          <p>
            The Test config + Real Delay action runs sing-box's native config check, then starts a
            temporary loopback-only proxy and sends an HTTP 204 request through that node. TCP
            reachability remains a separate diagnostic. Preflight never enables TUN or changes the
            Windows system proxy.
          </p>
        </div>
      </section>

      <section className="section-heading engine-heading">
        <div>
          <p className="eyebrow">ENGINE STRATEGY</p>
          <h2>Engine integration status</h2>
        </div>
      </section>
      <section className="engine-grid">
        {engines.map((engine) => (
          <article className="engine-card" key={engine.kind}>
            <div className="engine-card-top">
              <span className="engine-symbol">{engine.kind.slice(0, 1).toUpperCase()}</span>
              <span className="planned-tag">{engine.integrationStage}</span>
            </div>
            <h3>{engine.kind}</h3>
            <p className="binary-name">{engine.binaryName}</p>
            {engine.kind === "sing-box" ? (
              <p className="engine-note">sing-box config validation and isolated Real Delay are implemented; normal traffic routing is not.</p>
            ) : (
              <p className="engine-note">This engine adapter is not implemented yet.</p>
            )}
          </article>
        ))}
      </section>

      <footer className="footer">
        <span>Version {status?.version ?? "0.1.0"}</span>
        <span>{status?.developmentStage ?? "sing-box preflight implementation"} · Windows first</span>
      </footer>
    </main>
  );
}
