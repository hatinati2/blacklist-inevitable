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

type AgentServiceStatus = {
  available: boolean;
  state: "running" | "unavailable" | "unsupported";
  detail: string;
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

  useEffect(() => {
    void refreshStatus();
    void refreshAgentStatus();
    void refreshProfiles();
    void refreshRealDelaySettings();
  }, [refreshStatus, refreshAgentStatus, refreshProfiles, refreshRealDelaySettings]);

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
          <span className={agentStatus?.available ? "result-pill success" : "result-pill neutral"}>
            {agentStatusLoading && !agentStatus
              ? "Checking…"
              : agentStatus?.available
                ? "Responding"
                : agentStatus?.state === "unsupported"
                  ? "Windows only"
                  : "Unavailable"}
          </span>
        </div>
        <p className="panel-copy" aria-live="polite">
          {agentStatus?.detail ?? "Checking the local Agent service…"}
        </p>
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
