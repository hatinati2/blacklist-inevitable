import { useCallback, useEffect, useState } from "react";
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
  engines: EngineTarget[];
};

export default function App() {
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [message, setMessage] = useState("Checking desktop runtime…");
  const [loading, setLoading] = useState(false);

  const refreshStatus = useCallback(async () => {
    setLoading(true);
    try {
      const nextStatus = await invoke<AppStatus>("get_app_status");
      setStatus(nextStatus);
      setMessage("Connected to the native application shell.");
    } catch {
      setStatus(null);
      setMessage("Browser preview mode — launch through the Tauri desktop shell for native status.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshStatus();
  }, [refreshStatus]);

  const engines = status?.engines ?? [
    { kind: "sing-box", binaryName: "sing-box", integrationStage: "planned" },
    { kind: "Xray-core", binaryName: "xray", integrationStage: "planned" },
    { kind: "Mihomo", binaryName: "mihomo", integrationStage: "planned" },
  ];

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
        <span className="stage-tag">FOUNDATION</span>
      </header>

      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow">PROJECT STATUS</p>
          <h2>A safer route to a reliable connection.</h2>
          <p className="hero-description">
            A clean Windows-first foundation for profile management, isolated server checks,
            and predictable connection lifecycle control.
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

      <section className="section-heading">
        <div>
          <p className="eyebrow">ENGINE STRATEGY</p>
          <h2>One interface. Multiple runtimes.</h2>
        </div>
        <button className="quiet-button" onClick={() => void refreshStatus()} disabled={loading}>
          {loading ? "Refreshing…" : "Refresh status"}
        </button>
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
            <p className="engine-note">Adapter integration is not implemented yet.</p>
          </article>
        ))}
      </section>

      <section className="notice">
        <div className="notice-icon">i</div>
        <div>
          <h3>Development build — no traffic is routed</h3>
          <p>
            Connection and preflight testing are not available in this foundation.
            No TUN interface or system proxy settings are changed by this screen.
          </p>
        </div>
      </section>

      <footer className="footer">
        <span>Version {status?.version ?? "0.1.0"}</span>
        <span>{status?.developmentStage ?? "early foundation"} · Windows first</span>
      </footer>
    </main>
  );
}
