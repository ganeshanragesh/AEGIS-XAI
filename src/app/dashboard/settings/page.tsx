"use client";

import { useState, useEffect } from "react";
import {
  FiSettings,
  FiSave,
  FiShield,
  FiDatabase,
  FiCpu,
  FiActivity,
  FiInfo,
  FiCheck,
} from "react-icons/fi";

interface SystemInfo {
  monitor: {
    isRunning: boolean;
    mode: string;
    packetsCapured: number;
    flowsProcessed: number;
    alertsGenerated: number;
  };
  models: {
    modelId: string;
    modelType: string;
    version: string;
    accuracy: number;
    precision: number;
    f1Score: number;
    falsePositiveRate: number;
    trainingSamples: number;
    parameters: Record<string, unknown>;
  }[];
  availableInterfaces: { name: string; description: string; available: boolean }[];
}

export default function SettingsPage() {
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [saved, setSaved] = useState(false);

  // Settings state
  const [captureMode, setCaptureMode] = useState("live");
  const [networkInterface, setNetworkInterface] = useState("eth0");
  const [flowTimeout, setFlowTimeout] = useState("30");
  const [confidenceThreshold, setConfidenceThreshold] = useState("0.60");
  const [anomalyThreshold, setAnomalyThreshold] = useState("0.55");
  const [refreshInterval, setRefreshInterval] = useState("2");
  const [retentionDays, setRetentionDays] = useState("30");
  const [logLevel, setLogLevel] = useState("info");
  const [shapEnabled, setShapEnabled] = useState(true);

  useEffect(() => {
    fetch("/api/system/status")
      .then((r) => r.json())
      .then((d) => setSystemInfo(d))
      .catch(() => {});
  }, []);

  const handleSave = () => {
    // In production: POST to /api/system/config
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const models = systemInfo?.models ?? [];

  return (
    <div style={{ padding: 24 }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: "var(--text-primary)", margin: 0 }}>
            Settings
          </h1>
          <p style={{ fontSize: 13, color: "var(--text-muted)", margin: "4px 0 0" }}>
            AEGIS-XAI platform configuration
          </p>
        </div>
        <button
          onClick={handleSave}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            padding: "8px 18px",
            background: saved ? "rgba(16,185,129,0.15)" : "var(--accent-blue)",
            border: saved ? "1px solid rgba(16,185,129,0.3)" : "none",
            borderRadius: 6,
            color: saved ? "var(--accent-green)" : "#fff",
            fontSize: 13,
            fontWeight: 600,
            cursor: "pointer",
          }}
        >
          {saved ? <FiCheck size={14} /> : <FiSave size={14} />}
          {saved ? "Saved" : "Save Settings"}
        </button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
        {/* Capture Settings */}
        <div className="card" style={{ padding: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginBottom: 16, display: "flex", alignItems: "center", gap: 8 }}>
            <FiActivity size={14} color="var(--accent-blue)" />
            Capture Configuration
          </div>

          <div style={{ marginBottom: 14 }}>
            <label style={{ fontSize: 12, color: "var(--text-muted)", display: "block", marginBottom: 6 }}>Capture Mode</label>
            <select
              value={captureMode}
              onChange={(e) => setCaptureMode(e.target.value)}
              style={{ width: "100%", background: "var(--bg-secondary)", border: "1px solid var(--border-color)", color: "var(--text-primary)", borderRadius: 6, padding: "8px 10px", fontSize: 13 }}
            >
              <option value="live">Live Capture</option>
              <option value="pcap">PCAP Analysis</option>
            </select>
          </div>

          <div style={{ marginBottom: 14 }}>
            <label style={{ fontSize: 12, color: "var(--text-muted)", display: "block", marginBottom: 6 }}>Network Interface</label>
            <select
              value={networkInterface}
              onChange={(e) => setNetworkInterface(e.target.value)}
              style={{ width: "100%", background: "var(--bg-secondary)", border: "1px solid var(--border-color)", color: "var(--text-primary)", borderRadius: 6, padding: "8px 10px", fontSize: 13 }}
            >
              {systemInfo?.availableInterfaces.map((iface) => (
                <option key={iface.name} value={iface.name}>{iface.name} — {iface.description}</option>
              )) ?? (
                <>
                  <option value="eth0">eth0 — Ethernet</option>
                  <option value="wlan0">wlan0 — Wireless</option>
                  <option value="any">any — All interfaces</option>
                </>
              )}
            </select>
          </div>

          <div style={{ marginBottom: 14 }}>
            <label style={{ fontSize: 12, color: "var(--text-muted)", display: "block", marginBottom: 6 }}>
              Flow Timeout (seconds)
            </label>
            <input
              type="number"
              value={flowTimeout}
              onChange={(e) => setFlowTimeout(e.target.value)}
              min="5"
              max="300"
              style={{ width: "100%", background: "var(--bg-secondary)", border: "1px solid var(--border-color)", color: "var(--text-primary)", borderRadius: 6, padding: "8px 10px", fontSize: 13 }}
            />
          </div>

          <div style={{ marginBottom: 14 }}>
            <label style={{ fontSize: 12, color: "var(--text-muted)", display: "block", marginBottom: 6 }}>
              Dashboard Refresh Interval (seconds)
            </label>
            <input
              type="number"
              value={refreshInterval}
              onChange={(e) => setRefreshInterval(e.target.value)}
              min="1"
              max="60"
              style={{ width: "100%", background: "var(--bg-secondary)", border: "1px solid var(--border-color)", color: "var(--text-primary)", borderRadius: 6, padding: "8px 10px", fontSize: 13 }}
            />
          </div>
        </div>

        {/* ML Settings */}
        <div className="card" style={{ padding: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginBottom: 16, display: "flex", alignItems: "center", gap: 8 }}>
            <FiCpu size={14} color="var(--accent-blue)" />
            Machine Learning Configuration
          </div>

          <div style={{ marginBottom: 14 }}>
            <label style={{ fontSize: 12, color: "var(--text-muted)", display: "block", marginBottom: 6 }}>
              Supervised Confidence Threshold
            </label>
            <input
              type="number"
              value={confidenceThreshold}
              onChange={(e) => setConfidenceThreshold(e.target.value)}
              min="0.1"
              max="1.0"
              step="0.05"
              style={{ width: "100%", background: "var(--bg-secondary)", border: "1px solid var(--border-color)", color: "var(--text-primary)", borderRadius: 6, padding: "8px 10px", fontSize: 13 }}
            />
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
              Minimum confidence required to trigger a supervised alert (0.60 recommended)
            </div>
          </div>

          <div style={{ marginBottom: 14 }}>
            <label style={{ fontSize: 12, color: "var(--text-muted)", display: "block", marginBottom: 6 }}>
              Anomaly Detection Threshold
            </label>
            <input
              type="number"
              value={anomalyThreshold}
              onChange={(e) => setAnomalyThreshold(e.target.value)}
              min="0.1"
              max="1.0"
              step="0.05"
              style={{ width: "100%", background: "var(--bg-secondary)", border: "1px solid var(--border-color)", color: "var(--text-primary)", borderRadius: 6, padding: "8px 10px", fontSize: 13 }}
            />
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
              Isolation Forest anomaly score threshold
            </div>
          </div>

          <div style={{ marginBottom: 14 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <label style={{ fontSize: 12, color: "var(--text-muted)" }}>
                SHAP Explainability Engine
              </label>
              <button
                onClick={() => setShapEnabled(!shapEnabled)}
                style={{
                  width: 40,
                  height: 22,
                  borderRadius: 11,
                  background: shapEnabled ? "var(--accent-blue)" : "var(--bg-secondary)",
                  border: `1px solid ${shapEnabled ? "var(--accent-blue)" : "var(--border-color)"}`,
                  cursor: "pointer",
                  position: "relative",
                  transition: "all 0.2s",
                }}
              >
                <div
                  style={{
                    width: 16,
                    height: 16,
                    borderRadius: "50%",
                    background: "#fff",
                    position: "absolute",
                    top: 2,
                    left: shapEnabled ? 20 : 2,
                    transition: "left 0.2s",
                  }}
                />
              </button>
            </div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
              Enable per-prediction SHAP feature attribution (required for explainability)
            </div>
          </div>

          <div style={{ marginBottom: 14 }}>
            <label style={{ fontSize: 12, color: "var(--text-muted)", display: "block", marginBottom: 6 }}>
              Log Level
            </label>
            <select
              value={logLevel}
              onChange={(e) => setLogLevel(e.target.value)}
              style={{ width: "100%", background: "var(--bg-secondary)", border: "1px solid var(--border-color)", color: "var(--text-primary)", borderRadius: 6, padding: "8px 10px", fontSize: 13 }}
            >
              <option value="debug">Debug</option>
              <option value="info">Info</option>
              <option value="warning">Warning</option>
              <option value="error">Error</option>
            </select>
          </div>
        </div>

        {/* Database / Retention */}
        <div className="card" style={{ padding: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginBottom: 16, display: "flex", alignItems: "center", gap: 8 }}>
            <FiDatabase size={14} color="var(--accent-blue)" />
            Data Retention
          </div>

          <div style={{ marginBottom: 14 }}>
            <label style={{ fontSize: 12, color: "var(--text-muted)", display: "block", marginBottom: 6 }}>
              Retention Period (days)
            </label>
            <input
              type="number"
              value={retentionDays}
              onChange={(e) => setRetentionDays(e.target.value)}
              min="1"
              max="365"
              style={{ width: "100%", background: "var(--bg-secondary)", border: "1px solid var(--border-color)", color: "var(--text-primary)", borderRadius: 6, padding: "8px 10px", fontSize: 13 }}
            />
          </div>

          <div
            style={{
              padding: "10px 12px",
              background: "rgba(59,130,246,0.08)",
              borderRadius: 6,
              border: "1px solid rgba(59,130,246,0.2)",
              fontSize: 11,
              color: "var(--text-secondary)",
              lineHeight: 1.6,
            }}
          >
            <strong style={{ color: "var(--accent-blue)" }}>Local Data Residency:</strong> All data is stored locally on this
            system. No data is transmitted to external services. AEGIS-XAI operates in an air-gapped architecture.
          </div>
        </div>

        {/* Model Information */}
        <div className="card" style={{ padding: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginBottom: 16, display: "flex", alignItems: "center", gap: 8 }}>
            <FiShield size={14} color="var(--accent-blue)" />
            Loaded Models
          </div>

          {models.length === 0 ? (
            <div style={{ color: "var(--text-muted)", fontSize: 12 }}>Loading model information...</div>
          ) : (
            models.map((model) => (
              <div
                key={model.modelId}
                style={{
                  marginBottom: 12,
                  padding: 12,
                  background: "var(--bg-secondary)",
                  borderRadius: 6,
                  border: "1px solid var(--border-subtle)",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: "var(--accent-cyan)" }}>{model.modelType}</span>
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>v{model.version}</span>
                </div>
                {model.accuracy && (
                  <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                    Accuracy: <strong>{(model.accuracy * 100).toFixed(2)}%</strong>
                    {model.precision && <> · Precision: <strong>{(model.precision * 100).toFixed(2)}%</strong></>}
                    {model.f1Score && <> · F1: <strong>{(model.f1Score * 100).toFixed(2)}%</strong></>}
                  </div>
                )}
                {model.trainingSamples && (
                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                    Training samples: {model.trainingSamples.toLocaleString()}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>

      {/* MITRE Reference */}
      <div className="card" style={{ padding: 20, marginTop: 20 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginBottom: 14, display: "flex", alignItems: "center", gap: 8 }}>
          <FiInfo size={14} color="var(--accent-blue)" />
          MITRE ATT&CK Mapping Reference
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
          {[
            { family: "DoS", id: "TA0040", tactic: "Impact", tech: "T1498 - Network DoS" },
            { family: "Probe", id: "TA0043", tactic: "Reconnaissance", tech: "T1046 - Network Service Discovery" },
            { family: "R2L", id: "TA0001", tactic: "Initial Access", tech: "T1078 - Valid Accounts" },
            { family: "U2R", id: "TA0004", tactic: "Privilege Escalation", tech: "T1068 - Exploitation for PrivEsc" },
          ].map(({ family, id, tactic, tech }) => (
            <div key={family} style={{ padding: 12, background: "var(--bg-secondary)", borderRadius: 6, border: "1px solid var(--border-subtle)" }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: "var(--accent-blue)", marginBottom: 4 }}>{family}</div>
              <div style={{ fontSize: 11, color: "var(--text-primary)", fontWeight: 500 }}>{id}</div>
              <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>{tactic}</div>
              <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>{tech}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
