"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import {
  FiActivity,
  FiPlay,
  FiSquare,
  FiAlertTriangle,
  FiPackage,
  FiGitBranch,
  FiShield,
  FiWifi,
  FiDatabase,
  FiCpu,
  FiEye,
  FiRefreshCw,
  FiChevronRight,
} from "react-icons/fi";

interface MonitorState {
  isRunning: boolean;
  mode: string;
  sessionId: string | null;
  networkInterface: string | null;
  packetsCapured: number;
  flowsProcessed: number;
  alertsGenerated: number;
  lastActivity: string | null;
  engineStatus: Record<string, string>;
}

interface DetectionEvent {
  eventId: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  prediction: string;
  confidence: number;
  severity: string;
  anomalyDetected: boolean;
  mitreTacticId: string;
  mitreTacticName: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "var(--severity-critical)",
  HIGH: "var(--severity-high)",
  MEDIUM: "var(--severity-medium)",
  NORMAL: "var(--severity-normal)",
};

const ENGINE_ICONS: Record<string, React.ComponentType<{ size?: number; color?: string }>> = {
  capture: FiWifi,
  flow: FiGitBranch,
  ml: FiCpu,
  shap: FiEye,
  database: FiDatabase,
  api: FiActivity,
};

export default function LiveMonitorPage() {
  const [state, setState] = useState<MonitorState | null>(null);
  const [events, setEvents] = useState<DetectionEvent[]>([]);
  const [selectedInterface, setSelectedInterface] = useState("eth0");
  const [selectedMode, setSelectedMode] = useState("live");
  const [isStarting, setIsStarting] = useState(false);
  const [isStopping, setIsStopping] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<"connected" | "disconnected" | "connecting">("disconnected");
  const eventSourceRef = useRef<EventSource | null>(null);
  const eventsRef = useRef<DetectionEvent[]>([]);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch("/api/monitor/status");
      if (res.ok) {
        const data = await res.json();
        setState(data);
      }
    } catch {
      // Ignore
    }
  }, []);

  const connectSSE = useCallback(() => {
  if (eventSourceRef.current) {
    eventSourceRef.current.close();
  }

  setConnectionStatus("connecting");

  const es = new EventSource("/api/events");
  eventSourceRef.current = es;

  es.onopen = () => {
    setConnectionStatus("connected");
  };

  es.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);

      if (msg.type === "detection") {
        const evt: DetectionEvent = msg.payload;
        eventsRef.current = [evt, ...eventsRef.current].slice(0, 100);
        setEvents([...eventsRef.current]);
      }

      if (msg.type === "stats" || msg.type === "monitor_status") {
        fetchStatus();
      }
    } catch {
      // ignore parse errors
    }
  };

  es.onerror = () => {
  setConnectionStatus("disconnected");
};
}, [fetchStatus]);

  useEffect(() => {
  const statusTimer = window.setTimeout(() => {
    void fetchStatus();
  }, 0);

  const sseTimer = window.setTimeout(() => {
    connectSSE();
  }, 0);

  return () => {
    window.clearTimeout(statusTimer);
    window.clearTimeout(sseTimer);
    eventSourceRef.current?.close();
  };
}, [fetchStatus, connectSSE]);

  const handleStart = async () => {
    setIsStarting(true);
    setError(null);
    try {
      const res = await fetch("/api/monitor/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: selectedMode, networkInterface: selectedInterface }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to start");
      await fetchStatus();
    } catch (err) {
      setError(String(err));
    } finally {
      setIsStarting(false);
    }
  };

  const handleStop = async () => {
    setIsStopping(true);
    setError(null);
    try {
      const res = await fetch("/api/monitor/stop", { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to stop");
      await fetchStatus();
    } catch (err) {
      setError(String(err));
    } finally {
      setIsStopping(false);
    }
  };

  const isRunning = state?.isRunning ?? false;

  return (
    <div style={{ padding: 24 }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: "var(--text-primary)", margin: 0 }}>
            Live Monitor
          </h1>
          <p style={{ fontSize: 13, color: "var(--text-muted)", margin: "4px 0 0" }}>
            Real-time network traffic analysis and threat detection
          </p>
        </div>

        {/* SSE connection indicator */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: "var(--text-muted)" }}>
          <div
            style={{
              width: 8,
              height: 8,
              borderRadius: "50%",
              background: connectionStatus === "connected" ? "var(--accent-green)"
                : connectionStatus === "connecting" ? "var(--accent-yellow)"
                : "var(--text-muted)",
            }}
          />
          {connectionStatus === "connected" ? "Event stream connected"
            : connectionStatus === "connecting" ? "Connecting..."
            : "Reconnecting..."}
        </div>
      </div>

      {error && (
        <div
          style={{
            background: "rgba(239,68,68,0.1)",
            border: "1px solid rgba(239,68,68,0.3)",
            borderRadius: 6,
            padding: "10px 14px",
            marginBottom: 16,
            color: "var(--severity-critical)",
            fontSize: 13,
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <FiAlertTriangle size={14} />
          {error}
        </div>
      )}

      {/* Control Panel */}
      <div className="card" style={{ padding: 20, marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
          <div>
            <label style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", display: "block", marginBottom: 6 }}>
              Mode
            </label>
            <select
              value={selectedMode}
              onChange={(e) => setSelectedMode(e.target.value)}
              disabled={isRunning}
              style={{
                background: "var(--bg-secondary)",
                border: "1px solid var(--border-color)",
                color: "var(--text-primary)",
                borderRadius: 6,
                padding: "7px 12px",
                fontSize: 13,
                cursor: isRunning ? "not-allowed" : "pointer",
              }}
            >
              <option value="live">Live Capture</option>
              <option value="pcap">PCAP Analysis</option>
            </select>
          </div>

          <div>
            <label style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", display: "block", marginBottom: 6 }}>
              Interface
            </label>
            <select
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              disabled={isRunning}
              style={{
                background: "var(--bg-secondary)",
                border: "1px solid var(--border-color)",
                color: "var(--text-primary)",
                borderRadius: 6,
                padding: "7px 12px",
                fontSize: 13,
                cursor: isRunning ? "not-allowed" : "pointer",
              }}
            >
              <option value="eth0">eth0 (Ethernet)</option>
              <option value="wlan0">wlan0 (Wireless)</option>
              <option value="lo">lo (Loopback)</option>
              <option value="any">any (All interfaces)</option>
            </select>
          </div>

          <div style={{ marginTop: 20, display: "flex", gap: 10 }}>
            {!isRunning ? (
              <button
                onClick={handleStart}
                disabled={isStarting}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  padding: "8px 20px",
                  background: "var(--accent-blue)",
                  color: "#fff",
                  border: "none",
                  borderRadius: 6,
                  fontSize: 13,
                  fontWeight: 600,
                  cursor: isStarting ? "wait" : "pointer",
                  opacity: isStarting ? 0.7 : 1,
                }}
              >
                {isStarting ? <FiRefreshCw size={14} /> : <FiPlay size={14} />}
                {isStarting ? "Starting..." : "Start Monitoring"}
              </button>
            ) : (
              <button
                onClick={handleStop}
                disabled={isStopping}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  padding: "8px 20px",
                  background: "rgba(239,68,68,0.15)",
                  color: "var(--severity-critical)",
                  border: "1px solid rgba(239,68,68,0.3)",
                  borderRadius: 6,
                  fontSize: 13,
                  fontWeight: 600,
                  cursor: isStopping ? "wait" : "pointer",
                }}
              >
                <FiSquare size={14} />
                {isStopping ? "Stopping..." : "Stop Monitoring"}
              </button>
            )}
          </div>

          {/* Status */}
          <div style={{ marginTop: 20, display: "flex", alignItems: "center", gap: 8 }}>
            <div
              className={isRunning ? "pulse-live" : ""}
              style={{
                width: 10,
                height: 10,
                borderRadius: "50%",
                background: isRunning ? "var(--accent-green)" : "var(--text-muted)",
              }}
            />
            <span style={{ fontSize: 13, fontWeight: 600, color: isRunning ? "var(--accent-green)" : "var(--text-muted)" }}>
              {isRunning ? `MONITORING ACTIVE · ${state?.mode?.toUpperCase()}` : "MONITORING STOPPED"}
            </span>
          </div>
        </div>
      </div>

      {/* Stats row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 20 }}>
        {[
          { label: "Packets Captured", value: state?.packetsCapured ?? 0, icon: FiPackage, color: "var(--accent-cyan)" },
          { label: "Flows Processed", value: state?.flowsProcessed ?? 0, icon: FiGitBranch, color: "var(--accent-blue)" },
          { label: "Alerts Generated", value: state?.alertsGenerated ?? 0, icon: FiAlertTriangle, color: "var(--severity-high)" },
          { label: "Critical Events", value: events.filter(e => e.severity === "CRITICAL").length, icon: FiShield, color: "var(--severity-critical)" },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="card" style={{ padding: 18 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
              <span style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
                {label}
              </span>
              <Icon size={16} color={color} />
            </div>
            <div style={{ fontSize: 28, fontWeight: 700, color, fontVariantNumeric: "tabular-nums" }}>
              {value.toLocaleString()}
            </div>
          </div>
        ))}
      </div>

      {/* Engine Status */}
      <div className="card" style={{ padding: 16, marginBottom: 20 }}>
        <div style={{ fontSize: 12, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 12 }}>
          Engine Status
        </div>
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
          {Object.entries(state?.engineStatus ?? {}).map(([name, status]) => {
            const Icon = ENGINE_ICONS[name] || FiActivity;
            const color = status === "online" ? "var(--accent-green)"
              : status === "error" ? "var(--severity-critical)"
              : "var(--text-muted)";
            return (
              <div key={name} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <div
                  className={status === "online" ? "status-online" : status === "error" ? "status-error" : "status-offline"}
                  style={{ width: 7, height: 7, borderRadius: "50%" }}
                />
                <Icon size={13} color={color} />
                <span style={{ fontSize: 12, color, textTransform: "capitalize" }}>{name}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Event Stream */}
      <div className="card">
        <div
          style={{
            padding: "14px 18px",
            borderBottom: "1px solid var(--border-subtle)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <FiActivity size={14} color="var(--accent-blue)" />
            <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>
              Detection Events
            </span>
            <span
              style={{
                fontSize: 11,
                color: "var(--text-muted)",
                background: "var(--bg-secondary)",
                padding: "2px 8px",
                borderRadius: 10,
              }}
            >
              {events.length} events
            </span>
          </div>
          {isRunning && (
            <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: "var(--accent-green)" }}>
              <div className="pulse-live" style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--accent-green)" }} />
              Live
            </div>
          )}
        </div>

        {events.length === 0 ? (
          <div
            style={{
              padding: 48,
              textAlign: "center",
              color: "var(--text-muted)",
              fontSize: 14,
            }}
          >
            {isRunning
              ? "Waiting for network events..."
              : "Start monitoring to see detection events"}
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                  {["Time", "Source", "Destination", "Protocol", "Prediction", "Confidence", "Severity", "MITRE"].map(h => (
                    <th
                      key={h}
                      style={{
                        padding: "10px 14px",
                        textAlign: "left",
                        fontSize: 11,
                        color: "var(--text-muted)",
                        textTransform: "uppercase",
                        letterSpacing: "0.06em",
                        fontWeight: 500,
                        whiteSpace: "nowrap",
                      }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {events.slice(0, 50).map((evt, i) => (
                  <tr
                    key={`${evt.eventId}-${i}`}
                    className="table-row-hover"
                    style={{
                      borderBottom: "1px solid var(--border-subtle)",
                      background: evt.severity === "CRITICAL" ? "rgba(239,68,68,0.03)" : "transparent",
                    }}
                  >
                    <td style={{ padding: "9px 14px", fontSize: 12, color: "var(--text-muted)" }} className="mono">
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </td>
                    <td style={{ padding: "9px 14px", fontSize: 12 }} className="mono">
                      {evt.sourceIp}:{evt.sourcePort}
                    </td>
                    <td style={{ padding: "9px 14px", fontSize: 12 }} className="mono">
                      {evt.destinationIp}:{evt.destinationPort}
                    </td>
                    <td style={{ padding: "9px 14px", fontSize: 11 }}>
                      <span
                        style={{
                          background: "var(--bg-secondary)",
                          padding: "2px 8px",
                          borderRadius: 4,
                          color: "var(--accent-cyan)",
                          fontWeight: 500,
                        }}
                      >
                        {evt.protocol.toUpperCase()}
                      </span>
                    </td>
                    <td style={{ padding: "9px 14px", fontSize: 12, fontWeight: 600 }}>
                      <span style={{ color: evt.prediction !== "Normal" ? SEVERITY_COLORS[evt.severity] : "var(--accent-green)" }}>
                        {evt.prediction}
                      </span>
                    </td>
                    <td style={{ padding: "9px 14px", fontSize: 12 }} className="mono">
                      {(evt.confidence * 100).toFixed(1)}%
                    </td>
                    <td style={{ padding: "9px 14px" }}>
                      <span
                        className={`severity-${evt.severity.toLowerCase()}`}
                        style={{
                          fontSize: 11,
                          fontWeight: 700,
                          padding: "2px 8px",
                          borderRadius: 4,
                          letterSpacing: "0.05em",
                        }}
                      >
                        {evt.severity}
                      </span>
                    </td>
                    <td style={{ padding: "9px 14px", fontSize: 11, color: "var(--text-muted)" }}>
                      {evt.mitreTacticId !== "N/A" ? (
                        <span>
                          <span style={{ color: "var(--accent-blue)", fontWeight: 500 }}>{evt.mitreTacticId}</span>
                          {" · "}{evt.mitreTacticName}
                        </span>
                      ) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
