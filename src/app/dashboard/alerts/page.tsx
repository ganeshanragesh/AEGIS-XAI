"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  FiAlertTriangle,
  FiFilter,
  FiSearch,
  FiRefreshCw,
  FiEye,
  FiChevronLeft,
  FiChevronRight,
  FiCheck,
  FiX,
  FiInfo,
} from "react-icons/fi";

interface Alert {
  id: number;
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
  mitreId: string;
  mitreTactic: string;
  status: string;
  captureMode: string;
}

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "NORMAL"];

export default function AlertsPage() {
  const router = useRouter();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const pageSize = 25;

  // Filters
  const [severity, setSeverity] = useState("");
  const [prediction, setPrediction] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const [status, setStatus] = useState("");
  const [refreshing, setRefreshing] = useState(false);

  const fetchAlerts = useCallback(async (showRefresh = false) => {
    if (showRefresh) setRefreshing(true);
    setLoading(true);

    const params = new URLSearchParams();
    if (severity) params.set("severity", severity);
    if (prediction) params.set("prediction", prediction);
    if (sourceIp) params.set("sourceIp", sourceIp);
    if (status) params.set("status", status);
    params.set("limit", String(pageSize));
    params.set("offset", String(page * pageSize));

    try {
      const res = await fetch(`/api/alerts?${params}`);
      if (res.ok) {
        const data = await res.json();
        setAlerts(data.data ?? []);
        setTotal(data.pagination?.total ?? 0);
      }
    } finally {
      setLoading(false);
      if (showRefresh) setRefreshing(false);
    }
  }, [severity, prediction, sourceIp, status, page]);

  useEffect(() => {
  let cancelled = false;

  const loadAlerts = async () => {
    setLoading(true);

    const params = new URLSearchParams();
    if (severity) params.set("severity", severity);
    if (prediction) params.set("prediction", prediction);
    if (sourceIp) params.set("sourceIp", sourceIp);
    if (status) params.set("status", status);
    params.set("limit", String(pageSize));
    params.set("offset", String(page * pageSize));

    try {
      const res = await fetch(`/api/alerts?${params}`);
      if (!cancelled && res.ok) {
        const data = await res.json();
        setAlerts(data.data ?? []);
        setTotal(data.pagination?.total ?? 0);
      }
    } finally {
      if (!cancelled) {
        setLoading(false);
      }
    }
  };

  void loadAlerts();

  return () => {
    cancelled = true;
  };
}, [severity, prediction, sourceIp, status, page]);

  const handleStatusUpdate = async (id: number, newStatus: string) => {
    await fetch(`/api/alerts/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: newStatus }),
    });
    fetchAlerts();
  };

  const totalPages = Math.ceil(total / pageSize);

  return (
    <div style={{ padding: 24 }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: "var(--text-primary)", margin: 0 }}>
            Alert Management
          </h1>
          <p style={{ fontSize: 13, color: "var(--text-muted)", margin: "4px 0 0" }}>
            {total.toLocaleString()} total alerts
          </p>
        </div>
        <button
          onClick={() => fetchAlerts(true)}
          disabled={refreshing}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            padding: "7px 14px",
            background: "var(--bg-card)",
            border: "1px solid var(--border-subtle)",
            borderRadius: 6,
            color: "var(--text-secondary)",
            fontSize: 13,
            cursor: "pointer",
          }}
        >
          <FiRefreshCw size={13} />
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="card" style={{ padding: 16, marginBottom: 16, display: "flex", gap: 12, flexWrap: "wrap", alignItems: "flex-end" }}>
        <div>
          <label style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", display: "block", marginBottom: 5 }}>
            Severity
          </label>
          <select
            value={severity}
            onChange={(e) => { setSeverity(e.target.value); setPage(0); }}
            style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)", color: "var(--text-primary)", borderRadius: 6, padding: "6px 10px", fontSize: 12 }}
          >
            <option value="">All</option>
            {SEVERITY_ORDER.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>

        <div>
          <label style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", display: "block", marginBottom: 5 }}>
            Attack Type
          </label>
          <select
            value={prediction}
            onChange={(e) => { setPrediction(e.target.value); setPage(0); }}
            style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)", color: "var(--text-primary)", borderRadius: 6, padding: "6px 10px", fontSize: 12 }}
          >
            <option value="">All</option>
            {["Normal", "DoS", "Probe", "R2L", "U2R"].map(p => <option key={p} value={p}>{p}</option>)}
          </select>
        </div>

        <div>
          <label style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", display: "block", marginBottom: 5 }}>
            Status
          </label>
          <select
            value={status}
            onChange={(e) => { setStatus(e.target.value); setPage(0); }}
            style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)", color: "var(--text-primary)", borderRadius: 6, padding: "6px 10px", fontSize: 12 }}
          >
            <option value="">All</option>
            <option value="open">Open</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>
        </div>

        <div>
          <label style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", display: "block", marginBottom: 5 }}>
            Source IP
          </label>
          <input
            type="text"
            value={sourceIp}
            onChange={(e) => { setSourceIp(e.target.value); setPage(0); }}
            placeholder="Filter by IP..."
            style={{ background: "var(--bg-secondary)", border: "1px solid var(--border-color)", color: "var(--text-primary)", borderRadius: 6, padding: "6px 10px", fontSize: 12, width: 140 }}
          />
        </div>
      </div>

      {/* Alert Table */}
      <div className="card">
        {loading ? (
          <div style={{ padding: 40, textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
            Loading alerts...
          </div>
        ) : alerts.length === 0 ? (
          <div style={{ padding: 64, textAlign: "center" }}>
            <FiAlertTriangle size={36} color="var(--text-muted)" style={{ marginBottom: 12 }} />
            <div style={{ color: "var(--text-muted)", fontSize: 14 }}>No alerts found</div>
            <div style={{ color: "var(--text-muted)", fontSize: 12, marginTop: 6 }}>
              Try adjusting your filters or start monitoring to generate alerts
            </div>
          </div>
        ) : (
          <>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                    {["ID", "Timestamp", "Source", "Destination", "Protocol", "Prediction", "Confidence", "Severity", "MITRE", "Status", "Actions"].map(h => (
                      <th
                        key={h}
                        style={{
                          padding: "10px 12px",
                          textAlign: "left",
                          fontSize: 11,
                          color: "var(--text-muted)",
                          textTransform: "uppercase",
                          letterSpacing: "0.05em",
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
                  {alerts.map((alert) => (
                    <tr
                      key={alert.id}
                      className="table-row-hover"
                      style={{
                        borderBottom: "1px solid var(--border-subtle)",
                        background: alert.severity === "CRITICAL" ? "rgba(239,68,68,0.03)" : "transparent",
                      }}
                    >
                      <td style={{ padding: "9px 12px", fontSize: 11, color: "var(--text-muted)" }} className="mono">
                        {alert.eventId.split("-").slice(1).join("-")}
                      </td>
                      <td style={{ padding: "9px 12px", fontSize: 11, color: "var(--text-muted)", whiteSpace: "nowrap" }} className="mono">
                        {new Date(alert.timestamp).toLocaleString()}
                      </td>
                      <td style={{ padding: "9px 12px", fontSize: 11 }} className="mono">
                        {alert.sourceIp}:{alert.sourcePort}
                      </td>
                      <td style={{ padding: "9px 12px", fontSize: 11 }} className="mono">
                        {alert.destinationIp}:{alert.destinationPort}
                      </td>
                      <td style={{ padding: "9px 12px", fontSize: 11 }}>
                        <span style={{ background: "var(--bg-secondary)", padding: "2px 6px", borderRadius: 3, color: "var(--accent-cyan)", fontSize: 11 }}>
                          {alert.protocol.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ padding: "9px 12px", fontSize: 12, fontWeight: 600, color: alert.prediction !== "Normal" ? "var(--severity-high)" : "var(--accent-green)" }}>
                        {alert.prediction}
                      </td>
                      <td style={{ padding: "9px 12px", fontSize: 11 }} className="mono">
                        {(alert.confidence * 100).toFixed(1)}%
                      </td>
                      <td style={{ padding: "9px 12px" }}>
                        <span
                          className={`severity-${alert.severity.toLowerCase()}`}
                          style={{ fontSize: 10, fontWeight: 700, padding: "2px 7px", borderRadius: 3, letterSpacing: "0.04em" }}
                        >
                          {alert.severity}
                        </span>
                      </td>
                      <td style={{ padding: "9px 12px", fontSize: 11, color: alert.mitreId !== "N/A" ? "var(--accent-blue)" : "var(--text-muted)" }}>
                        {alert.mitreId !== "N/A" ? alert.mitreId : "—"}
                      </td>
                      <td style={{ padding: "9px 12px" }}>
                        <span style={{
                          fontSize: 10,
                          padding: "2px 7px",
                          borderRadius: 3,
                          background: alert.status === "open" ? "rgba(59,130,246,0.1)"
                            : alert.status === "resolved" ? "rgba(16,185,129,0.1)"
                            : "rgba(100,116,139,0.1)",
                          color: alert.status === "open" ? "var(--accent-blue)"
                            : alert.status === "resolved" ? "var(--accent-green)"
                            : "var(--text-muted)",
                          border: `1px solid ${alert.status === "open" ? "rgba(59,130,246,0.3)" : alert.status === "resolved" ? "rgba(16,185,129,0.3)" : "rgba(100,116,139,0.2)"}`,
                        }}>
                          {alert.status}
                        </span>
                      </td>
                      <td style={{ padding: "9px 12px" }}>
                        <div style={{ display: "flex", gap: 4 }}>
                          <button
                            onClick={() => router.push(`/dashboard/alerts/${alert.id}`)}
                            title="View details"
                            style={{ background: "none", border: "none", cursor: "pointer", color: "var(--accent-blue)", padding: 4 }}
                          >
                            <FiEye size={13} />
                          </button>
                          {alert.status === "open" && (
                            <button
                              onClick={() => handleStatusUpdate(alert.id, "acknowledged")}
                              title="Acknowledge"
                              style={{ background: "none", border: "none", cursor: "pointer", color: "var(--accent-green)", padding: 4 }}
                            >
                              <FiCheck size={13} />
                            </button>
                          )}
                          {alert.status !== "false_positive" && (
                            <button
                              onClick={() => handleStatusUpdate(alert.id, "false_positive")}
                              title="Mark false positive"
                              style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)", padding: 4 }}
                            >
                              <FiX size={13} />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div
              style={{
                padding: "12px 16px",
                borderTop: "1px solid var(--border-subtle)",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
              }}
            >
              <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
                {page * pageSize + 1}–{Math.min((page + 1) * pageSize, total)} of {total.toLocaleString()}
              </span>
              <div style={{ display: "flex", gap: 6 }}>
                <button
                  onClick={() => setPage(p => Math.max(0, p - 1))}
                  disabled={page === 0}
                  style={{ padding: "5px 10px", background: "var(--bg-secondary)", border: "1px solid var(--border-subtle)", borderRadius: 5, color: "var(--text-secondary)", cursor: page === 0 ? "not-allowed" : "pointer", opacity: page === 0 ? 0.4 : 1 }}
                >
                  <FiChevronLeft size={13} />
                </button>
                <span style={{ padding: "5px 12px", fontSize: 12, color: "var(--text-muted)" }}>
                  {page + 1} / {totalPages}
                </span>
                <button
                  onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                  disabled={page >= totalPages - 1}
                  style={{ padding: "5px 10px", background: "var(--bg-secondary)", border: "1px solid var(--border-subtle)", borderRadius: 5, color: "var(--text-secondary)", cursor: page >= totalPages - 1 ? "not-allowed" : "pointer", opacity: page >= totalPages - 1 ? 0.4 : 1 }}
                >
                  <FiChevronRight size={13} />
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
