"use client";

import { useState, useEffect, use } from "react";
import { useRouter } from "next/navigation";
import {
  FiArrowLeft,
  FiAlertTriangle,
  FiShield,
  FiActivity,
  FiCpu,
  FiInfo,
  FiCheck,
  FiX,
  FiGlobe,
  FiTarget,
} from "react-icons/fi";

interface ShapValue {
  id: number;
  featureName: string;
  featureValue: number;
  shapValue: number;
  rank: number;
  direction: string;
}

interface Detection {
  id: number;
  model: string;
  prediction: string;
  confidence: number;
}

interface AlertDetail {
  alert: {
    id: number;
    eventId: string;
    timestamp: string;
    sourceIp: string;
    destinationIp: string;
    sourcePort: number;
    destinationPort: number;
    protocol: string;
    service: string;
    prediction: string;
    confidence: number;
    anomalyDetected: boolean;
    anomalyScore: number;
    severity: string;
    mitreId: string;
    mitreTactic: string;
    mitreDescription: string;
    rfConfidence: number;
    xgbConfidence: number;
    modelVersion: string;
    status: string;
    captureMode: string;
    inferenceTimeMs: number;
    shapTimeMs: number;
  };
  detections: Detection[];
  shapValues: ShapValue[];
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "var(--severity-critical)",
  HIGH: "var(--severity-high)",
  MEDIUM: "var(--severity-medium)",
  NORMAL: "var(--severity-normal)",
};

export default function AlertDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const router = useRouter();
  const [detail, setDetail] = useState<AlertDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch(`/api/alerts/${id}`)
      .then(res => {
        if (!res.ok) throw new Error("Alert not found");
        return res.json();
      })
      .then(data => setDetail(data))
      .catch(err => setError(String(err)))
      .finally(() => setLoading(false));
  }, [id]);

  const handleStatusUpdate = async (newStatus: string) => {
    await fetch(`/api/alerts/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: newStatus }),
    });
    const res = await fetch(`/api/alerts/${id}`);
    if (res.ok) setDetail(await res.json());
  };

  if (loading) {
    return <div style={{ padding: 24, color: "var(--text-muted)", fontSize: 13 }}>Loading alert details...</div>;
  }

  if (error || !detail) {
    return (
      <div style={{ padding: 24 }}>
        <div style={{ color: "var(--severity-critical)", fontSize: 14 }}>{error || "Alert not found"}</div>
        <button onClick={() => router.back()} style={{ marginTop: 12, color: "var(--accent-blue)", background: "none", border: "none", cursor: "pointer", fontSize: 13 }}>
          ← Back to Alerts
        </button>
      </div>
    );
  }

  const { alert, detections, shapValues } = detail;
  const maxShap = Math.max(...shapValues.map(s => Math.abs(s.shapValue)));

  return (
    <div style={{ padding: 24 }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
        <button
          onClick={() => router.back()}
          style={{ display: "flex", alignItems: "center", gap: 6, background: "none", border: "none", cursor: "pointer", color: "var(--text-secondary)", fontSize: 13 }}
        >
          <FiArrowLeft size={14} />
          Back
        </button>
        <div style={{ height: 16, width: 1, background: "var(--border-subtle)" }} />
        <div>
          <h1 style={{ fontSize: 18, fontWeight: 700, color: "var(--text-primary)", margin: 0 }}>
            Alert Detail
          </h1>
          <span style={{ fontSize: 11, color: "var(--text-muted)" }} className="mono">{alert.eventId}</span>
        </div>
        <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
          {alert.status === "open" && (
            <button
              onClick={() => handleStatusUpdate("acknowledged")}
              style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 14px", background: "rgba(16,185,129,0.1)", border: "1px solid rgba(16,185,129,0.3)", borderRadius: 6, color: "var(--accent-green)", fontSize: 12, cursor: "pointer" }}
            >
              <FiCheck size={12} />
              Acknowledge
            </button>
          )}
          {alert.status !== "resolved" && (
            <button
              onClick={() => handleStatusUpdate("resolved")}
              style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 14px", background: "rgba(59,130,246,0.1)", border: "1px solid rgba(59,130,246,0.3)", borderRadius: 6, color: "var(--accent-blue)", fontSize: 12, cursor: "pointer" }}
            >
              <FiShield size={12} />
              Mark Resolved
            </button>
          )}
        </div>
      </div>

      {/* Severity Banner */}
      <div
        style={{
          borderRadius: 8,
          padding: "16px 20px",
          marginBottom: 20,
          background: `rgba(${alert.severity === "CRITICAL" ? "239,68,68" : alert.severity === "HIGH" ? "249,115,22" : alert.severity === "MEDIUM" ? "234,179,8" : "16,185,129"}, 0.08)`,
          border: `1px solid ${SEVERITY_COLORS[alert.severity]}40`,
          display: "flex",
          alignItems: "center",
          gap: 16,
        }}
      >
        <FiAlertTriangle size={24} color={SEVERITY_COLORS[alert.severity]} />
        <div>
          <div style={{ fontSize: 18, fontWeight: 700, color: SEVERITY_COLORS[alert.severity] }}>
            {alert.severity} — {alert.prediction}
          </div>
          <div style={{ fontSize: 13, color: "var(--text-muted)", marginTop: 2 }}>
            Confidence: {(alert.confidence * 100).toFixed(1)}% · Anomaly: {alert.anomalyDetected ? "Detected" : "Not detected"} · {new Date(alert.timestamp).toLocaleString()}
          </div>
        </div>
        <div style={{ marginLeft: "auto", textAlign: "right" }}>
          <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.06em" }}>Status</div>
          <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginTop: 2 }}>{alert.status}</div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 20 }}>
        {/* Network Details */}
        <div className="card" style={{ padding: 20 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 14, display: "flex", alignItems: "center", gap: 6 }}>
            <FiGlobe size={12} />
            Network Details
          </div>
          {[
            ["Source IP", alert.sourceIp],
            ["Source Port", String(alert.sourcePort)],
            ["Destination IP", alert.destinationIp],
            ["Destination Port", String(alert.destinationPort)],
            ["Protocol", alert.protocol.toUpperCase()],
            ["Service", alert.service || "unknown"],
            ["Capture Mode", alert.captureMode],
          ].map(([label, value]) => (
            <div key={label} style={{ display: "flex", justifyContent: "space-between", marginBottom: 10, alignItems: "baseline" }}>
              <span style={{ fontSize: 12, color: "var(--text-muted)" }}>{label}</span>
              <span style={{ fontSize: 12, color: "var(--text-primary)", fontWeight: 500 }} className="mono">{value}</span>
            </div>
          ))}
        </div>

        {/* Detection Details */}
        <div className="card" style={{ padding: 20 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 14, display: "flex", alignItems: "center", gap: 6 }}>
            <FiCpu size={12} />
            Detection Details
          </div>
          {[
            ["Prediction", alert.prediction],
            ["Ensemble Confidence", `${(alert.confidence * 100).toFixed(2)}%`],
            ["RF Confidence", `${((alert.rfConfidence ?? 0) * 100).toFixed(2)}%`],
            ["XGBoost Confidence", `${((alert.xgbConfidence ?? 0) * 100).toFixed(2)}%`],
            ["Anomaly Score", alert.anomalyScore !== null ? alert.anomalyScore?.toFixed(4) : "N/A"],
            ["Inference Time", `${alert.inferenceTimeMs?.toFixed(2) ?? "N/A"} ms`],
            ["SHAP Time", `${alert.shapTimeMs?.toFixed(2) ?? "N/A"} ms`],
            ["Model Version", alert.modelVersion || "1.0.0"],
          ].map(([label, value]) => (
            <div key={label} style={{ display: "flex", justifyContent: "space-between", marginBottom: 10, alignItems: "baseline" }}>
              <span style={{ fontSize: 12, color: "var(--text-muted)" }}>{label}</span>
              <span style={{ fontSize: 12, color: "var(--text-primary)", fontWeight: 500 }} className="mono">{value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* MITRE ATT&CK */}
      {alert.mitreId && alert.mitreId !== "N/A" && (
        <div className="card" style={{ padding: 20, marginBottom: 20, background: "rgba(59,130,246,0.04)", borderColor: "rgba(59,130,246,0.2)" }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 12, display: "flex", alignItems: "center", gap: 6 }}>
            <FiTarget size={12} />
            MITRE ATT&CK Framework
          </div>
          <div style={{ display: "flex", gap: 20, alignItems: "flex-start" }}>
            <div
              style={{
                background: "rgba(59,130,246,0.15)",
                border: "1px solid rgba(59,130,246,0.3)",
                borderRadius: 8,
                padding: "12px 16px",
                minWidth: 120,
                textAlign: "center",
              }}
            >
              <div style={{ fontSize: 16, fontWeight: 700, color: "var(--accent-blue)" }}>{alert.mitreId}</div>
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>Tactic</div>
            </div>
            <div>
              <div style={{ fontSize: 15, fontWeight: 600, color: "var(--text-primary)", marginBottom: 6 }}>{alert.mitreTactic}</div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6 }}>{alert.mitreDescription}</div>
            </div>
          </div>
        </div>
      )}

      {/* SHAP Explanations */}
      <div className="card" style={{ padding: 20, marginBottom: 20 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 16, display: "flex", alignItems: "center", gap: 6 }}>
          <FiActivity size={12} />
          SHAP Feature Attribution — Why this was classified as {alert.prediction}
        </div>

        {shapValues.length === 0 ? (
          <div style={{ color: "var(--text-muted)", fontSize: 13, textAlign: "center", padding: 24 }}>
            SHAP explanation not available for this alert
          </div>
        ) : (
          <>
            {/* SHAP Bar Chart */}
            <div style={{ marginBottom: 20 }}>
              {shapValues.slice(0, 12).map((sv) => {
                const pct = maxShap > 0 ? (Math.abs(sv.shapValue) / maxShap) * 100 : 0;
                const isPos = sv.direction === "positive";
                return (
                  <div key={sv.id} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                    <div style={{ width: 24, textAlign: "right", fontSize: 10, color: "var(--text-muted)", flexShrink: 0 }}>
                      #{sv.rank}
                    </div>
                    <div style={{ width: 160, fontSize: 11, color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {sv.featureName}
                    </div>
                    <div style={{ flex: 1, position: "relative", height: 20, display: "flex", alignItems: "center" }}>
                      <div
                        style={{
                          height: 10,
                          width: `${pct}%`,
                          background: isPos
                            ? "linear-gradient(90deg, rgba(239,68,68,0.3), rgba(239,68,68,0.7))"
                            : "linear-gradient(90deg, rgba(16,185,129,0.7), rgba(16,185,129,0.3))",
                          borderRadius: 2,
                          transition: "width 0.4s ease",
                        }}
                      />
                    </div>
                    <div style={{ width: 80, textAlign: "right", fontSize: 11, fontWeight: 600, color: isPos ? "var(--severity-critical)" : "var(--accent-green)" }} className="mono">
                      {isPos ? "+" : ""}{sv.shapValue.toFixed(4)}
                    </div>
                    <div style={{ width: 80, textAlign: "right", fontSize: 11, color: "var(--text-muted)" }} className="mono">
                      {sv.featureValue?.toFixed(2) ?? "N/A"}
                    </div>
                  </div>
                );
              })}
              <div style={{ display: "flex", gap: 16, marginTop: 12, fontSize: 11, color: "var(--text-muted)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <div style={{ width: 20, height: 8, background: "rgba(239,68,68,0.6)", borderRadius: 2 }} />
                  <span>Positive (increases {alert.prediction} probability)</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <div style={{ width: 20, height: 8, background: "rgba(16,185,129,0.6)", borderRadius: 2 }} />
                  <span>Negative (decreases {alert.prediction} probability)</span>
                </div>
              </div>
            </div>
          </>
        )}
      </div>

      {/* Individual Model Results */}
      {detections.length > 0 && (
        <div className="card" style={{ padding: 20, marginBottom: 20 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 14, display: "flex", alignItems: "center", gap: 6 }}>
            <FiCpu size={12} />
            Individual Model Results
          </div>
          <div style={{ display: "flex", gap: 16 }}>
            {detections.map((det) => (
              <div
                key={det.id}
                style={{
                  flex: 1,
                  background: "var(--bg-secondary)",
                  borderRadius: 8,
                  padding: 16,
                  border: "1px solid var(--border-subtle)",
                }}
              >
                <div style={{ fontSize: 12, fontWeight: 600, color: "var(--accent-blue)", marginBottom: 8 }}>{det.model}</div>
                <div style={{ fontSize: 14, fontWeight: 700, color: "var(--text-primary)", marginBottom: 6 }}>{det.prediction}</div>
                <div style={{ fontSize: 13, color: "var(--text-secondary)" }}>
                  Confidence: <strong>{(det.confidence * 100).toFixed(2)}%</strong>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Analyst Guidance */}
      <div className="card" style={{ padding: 20, background: "rgba(234,179,8,0.04)", borderColor: "rgba(234,179,8,0.2)" }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 12, display: "flex", alignItems: "center", gap: 6 }}>
          <FiInfo size={12} />
          Analyst Guidance
        </div>
        <div style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.7 }}>
          {alert.prediction === "DoS" && (
            <>
              <strong style={{ color: "var(--text-primary)" }}>Denial of Service detected.</strong> Investigate the source IP{" "}
              <code style={{ background: "var(--bg-secondary)", padding: "1px 6px", borderRadius: 3, fontSize: 12 }}>{alert.sourceIp}</code> for
              abnormally high connection rates. Consider rate-limiting or blocking at the network perimeter.
              The Isolation Forest flagged this flow as structurally anomalous, providing additional confirmation.
              Cross-reference with firewall logs and upstream router traffic counters.
            </>
          )}
          {alert.prediction === "Probe" && (
            <>
              <strong style={{ color: "var(--text-primary)" }}>Network reconnaissance detected.</strong> Source{" "}
              <code style={{ background: "var(--bg-secondary)", padding: "1px 6px", borderRadius: 3, fontSize: 12 }}>{alert.sourceIp}</code> is
              scanning network services. Review which ports were probed and consider whether any discovered services
              are exposed unnecessarily. This activity may precede exploitation attempts.
            </>
          )}
          {alert.prediction === "R2L" && (
            <>
              <strong style={{ color: "var(--text-primary)" }}>Remote-to-local intrusion attempt detected.</strong> Multiple failed login
              indicators suggest credential-based attack from{" "}
              <code style={{ background: "var(--bg-secondary)", padding: "1px 6px", borderRadius: 3, fontSize: 12 }}>{alert.sourceIp}</code>.
              Review authentication logs for the target service. Consider implementing account lockout policies
              and monitoring for successful logins from this source.
            </>
          )}
          {alert.prediction === "U2R" && (
            <>
              <strong style={{ color: "var(--text-primary)" }}>Privilege escalation indicators detected.</strong> Root shell access
              indicators and elevated access patterns suggest attempted privilege escalation.
              Immediately investigate active sessions on the target host{" "}
              <code style={{ background: "var(--bg-secondary)", padding: "1px 6px", borderRadius: 3, fontSize: 12 }}>{alert.destinationIp}</code>.
              Check system logs for unauthorized sudo/su attempts and newly created files.
            </>
          )}
          {alert.prediction === "Normal" && (
            <>
              <strong style={{ color: "var(--text-primary)" }}>Traffic classified as normal.</strong> This flow was identified as benign
              network activity. {alert.anomalyDetected ? "However, the Isolation Forest flagged this as structurally unusual — consider reviewing if this represents expected baseline behaviour." : "No anomalous behaviour was detected."}
            </>
          )}
        </div>
        <div style={{ marginTop: 12, padding: "8px 12px", background: "rgba(234,179,8,0.08)", borderRadius: 6, fontSize: 11, color: "var(--text-muted)", lineHeight: 1.6 }}>
          <strong style={{ color: "var(--severity-medium)" }}>Disclaimer:</strong> This is a decision-support system.
          All detections should be validated by a qualified security analyst.
          This system is not a substitute for SOC processes, EDR, SIEM, or incident response procedures.
        </div>
      </div>
    </div>
  );
}
