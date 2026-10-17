"use client";

import { useState, useEffect, useCallback } from "react";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  CartesianGrid,
  Legend,
} from "recharts";
import {
  FiBarChart2,
  FiTrendingUp,
  FiAlertTriangle,
  FiTarget,
  FiRefreshCw,
} from "react-icons/fi";

const ATTACK_COLORS: Record<string, string> = {
  Normal: "#10b981",
  DoS: "#ef4444",
  Probe: "#f97316",
  R2L: "#eab308",
  U2R: "#8b5cf6",
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  NORMAL: "#10b981",
};

interface Metrics {
  alertMetrics: {
    totals: {
      total: number;
      critical: number;
      high: number;
      medium: number;
      normal: number;
    };
    attackDistribution: { prediction: string; count: number }[];
    recentActivity: { hour: string; count: number }[];
    topSourceIps: { sourceIp: string; count: number }[];
    topDestIps: { destinationIp: string; count: number }[];
    protocolDistribution: { protocol: string; count: number }[];
  };
  performanceMetrics: {
    avgInferenceMs: number;
    avgShapMs: number;
    p95InferenceMs: number;
    p99InferenceMs: number;
    maxInferenceMs: number;
    avgConfidence: number;
  };
}

export default function ThreatAnalysisPage() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchMetrics = useCallback(async (showRefresh = false) => {
  if (showRefresh) setRefreshing(true);

  try {
    const res = await fetch("/api/metrics", {
      cache: "no-store",
    });

    if (res.ok) {
      const data = await res.json();
      setMetrics(data);
    }
  } finally {
    setLoading(false);

    if (showRefresh) {
      setRefreshing(false);
    }
  }
}, []);

  useEffect(() => {
  const initialTimer = window.setTimeout(() => {
    void fetchMetrics();
  }, 0);

  const interval = window.setInterval(() => {
    void fetchMetrics();
  }, 10000);

  return () => {
    window.clearTimeout(initialTimer);
    window.clearInterval(interval);
  };
}, [fetchMetrics]);

  if (loading) {
    return (
      <div style={{ padding: 24 }}>
        <div style={{ color: "var(--text-muted)", fontSize: 14 }}>Loading threat analysis data...</div>
      </div>
    );
  }

  const totals = metrics?.alertMetrics?.totals;
  const attackDist = metrics?.alertMetrics?.attackDistribution ?? [];
  const recentActivity = metrics?.alertMetrics?.recentActivity ?? [];
  const topSources = metrics?.alertMetrics?.topSourceIps ?? [];
  const protocolDist = metrics?.alertMetrics?.protocolDistribution ?? [];
  const perfMetrics = metrics?.performanceMetrics;

  const severityData = [
    { name: "CRITICAL", value: Number(totals?.critical ?? 0), color: "#ef4444" },
    { name: "HIGH", value: Number(totals?.high ?? 0), color: "#f97316" },
    { name: "MEDIUM", value: Number(totals?.medium ?? 0), color: "#eab308" },
    { name: "NORMAL", value: Number(totals?.normal ?? 0), color: "#10b981" },
  ].filter((d) => d.value > 0);

  const attackChartData = attackDist.map((d) => ({
    name: d.prediction,
    count: Number(d.count),
    color: ATTACK_COLORS[d.prediction] || "#6366f1",
  }));

  const activityData = recentActivity.map((d) => ({
    time: new Date(d.hour).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    alerts: Number(d.count),
  }));

  const totalAlerts = Number(totals?.total ?? 0);

  return (
    <div style={{ padding: 24 }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: "var(--text-primary)", margin: 0 }}>
            Threat Analysis
          </h1>
          <p style={{ fontSize: 13, color: "var(--text-muted)", margin: "4px 0 0" }}>
            Statistical analysis of detected threats and attack patterns
          </p>
        </div>
        <button
          onClick={() => fetchMetrics(true)}
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
          <FiRefreshCw size={13} style={{ animation: refreshing ? "spin 1s linear infinite" : "none" }} />
          Refresh
        </button>
      </div>

      {/* Overview stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 16, marginBottom: 24 }}>
        {[
          { label: "Total Events", value: totalAlerts, color: "var(--accent-blue)" },
          { label: "Critical", value: Number(totals?.critical ?? 0), color: "var(--severity-critical)" },
          { label: "High", value: Number(totals?.high ?? 0), color: "var(--severity-high)" },
          { label: "Medium", value: Number(totals?.medium ?? 0), color: "var(--severity-medium)" },
          { label: "Normal", value: Number(totals?.normal ?? 0), color: "var(--severity-normal)" },
        ].map(({ label, value, color }) => (
          <div key={label} className="card" style={{ padding: 16 }}>
            <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 8 }}>
              {label}
            </div>
            <div style={{ fontSize: 26, fontWeight: 700, color }}>{value.toLocaleString()}</div>
          </div>
        ))}
      </div>

      {totalAlerts === 0 ? (
        <div className="card" style={{ padding: 64, textAlign: "center" }}>
          <FiBarChart2 size={40} color="var(--text-muted)" style={{ marginBottom: 16 }} />
          <div style={{ color: "var(--text-muted)", fontSize: 15 }}>No detection data available</div>
          <div style={{ color: "var(--text-muted)", fontSize: 13, marginTop: 8 }}>
            Start monitoring to collect threat intelligence data
          </div>
        </div>
      ) : (
        <>
          {/* Charts row 1 */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 20 }}>
            {/* Attack Distribution Pie */}
            <div className="card" style={{ padding: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginBottom: 16, display: "flex", alignItems: "center", gap: 8 }}>
                <FiTarget size={14} color="var(--accent-blue)" />
                Attack Category Distribution
              </div>
              {severityData.length > 0 ? (
                <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
                  <ResponsiveContainer width={180} height={180}>
                    <PieChart>
                      <Pie
                        data={severityData}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={80}
                        dataKey="value"
                        strokeWidth={0}
                      >
                        {severityData.map((entry) => (
                          <Cell key={entry.name} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)", borderRadius: 6, fontSize: 12 }}
                        labelStyle={{ color: "var(--text-primary)" }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div style={{ flex: 1 }}>
                    {severityData.map((d) => (
                      <div key={d.name} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                        <div style={{ width: 10, height: 10, borderRadius: 2, background: d.color, flexShrink: 0 }} />
                        <span style={{ fontSize: 12, color: "var(--text-secondary)", flex: 1 }}>{d.name}</span>
                        <span style={{ fontSize: 12, color: "var(--text-primary)", fontWeight: 600 }}>{d.value}</span>
                        <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                          {totalAlerts > 0 ? ((d.value / totalAlerts) * 100).toFixed(1) : 0}%
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div style={{ color: "var(--text-muted)", fontSize: 13, textAlign: "center", padding: 40 }}>No data</div>
              )}
            </div>

            {/* Attack Family Bar Chart */}
            <div className="card" style={{ padding: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginBottom: 16, display: "flex", alignItems: "center", gap: 8 }}>
                <FiAlertTriangle size={14} color="var(--accent-blue)" />
                Attack Family Breakdown
              </div>
              {attackChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={attackChartData} margin={{ top: 0, right: 10, left: -20, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" vertical={false} />
                    <XAxis dataKey="name" tick={{ fontSize: 11, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fontSize: 11, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} />
                    <Tooltip
                      contentStyle={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)", borderRadius: 6, fontSize: 12 }}
                    />
                    <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                      {attackChartData.map((entry) => (
                        <Cell key={entry.name} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div style={{ color: "var(--text-muted)", fontSize: 13, textAlign: "center", padding: 40 }}>No data</div>
              )}
            </div>
          </div>

          {/* Activity Timeline */}
          {activityData.length > 0 && (
            <div className="card" style={{ padding: 20, marginBottom: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginBottom: 16, display: "flex", alignItems: "center", gap: 8 }}>
                <FiTrendingUp size={14} color="var(--accent-blue)" />
                Alert Timeline (Last 24 Hours)
              </div>
              <ResponsiveContainer width="100%" height={160}>
                <LineChart data={activityData} margin={{ top: 0, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" vertical={false} />
                  <XAxis dataKey="time" tick={{ fontSize: 10, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 10, fill: "var(--text-muted)" }} axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)", borderRadius: 6, fontSize: 12 }}
                  />
                  <Line type="monotone" dataKey="alerts" stroke="var(--accent-blue)" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Tables row */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 20 }}>
            {/* Top Source IPs */}
            <div className="card" style={{ padding: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginBottom: 14 }}>
                Top Source IPs (Threats)
              </div>
              {topSources.length === 0 ? (
                <div style={{ color: "var(--text-muted)", fontSize: 12, textAlign: "center", padding: 20 }}>No data</div>
              ) : (
                topSources.slice(0, 8).map((s, i) => (
                  <div key={s.sourceIp} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                    <span style={{ fontSize: 10, color: "var(--text-muted)", width: 16, textAlign: "right" }}>{i + 1}</span>
                    <span style={{ flex: 1, fontSize: 12, color: "var(--text-secondary)" }} className="mono">{s.sourceIp}</span>
                    <span style={{ fontSize: 12, fontWeight: 600, color: "var(--accent-blue)" }}>{s.count}</span>
                  </div>
                ))
              )}
            </div>

            {/* Protocol Distribution */}
            <div className="card" style={{ padding: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginBottom: 14 }}>
                Protocol Distribution
              </div>
              {protocolDist.length === 0 ? (
                <div style={{ color: "var(--text-muted)", fontSize: 12, textAlign: "center", padding: 20 }}>No data</div>
              ) : (
                protocolDist.map((p) => {
                  const pct = totalAlerts > 0 ? (Number(p.count) / totalAlerts) * 100 : 0;
                  return (
                    <div key={p.protocol} style={{ marginBottom: 12 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                        <span style={{ fontSize: 12, color: "var(--text-secondary)", textTransform: "uppercase" }}>{p.protocol}</span>
                        <span style={{ fontSize: 12, color: "var(--text-primary)", fontWeight: 600 }}>{p.count}</span>
                      </div>
                      <div style={{ background: "var(--bg-secondary)", borderRadius: 2, height: 4 }}>
                        <div
                          style={{
                            width: `${pct}%`,
                            height: "100%",
                            background: "var(--accent-cyan)",
                            borderRadius: 2,
                            transition: "width 0.4s ease",
                          }}
                        />
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {/* Performance Metrics */}
            <div className="card" style={{ padding: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginBottom: 14 }}>
                ML Performance
              </div>
              {perfMetrics ? (
                [
                  { label: "Avg Inference", value: `${(perfMetrics.avgInferenceMs ?? 0).toFixed(2)} ms`, target: "<40ms", ok: (perfMetrics.avgInferenceMs ?? 0) < 40 },
                  { label: "SHAP Avg", value: `${(perfMetrics.avgShapMs ?? 0).toFixed(2)} ms`, target: "<40ms", ok: (perfMetrics.avgShapMs ?? 0) < 40 },
                  { label: "P95 Inference", value: `${(perfMetrics.p95InferenceMs ?? 0).toFixed(2)} ms`, target: "", ok: true },
                  { label: "P99 Inference", value: `${(perfMetrics.p99InferenceMs ?? 0).toFixed(2)} ms`, target: "", ok: true },
                  { label: "Avg Confidence", value: `${((perfMetrics.avgConfidence ?? 0) * 100).toFixed(1)}%`, target: ">60%", ok: (perfMetrics.avgConfidence ?? 0) > 0.6 },
                ].map(({ label, value, target, ok }) => (
                  <div key={label} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                    <span style={{ fontSize: 12, color: "var(--text-muted)" }}>{label}</span>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <span style={{ fontSize: 12, fontWeight: 600, color: ok ? "var(--accent-green)" : "var(--severity-high)" }}>{value}</span>
                      {target && <span style={{ fontSize: 10, color: "var(--text-muted)" }}>{target}</span>}
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ color: "var(--text-muted)", fontSize: 12, textAlign: "center", padding: 20 }}>No data</div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
