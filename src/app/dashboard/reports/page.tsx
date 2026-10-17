"use client";

import { useCallback, useEffect, useState } from "react";
import {
  FiShield,
  FiDownload,
  FiCalendar,
  FiBarChart2,
  FiAlertTriangle,
  FiRefreshCw,
} from "react-icons/fi";

interface ReportData {
  period: {
    startDate: string;
    endDate: string;
  };
  totals: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    normal: number;
  };
  attackBreakdown: {
    prediction: string;
    count: number;
  }[];
  topSources: {
    sourceIp: string;
    count: number;
  }[];
  topDestinations: {
    destinationIp: string;
    count: number;
  }[];
  recentAlerts: {
    eventId: string;
    timestamp: string;
    sourceIp: string;
    prediction: string;
    severity: string;
    confidence: number;
  }[];
}

const ATTACK_COLORS: Record<string, string> = {
  Normal: "var(--accent-green)",
  DoS: "var(--severity-critical)",
  Probe: "var(--accent-orange)",
  R2L: "var(--accent-yellow)",
  U2R: "var(--accent-purple)",
};

const REPORT_PERIODS = [
  { value: "day", label: "Last 24 Hours" },
  { value: "week", label: "Last 7 Days" },
  { value: "month", label: "Last 30 Days" },
] as const;

function escapeCsvValue(value: string): string {
  return `"${value.replace(/"/g, '""')}"`;
}

export default function ReportsPage() {
  const [report, setReport] = useState<ReportData | null>(null);
  const [period, setPeriod] = useState("day");
  const [loading, setLoading] = useState(false);

  const fetchReport = useCallback(async () => {
    setLoading(true);

    try {
      const response = await fetch(`/api/reports?period=${encodeURIComponent(period)}`, {
        cache: "no-store",
      });

      if (!response.ok) {
        throw new Error(`Failed to load report: HTTP ${response.status}`);
      }

      const data = (await response.json()) as ReportData;
      setReport(data);
    } catch {
      setReport(null);
    } finally {
      setLoading(false);
    }
  }, [period]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void fetchReport();
    }, 0);

    return () => {
      window.clearTimeout(timer);
    };
  }, [fetchReport]);

  const exportJson = useCallback(() => {
    if (!report) {
      return;
    }

    const blob = new Blob(
      [JSON.stringify(report, null, 2)],
      { type: "application/json;charset=utf-8" }
    );

    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");

    anchor.href = url;
    anchor.download = `aegis-xai-report-${period}-${new Date()
      .toISOString()
      .split("T")[0]}.json`;

    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }, [period, report]);

  const exportCsv = useCallback(() => {
    if (!report) {
      return;
    }

    const rows = [
      [
        "Event ID",
        "Timestamp",
        "Source IP",
        "Prediction",
        "Severity",
        "Confidence",
      ],
      ...report.recentAlerts.map((alert) => [
        alert.eventId,
        new Date(alert.timestamp).toLocaleString(),
        alert.sourceIp,
        alert.prediction,
        alert.severity,
        `${(alert.confidence * 100).toFixed(1)}%`,
      ]),
    ];

    const csv = rows
      .map((row) => row.map((value) => escapeCsvValue(String(value))).join(","))
      .join("\n");

    const blob = new Blob(
      [csv],
      { type: "text/csv;charset=utf-8" }
    );

    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");

    anchor.href = url;
    anchor.download = `aegis-xai-alerts-${period}-${new Date()
      .toISOString()
      .split("T")[0]}.csv`;

    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }, [period, report]);

  const totals = report?.totals;
  const total = Number(totals?.total ?? 0);

  return (
    <div style={{ padding: 24 }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: 24,
          gap: 16,
          flexWrap: "wrap",
        }}
      >
        <div>
          <h1
            style={{
              fontSize: 22,
              fontWeight: 700,
              color: "var(--text-primary)",
              margin: 0,
            }}
          >
            Reports
          </h1>

          <p
            style={{
              fontSize: 13,
              color: "var(--text-muted)",
              margin: "4px 0 0",
            }}
          >
            Security analysis reports generated from detection data
          </p>
        </div>

        <div style={{ display: "flex", gap: 10 }}>
          <button
            onClick={exportJson}
            disabled={!report || total === 0}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              padding: "7px 14px",
              background: "var(--bg-card)",
              border: "1px solid var(--border-subtle)",
              borderRadius: 6,
              color: "var(--text-secondary)",
              fontSize: 12,
              cursor: !report || total === 0 ? "not-allowed" : "pointer",
              opacity: !report || total === 0 ? 0.4 : 1,
            }}
          >
            <FiDownload size={12} />
            Export JSON
          </button>

          <button
            onClick={exportCsv}
            disabled={!report || total === 0}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              padding: "7px 14px",
              background: "var(--bg-card)",
              border: "1px solid var(--border-subtle)",
              borderRadius: 6,
              color: "var(--text-secondary)",
              fontSize: 12,
              cursor: !report || total === 0 ? "not-allowed" : "pointer",
              opacity: !report || total === 0 ? 0.4 : 1,
            }}
          >
            <FiDownload size={12} />
            Export CSV
          </button>
        </div>
      </div>

      <div
        className="card"
        style={{
          padding: 16,
          marginBottom: 20,
          display: "flex",
          gap: 12,
          alignItems: "center",
          flexWrap: "wrap",
        }}
      >
        <FiCalendar size={14} color="var(--text-muted)" />

        <span
          style={{
            fontSize: 13,
            color: "var(--text-muted)",
          }}
        >
          Report period:
        </span>

        {REPORT_PERIODS.map(({ value, label }) => (
          <button
            key={value}
            onClick={() => setPeriod(value)}
            style={{
              padding: "6px 14px",
              borderRadius: 6,
              border: "1px solid",
              fontSize: 12,
              cursor: "pointer",
              background:
                period === value
                  ? "rgba(59,130,246,0.15)"
                  : "var(--bg-secondary)",
              borderColor:
                period === value
                  ? "rgba(59,130,246,0.4)"
                  : "var(--border-subtle)",
              color:
                period === value
                  ? "var(--accent-blue)"
                  : "var(--text-secondary)",
              fontWeight: period === value ? 600 : 400,
            }}
          >
            {label}
          </button>
        ))}

        <button
          onClick={() => {
            void fetchReport();
          }}
          disabled={loading}
          style={{
            marginLeft: "auto",
            display: "flex",
            alignItems: "center",
            gap: 6,
            padding: "6px 12px",
            background: "none",
            border: "1px solid var(--border-subtle)",
            borderRadius: 6,
            color: "var(--text-secondary)",
            fontSize: 12,
            cursor: loading ? "wait" : "pointer",
            opacity: loading ? 0.6 : 1,
          }}
        >
          <FiRefreshCw size={12} />
          Refresh
        </button>
      </div>

      {loading ? (
        <div
          style={{
            color: "var(--text-muted)",
            fontSize: 13,
            padding: 24,
          }}
        >
          Generating report...
        </div>
      ) : !report ? (
        <div
          className="card"
          style={{
            padding: 48,
            textAlign: "center",
          }}
        >
          <FiAlertTriangle
            size={32}
            color="var(--severity-high)"
            style={{ marginBottom: 12 }}
          />

          <div
            style={{
              color: "var(--text-primary)",
              fontSize: 14,
              fontWeight: 600,
            }}
          >
            Failed to load report
          </div>

          <div
            style={{
              color: "var(--text-muted)",
              fontSize: 12,
              marginTop: 8,
            }}
          >
            Check the API and database connection, then try refreshing.
          </div>

          <button
            onClick={() => {
              void fetchReport();
            }}
            style={{
              marginTop: 16,
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
              padding: "7px 14px",
              background: "var(--accent-blue)",
              color: "#fff",
              border: "none",
              borderRadius: 6,
              fontSize: 12,
              cursor: "pointer",
            }}
          >
            <FiRefreshCw size={12} />
            Retry
          </button>
        </div>
      ) : (
        <>
          <div
            style={{
              background:
                "linear-gradient(135deg, rgba(59,130,246,0.1), rgba(6,182,212,0.05))",
              border: "1px solid rgba(59,130,246,0.2)",
              borderRadius: 8,
              padding: 20,
              marginBottom: 20,
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                marginBottom: 8,
              }}
            >
              <FiShield size={20} color="var(--accent-blue)" />

              <div>
                <div
                  style={{
                    fontSize: 16,
                    fontWeight: 700,
                    color: "var(--text-primary)",
                  }}
                >
                  AEGIS-XAI Security Report
                </div>

                <div
                  style={{
                    fontSize: 12,
                    color: "var(--text-muted)",
                  }}
                >
                  {new Date(report.period.startDate).toLocaleString()}{" "}
                  —{" "}
                  {new Date(report.period.endDate).toLocaleString()}
                </div>
              </div>
            </div>

            <div
              style={{
                fontSize: 12,
                color: "var(--text-secondary)",
                lineHeight: 1.6,
              }}
            >
              Generated by AEGIS-XAI v1.0.0 · Hybrid AI Intrusion Detection
              System · Models: Random Forest + XGBoost + Isolation Forest
              · Explainability: SHAP TreeExplainer
            </div>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(5, 1fr)",
              gap: 16,
              marginBottom: 20,
            }}
          >
            {[
              {
                label: "Total Events",
                value: total,
                color: "var(--accent-blue)",
              },
              {
                label: "Critical",
                value: Number(totals?.critical ?? 0),
                color: "var(--severity-critical)",
              },
              {
                label: "High",
                value: Number(totals?.high ?? 0),
                color: "var(--severity-high)",
              },
              {
                label: "Medium",
                value: Number(totals?.medium ?? 0),
                color: "var(--severity-medium)",
              },
              {
                label: "Normal",
                value: Number(totals?.normal ?? 0),
                color: "var(--severity-normal)",
              },
            ].map(({ label, value, color }) => (
              <div
                key={label}
                className="card"
                style={{ padding: 16 }}
              >
                <div
                  style={{
                    fontSize: 10,
                    color: "var(--text-muted)",
                    textTransform: "uppercase",
                    letterSpacing: "0.06em",
                    marginBottom: 8,
                  }}
                >
                  {label}
                </div>

                <div
                  style={{
                    fontSize: 24,
                    fontWeight: 700,
                    color,
                  }}
                >
                  {value.toLocaleString()}
                </div>
              </div>
            ))}
          </div>

          {total === 0 ? (
            <div
              className="card"
              style={{
                padding: 48,
                textAlign: "center",
              }}
            >
              <FiBarChart2
                size={32}
                color="var(--text-muted)"
                style={{ marginBottom: 12 }}
              />

              <div
                style={{
                  color: "var(--text-muted)",
                  fontSize: 14,
                }}
              >
                No events in the selected period
              </div>

              <div
                style={{
                  color: "var(--text-muted)",
                  fontSize: 12,
                  marginTop: 8,
                }}
              >
                Start monitoring to collect security data for report
                generation.
              </div>
            </div>
          ) : (
            <>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr 1fr",
                  gap: 20,
                  marginBottom: 20,
                }}
              >
                <div className="card" style={{ padding: 20 }}>
                  <div
                    style={{
                      fontSize: 13,
                      fontWeight: 600,
                      color: "var(--text-primary)",
                      marginBottom: 14,
                    }}
                  >
                    Attack Categories
                  </div>

                  {report.attackBreakdown.map((item) => {
                    const percentage =
                      total > 0 ? (Number(item.count) / total) * 100 : 0;

                    return (
                      <div
                        key={item.prediction}
                        style={{ marginBottom: 10 }}
                      >
                        <div
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            marginBottom: 4,
                          }}
                        >
                          <span
                            style={{
                              fontSize: 12,
                              color:
                                ATTACK_COLORS[item.prediction] ??
                                "var(--text-secondary)",
                              fontWeight: 500,
                            }}
                          >
                            {item.prediction}
                          </span>

                          <span
                            style={{
                              fontSize: 12,
                              color: "var(--text-primary)",
                              fontWeight: 600,
                            }}
                          >
                            {item.count}
                          </span>
                        </div>

                        <div
                          style={{
                            background: "var(--bg-secondary)",
                            borderRadius: 2,
                            height: 4,
                          }}
                        >
                          <div
                            style={{
                              width: `${percentage}%`,
                              height: "100%",
                              background:
                                ATTACK_COLORS[item.prediction] ??
                                "var(--accent-blue)",
                              borderRadius: 2,
                            }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>

                <div className="card" style={{ padding: 20 }}>
                  <div
                    style={{
                      fontSize: 13,
                      fontWeight: 600,
                      color: "var(--text-primary)",
                      marginBottom: 14,
                    }}
                  >
                    Top Threat Sources
                  </div>

                  {report.topSources.length === 0 ? (
                    <div
                      style={{
                        color: "var(--text-muted)",
                        fontSize: 12,
                        textAlign: "center",
                        padding: 20,
                      }}
                    >
                      No threat sources
                    </div>
                  ) : (
                    report.topSources.slice(0, 8).map((source, index) => (
                      <div
                        key={source.sourceIp}
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 8,
                          marginBottom: 8,
                        }}
                      >
                        <span
                          style={{
                            fontSize: 10,
                            color: "var(--text-muted)",
                            width: 16,
                            textAlign: "right",
                          }}
                        >
                          {index + 1}
                        </span>

                        <span
                          className="mono"
                          style={{
                            flex: 1,
                            fontSize: 11,
                            color: "var(--text-secondary)",
                          }}
                        >
                          {source.sourceIp}
                        </span>

                        <span
                          style={{
                            fontSize: 12,
                            fontWeight: 600,
                            color: "var(--severity-high)",
                          }}
                        >
                          {source.count}
                        </span>
                      </div>
                    ))
                  )}
                </div>

                <div className="card" style={{ padding: 20 }}>
                  <div
                    style={{
                      fontSize: 13,
                      fontWeight: 600,
                      color: "var(--text-primary)",
                      marginBottom: 14,
                    }}
                  >
                    Top Target Destinations
                  </div>

                  {report.topDestinations.length === 0 ? (
                    <div
                      style={{
                        color: "var(--text-muted)",
                        fontSize: 12,
                        textAlign: "center",
                        padding: 20,
                      }}
                    >
                      No destination data
                    </div>
                  ) : (
                    report.topDestinations
                      .slice(0, 8)
                      .map((destination, index) => (
                        <div
                          key={destination.destinationIp}
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: 8,
                            marginBottom: 8,
                          }}
                        >
                          <span
                            style={{
                              fontSize: 10,
                              color: "var(--text-muted)",
                              width: 16,
                              textAlign: "right",
                            }}
                          >
                            {index + 1}
                          </span>

                          <span
                            className="mono"
                            style={{
                              flex: 1,
                              fontSize: 11,
                              color: "var(--text-secondary)",
                            }}
                          >
                            {destination.destinationIp}
                          </span>

                          <span
                            style={{
                              fontSize: 12,
                              fontWeight: 600,
                              color: "var(--accent-blue)",
                            }}
                          >
                            {destination.count}
                          </span>
                        </div>
                      ))
                  )}
                </div>
              </div>

              {report.recentAlerts.length > 0 && (
                <div
                  className="card"
                  style={{ padding: 20 }}
                >
                  <div
                    style={{
                      fontSize: 13,
                      fontWeight: 600,
                      color: "var(--text-primary)",
                      marginBottom: 14,
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                    }}
                  >
                    <FiAlertTriangle
                      size={13}
                      color="var(--severity-high)"
                    />
                    Critical & High Severity Events
                  </div>

                  <div style={{ overflowX: "auto" }}>
                    <table
                      style={{
                        width: "100%",
                        borderCollapse: "collapse",
                      }}
                    >
                      <thead>
                        <tr
                          style={{
                            borderBottom:
                              "1px solid var(--border-subtle)",
                          }}
                        >
                          {[
                            "Event ID",
                            "Timestamp",
                            "Source IP",
                            "Attack",
                            "Severity",
                            "Confidence",
                          ].map((heading) => (
                            <th
                              key={heading}
                              style={{
                                padding: "8px 12px",
                                textAlign: "left",
                                fontSize: 11,
                                color: "var(--text-muted)",
                                textTransform: "uppercase",
                                letterSpacing: "0.05em",
                                fontWeight: 500,
                              }}
                            >
                              {heading}
                            </th>
                          ))}
                        </tr>
                      </thead>

                      <tbody>
                        {report.recentAlerts.map((alert) => (
                          <tr
                            key={alert.eventId}
                            style={{
                              borderBottom:
                                "1px solid var(--border-subtle)",
                            }}
                          >
                            <td
                              className="mono"
                              style={{
                                padding: "8px 12px",
                                fontSize: 11,
                                color: "var(--text-muted)",
                              }}
                            >
                              {alert.eventId
                                .split("-")
                                .slice(1)
                                .join("-")}
                            </td>

                            <td
                              className="mono"
                              style={{
                                padding: "8px 12px",
                                fontSize: 11,
                                color: "var(--text-muted)",
                              }}
                            >
                              {new Date(
                                alert.timestamp
                              ).toLocaleString()}
                            </td>

                            <td
                              className="mono"
                              style={{
                                padding: "8px 12px",
                                fontSize: 11,
                              }}
                            >
                              {alert.sourceIp}
                            </td>

                            <td
                              style={{
                                padding: "8px 12px",
                                fontSize: 12,
                                fontWeight: 600,
                                color:
                                  ATTACK_COLORS[alert.prediction] ??
                                  "var(--text-primary)",
                              }}
                            >
                              {alert.prediction}
                            </td>

                            <td style={{ padding: "8px 12px" }}>
                              <span
                                className={`severity-${alert.severity.toLowerCase()}`}
                                style={{
                                  fontSize: 10,
                                  fontWeight: 700,
                                  padding: "2px 7px",
                                  borderRadius: 3,
                                }}
                              >
                                {alert.severity}
                              </span>
                            </td>

                            <td
                              className="mono"
                              style={{
                                padding: "8px 12px",
                                fontSize: 11,
                              }}
                            >
                              {(alert.confidence * 100).toFixed(1)}%
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}