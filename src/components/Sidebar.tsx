"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  FiActivity,
  FiShield,
  FiAlertTriangle,
  FiBarChart2,
  FiSettings,
  FiCpu,
  FiZap,
} from "react-icons/fi";

const NAV_ITEMS = [
  { href: "/dashboard/monitor", label: "Live Monitor", icon: FiActivity },
  { href: "/dashboard/threats", label: "Threat Analysis", icon: FiBarChart2 },
  { href: "/dashboard/alerts", label: "Alerts", icon: FiAlertTriangle },
  { href: "/dashboard/reports", label: "Reports", icon: FiShield },
  { href: "/dashboard/settings", label: "Settings", icon: FiSettings },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside
      style={{
        width: 220,
        minHeight: "100vh",
        background: "var(--bg-secondary)",
        borderRight: "1px solid var(--border-subtle)",
        display: "flex",
        flexDirection: "column",
        flexShrink: 0,
      }}
    >
      {/* Logo */}
      <div
        style={{
          padding: "20px 16px",
          borderBottom: "1px solid var(--border-subtle)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div
            style={{
              width: 36,
              height: 36,
              background: "linear-gradient(135deg, #3b82f6, #06b6d4)",
              borderRadius: 8,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <FiZap size={20} color="#fff" />
          </div>
          <div>
            <div
              style={{
                fontSize: 15,
                fontWeight: 700,
                color: "var(--text-primary)",
                letterSpacing: "0.02em",
              }}
            >
              AEGIS-XAI
            </div>
            <div
              style={{
                fontSize: 10,
                color: "var(--text-muted)",
                letterSpacing: "0.05em",
                textTransform: "uppercase",
              }}
            >
              IDS Platform v1.0
            </div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, padding: "12px 8px" }}>
        {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
          const active = pathname.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                padding: "10px 12px",
                borderRadius: 6,
                marginBottom: 2,
                color: active ? "var(--accent-blue)" : "var(--text-secondary)",
                background: active ? "rgba(59, 130, 246, 0.1)" : "transparent",
                border: active ? "1px solid rgba(59, 130, 246, 0.2)" : "1px solid transparent",
                textDecoration: "none",
                fontSize: 13,
                fontWeight: active ? 600 : 400,
                transition: "all 0.15s",
              }}
            >
              <Icon size={16} />
              {label}
            </Link>
          );
        })}
      </nav>

      
{/* Footer */}
<div
  style={{
    padding: "12px 16px",
    borderTop: "1px solid var(--border-subtle)",
    fontSize: 10,
    color: "var(--text-muted)",
    lineHeight: 1.6,
  }}
>
  <div
    style={{
      fontWeight: 700,
      fontSize: 12,
      color: "var(--text-primary)",
      marginBottom: 4,
    }}
  >
    AEGIS-XAI
  </div>

  <div style={{ marginBottom: 4 }}>
    Developed by Ganeshan Ragesh
  </div>

  <div>Network Technology &amp; CyberSecurity</div>

  <div style={{ marginTop: 4, color: "var(--border-color)" }}>
    Local / Offline / Air-Gapped
  </div>
</div>
</aside>

  );
}
