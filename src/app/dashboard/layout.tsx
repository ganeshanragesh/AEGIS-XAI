import type { ReactNode } from "react";
import Sidebar from "@/components/Sidebar";

export default function DashboardLayout({ children }: { children: ReactNode }) {
  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ flex: 1, overflow: "auto", background: "var(--bg-primary)" }}>
        {children}
      </main>
    </div>
  );
}
