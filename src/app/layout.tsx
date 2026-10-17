import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "AEGIS-XAI | AI-Enhanced Intrusion Detection",
  description:
    "AI-Enhanced Guard for Intelligent Security with Explainable AI — Local Hybrid AI-Based Network Intrusion Detection Platform",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
