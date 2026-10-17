import { NextResponse } from "next/server";
import { db } from "@/db";
import { sql } from "drizzle-orm";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    await db.execute(sql`SELECT 1`);
    return NextResponse.json({
      status: "healthy",
      service: "AEGIS-XAI",
      version: "1.0.0",
      description: "AI-Enhanced Guard for Intelligent Security with Explainable AI",
      timestamp: new Date().toISOString(),
      database: "connected",
    });
  } catch {
    return NextResponse.json(
      {
        status: "degraded",
        service: "AEGIS-XAI",
        version: "1.0.0",
        timestamp: new Date().toISOString(),
        database: "disconnected",
      },
      { status: 503 }
    );
  }
}
