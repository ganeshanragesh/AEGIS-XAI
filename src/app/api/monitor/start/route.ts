import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import {
  startMonitoring,
  getMonitorState,
  type MonitorMode,
} from "@/lib/aegis/monitor-state";
import { createMonitorSession, stopAllSessions } from "@/lib/aegis/repository";

export const dynamic = "force-dynamic";

const StartSchema = z.object({
  mode: z.enum(["live", "pcap"]).default("live"),
  networkInterface: z.string().min(1).max(64).optional(),
  pcapFile: z.string().max(512).optional(),
});

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const parsed = StartSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        { error: "Invalid request", details: parsed.error.flatten() },
        { status: 400 }
      );
    }

    const { mode, networkInterface, pcapFile } = parsed.data;

    // Stop any existing sessions
    await stopAllSessions();

    // Create new session
    const session = await createMonitorSession(mode, networkInterface, pcapFile);

    // Start monitoring
    await startMonitoring(
      session.sessionId,
      mode as MonitorMode,
      networkInterface,
      pcapFile
    );

    return NextResponse.json({
      success: true,
      sessionId: session.sessionId,
      mode,
      networkInterface,
      message: `Monitoring started in ${mode} mode`,
    });
  } catch (err) {
  console.error("MONITOR START ERROR:", err);

  return NextResponse.json(
    {
      error: "Failed to start monitoring",
      details: err instanceof Error ? err.message : String(err),
    },
    { status: 500 }
  );
}
}
