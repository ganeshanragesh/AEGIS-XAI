import { NextResponse } from "next/server";

import {
  getMonitorState,
  stopMonitoring,
} from "@/lib/aegis/monitor-state";

export const dynamic = "force-dynamic";

export async function POST() {
  try {
    /*
     * IMPORTANT:
     *
     * stopMonitoring() is asynchronous because it must wait for
     * the current monitor session to be persisted to PostgreSQL.
     *
     * Do NOT call it without await.
     */
    await stopMonitoring();

    /*
     * Read the state only AFTER the shutdown has completed.
     *
     * This guarantees the returned summary represents the final
     * in-memory monitor state rather than an intermediate state.
     */
    const state =
      getMonitorState();

    return NextResponse.json({
      success: true,

      message:
        "Monitoring stopped",

      summary: {
        packetsCapured:
          state.packetsCapured,

        flowsProcessed:
          state.flowsProcessed,

        alertsGenerated:
          state.alertsGenerated,
      },
    });
  } catch (error) {
    console.error(
      "[AEGIS MONITOR STOP ERROR]",
      error
    );

    return NextResponse.json(
      {
        success: false,

        error:
          "Failed to stop monitoring",

        details:
          error instanceof Error
            ? error.message
            : String(error),
      },
      {
        status: 500,
      }
    );
  }
}