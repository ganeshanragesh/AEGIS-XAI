import { NextResponse } from "next/server";
import { getAlertMetrics, getPerformanceMetrics, getModelMetadata } from "@/lib/aegis/repository";
import { getPipelineMetrics } from "@/lib/aegis/detection-pipeline";
import { getMonitorState } from "@/lib/aegis/monitor-state";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const [alertMetrics, performanceMetrics, models, pipelineMetrics, monitorState] =
      await Promise.all([
        getAlertMetrics(),
        getPerformanceMetrics(),
        getModelMetadata(),
        getPipelineMetrics(),
        getMonitorState(),
      ]);

    return NextResponse.json({
      alertMetrics,
      performanceMetrics,
      models,
      pipelineMetrics,
      monitorState,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    return NextResponse.json(
      { error: "Failed to retrieve metrics", details: String(err) },
      { status: 500 }
    );
  }
}
