import { NextResponse } from "next/server";
import { getMonitorState, AVAILABLE_INTERFACES } from "@/lib/aegis/monitor-state";
import { getModelMetadata, upsertModelMetadata } from "@/lib/aegis/repository";
import { getPipelineMetrics } from "@/lib/aegis/detection-pipeline";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    await upsertModelMetadata();
    const [state, models, pipelineMetrics] = await Promise.all([
      getMonitorState(),
      getModelMetadata(),
      getPipelineMetrics(),
    ]);

    return NextResponse.json({
      monitor: state,
      models,
      pipelineMetrics,
      availableInterfaces: AVAILABLE_INTERFACES,
      systemInfo: {
        platform: process.platform,
        nodeVersion: process.version,
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage(),
      },
    });
  } catch (err) {
    return NextResponse.json(
      { error: "Failed to retrieve system status", details: String(err) },
      { status: 500 }
    );
  }
}
