import { NextResponse } from "next/server";
import { getModelMetadata, upsertModelMetadata } from "@/lib/aegis/repository";
import { getAllMitreMappings } from "@/lib/aegis/mitre";
import { FEATURE_NAMES, FEATURE_DESCRIPTIONS } from "@/lib/aegis/features";
import { ATTACK_LABELS, CONFIDENCE_THRESHOLD } from "@/lib/aegis/ml-engine";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    await upsertModelMetadata();
    const models = await getModelMetadata();

    return NextResponse.json({
      models,
      mitreMappings: getAllMitreMappings(),
      featureSchema: {
        version: "41-v1",
        count: FEATURE_NAMES.length,
        features: FEATURE_NAMES.map((name, idx) => ({
          index: idx,
          name,
          description: FEATURE_DESCRIPTIONS[name as string] || name,
        })),
      },
      attackLabels: ATTACK_LABELS,
      configuration: {
        confidenceThreshold: CONFIDENCE_THRESHOLD,
        ensembleStrategy: "soft_voting",
        isolationContamination: 0.05,
      },
    });
  } catch (err) {
    return NextResponse.json(
      { error: "Failed to retrieve model info", details: String(err) },
      { status: 500 }
    );
  }
}
