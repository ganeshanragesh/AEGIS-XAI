import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { runDetectionPipeline } from "@/lib/aegis/detection-pipeline";
import { saveDetectionResult } from "@/lib/aegis/repository";
import { portToService } from "@/lib/aegis/features";
import { type NetworkFlow } from "@/lib/aegis/features";

export const dynamic = "force-dynamic";

const FlowSchema = z.object({
  sourceIp: z
    .string()
    .regex(/^(\d{1,3}\.){3}\d{1,3}$/, "Invalid IPv4 address")
    .or(z.string().regex(/^[0-9a-fA-F:]+$/, "Invalid IPv6 address")),
  destinationIp: z
    .string()
    .regex(/^(\d{1,3}\.){3}\d{1,3}$/, "Invalid IPv4 address")
    .or(z.string().regex(/^[0-9a-fA-F:]+$/, "Invalid IPv6 address")),
  sourcePort: z.number().int().min(0).max(65535),
  destinationPort: z.number().int().min(0).max(65535),
  protocol: z.enum(["tcp", "udp", "icmp"]).default("tcp"),
  duration: z.number().min(0).max(60000).default(0),
  srcBytes: z.number().int().min(0).default(0),
  dstBytes: z.number().int().min(0).default(0),
  srcPackets: z.number().int().min(0).default(1),
  dstPackets: z.number().int().min(0).default(1),
  service: z.string().max(64).optional(),
  flag: z.enum(["SF", "S0", "REJ", "RSTO", "RSTR", "SH", "S1", "S2", "S3", "OTH"]).default("SF"),
  land: z.boolean().default(false),
  wrongFragment: z.number().int().min(0).default(0),
  urgent: z.number().int().min(0).default(0),
  hot: z.number().int().min(0).default(0),
  numFailedLogins: z.number().int().min(0).default(0),
  loggedIn: z.boolean().default(false),
  numCompromised: z.number().int().min(0).default(0),
  rootShell: z.boolean().default(false),
  suAttempted: z.boolean().default(false),
  numRoot: z.number().int().min(0).default(0),
  numFileCreations: z.number().int().min(0).default(0),
  numShells: z.number().int().min(0).default(0),
  numAccessFiles: z.number().int().min(0).default(0),
  numOutboundCmds: z.number().int().min(0).default(0),
  isHostLogin: z.boolean().default(false),
  isGuestLogin: z.boolean().default(false),
  count: z.number().int().min(0).max(511).default(1),
  srvCount: z.number().int().min(0).max(511).default(1),
  serrorRate: z.number().min(0).max(1).default(0),
  srvSerrorRate: z.number().min(0).max(1).default(0),
  rerrorRate: z.number().min(0).max(1).default(0),
  srvRerrorRate: z.number().min(0).max(1).default(0),
  sameSrvRate: z.number().min(0).max(1).default(1),
  diffSrvRate: z.number().min(0).max(1).default(0),
  srvDiffHostRate: z.number().min(0).max(1).default(0),
  dstHostCount: z.number().int().min(0).max(255).default(1),
  dstHostSrvCount: z.number().int().min(0).max(255).default(1),
  dstHostSameSrvRate: z.number().min(0).max(1).default(1),
  dstHostDiffSrvRate: z.number().min(0).max(1).default(0),
  dstHostSameSrcPortRate: z.number().min(0).max(1).default(0),
  dstHostSrvDiffHostRate: z.number().min(0).max(1).default(0),
  dstHostSerrorRate: z.number().min(0).max(1).default(0),
  dstHostSrvSerrorRate: z.number().min(0).max(1).default(0),
  dstHostRerrorRate: z.number().min(0).max(1).default(0),
  dstHostSrvRerrorRate: z.number().min(0).max(1).default(0),
});

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const parsed = FlowSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        { error: "Invalid flow data", details: parsed.error.flatten() },
        { status: 400 }
      );
    }

    const data = parsed.data;

    const flow: NetworkFlow = {
      ...data,
      service: data.service || portToService(data.destinationPort, data.protocol),
    };

    const result = runDetectionPipeline(flow);
    const alertId = await saveDetectionResult(result, "api");

    return NextResponse.json({
      success: true,
      alertId,
      eventId: result.eventId,
      prediction: result.prediction,
      confidence: result.confidence,
      severity: result.severity,
      anomalyDetected: result.anomalyDetected,
      anomalyScore: result.anomalyScore,
      mitre: result.mitre,
      explanation: result.explanation,
      topFeatures: result.shapFeatures.slice(0, 10).map((f) => ({
        name: f.featureName,
        value: f.featureValue,
        shapValue: f.shapValue,
        direction: f.direction,
        rank: f.rank,
      })),
      performance: {
        inferenceTimeMs: result.inferenceTimeMs,
        shapTimeMs: result.shapTimeMs,
        totalMs: result.inferenceTimeMs + result.shapTimeMs,
      },
    });
  } catch (err) {
    return NextResponse.json(
      { error: "Analysis failed", details: String(err) },
      { status: 500 }
    );
  }
}
