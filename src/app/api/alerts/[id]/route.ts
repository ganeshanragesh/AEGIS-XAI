import { NextRequest, NextResponse } from "next/server";
import { getAlertById, updateAlertStatus } from "@/lib/aegis/repository";
import { z } from "zod";

export const dynamic = "force-dynamic";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const alertId = parseInt(id);

    if (isNaN(alertId) || alertId < 1) {
      return NextResponse.json({ error: "Invalid alert ID" }, { status: 400 });
    }

    const result = await getAlertById(alertId);

    if (!result) {
      return NextResponse.json({ error: "Alert not found" }, { status: 404 });
    }

    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json(
      { error: "Failed to retrieve alert", details: String(err) },
      { status: 500 }
    );
  }
}

const StatusSchema = z.object({
  status: z.enum(["open", "acknowledged", "resolved", "false_positive"]),
});

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const alertId = parseInt(id);

    if (isNaN(alertId) || alertId < 1) {
      return NextResponse.json({ error: "Invalid alert ID" }, { status: 400 });
    }

    const body = await req.json();
    const parsed = StatusSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        { error: "Invalid status value", details: parsed.error.flatten() },
        { status: 400 }
      );
    }

    await updateAlertStatus(alertId, parsed.data.status);

    return NextResponse.json({ success: true, status: parsed.data.status });
  } catch (err) {
    return NextResponse.json(
      { error: "Failed to update alert", details: String(err) },
      { status: 500 }
    );
  }
}
