import { NextRequest, NextResponse } from "next/server";
import { getAlerts, getTotalAlertCount } from "@/lib/aegis/repository";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);

    const severity = searchParams.get("severity") || undefined;
    const prediction = searchParams.get("prediction") || undefined;
    const sourceIp = searchParams.get("sourceIp") || undefined;
    const destinationIp = searchParams.get("destinationIp") || undefined;
    const status = searchParams.get("status") || undefined;
    const limit = Math.min(parseInt(searchParams.get("limit") || "50"), 200);
    const offset = Math.max(parseInt(searchParams.get("offset") || "0"), 0);

    const startDateStr = searchParams.get("startDate");
    const endDateStr = searchParams.get("endDate");
    const startDate = startDateStr ? new Date(startDateStr) : undefined;
    const endDate = endDateStr ? new Date(endDateStr) : undefined;

    const filters = { severity, prediction, sourceIp, destinationIp, status, startDate, endDate, limit, offset };

    const [data, total] = await Promise.all([
      getAlerts(filters),
      getTotalAlertCount(filters),
    ]);

    return NextResponse.json({
      data,
      pagination: {
        total,
        limit,
        offset,
        hasMore: offset + limit < total,
      },
    });
  } catch (err) {
    return NextResponse.json(
      { error: "Failed to retrieve alerts", details: String(err) },
      { status: 500 }
    );
  }
}
