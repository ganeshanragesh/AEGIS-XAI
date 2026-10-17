import { NextRequest, NextResponse } from "next/server";
import { generateReport } from "@/lib/aegis/repository";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const period = searchParams.get("period") || "day";
    const startDateStr = searchParams.get("startDate");
    const endDateStr = searchParams.get("endDate");

    let startDate: Date;
    let endDate: Date;

    if (startDateStr && endDateStr) {
      startDate = new Date(startDateStr);
      endDate = new Date(endDateStr);
    } else {
      endDate = new Date();
      if (period === "week") {
        startDate = new Date(endDate.getTime() - 7 * 24 * 60 * 60 * 1000);
      } else if (period === "month") {
        startDate = new Date(endDate.getTime() - 30 * 24 * 60 * 60 * 1000);
      } else {
        startDate = new Date(endDate.getTime() - 24 * 60 * 60 * 1000);
      }
    }

    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      return NextResponse.json({ error: "Invalid date range" }, { status: 400 });
    }

    if (endDate < startDate) {
      return NextResponse.json(
        { error: "End date must be after start date" },
        { status: 400 }
      );
    }

    const report = await generateReport(startDate, endDate);

    return NextResponse.json(report);
  } catch (err) {
    return NextResponse.json(
      { error: "Failed to generate report", details: String(err) },
      { status: 500 }
    );
  }
}
