import { NextResponse } from "next/server";
import { getMonitorState } from "@/lib/aegis/monitor-state";

export const dynamic = "force-dynamic";

export async function GET() {
  const state = getMonitorState();
  return NextResponse.json(state);
}
