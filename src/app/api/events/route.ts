/**
 * AEGIS-XAI Server-Sent Events (SSE) endpoint.
 * Streams real detection events to connected clients.
 */
import { subscribeToEvents } from "@/lib/aegis/monitor-state";

export const dynamic = "force-dynamic";

export async function GET() {
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    start(controller) {
      // Send initial connection event
      controller.enqueue(
        encoder.encode(
          `data: ${JSON.stringify({ type: "connected", timestamp: new Date().toISOString() })}\n\n`
        )
      );

      // Subscribe to events from monitor state
      const unsubscribe = subscribeToEvents((message: string) => {
        try {
          controller.enqueue(encoder.encode(`data: ${message}\n\n`));
        } catch {
          unsubscribe();
        }
      });

      // Heartbeat every 15 seconds to keep connection alive
      const heartbeat = setInterval(() => {
        try {
          controller.enqueue(
            encoder.encode(
              `data: ${JSON.stringify({ type: "heartbeat", timestamp: new Date().toISOString() })}\n\n`
            )
          );
        } catch {
          clearInterval(heartbeat);
          unsubscribe();
        }
      }, 15000);

      // Cleanup when client disconnects
      return () => {
        clearInterval(heartbeat);
        unsubscribe();
      };
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
