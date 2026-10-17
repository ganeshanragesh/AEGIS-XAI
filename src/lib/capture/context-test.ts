import { createTSharkCapture } from "./tshark-capture";
import { FlowAggregator } from "./flow-aggregator";
import {
  createNetworkFlow,
  formatNetworkFlowSummary,
} from "./network-flow-adapter";
import { RollingTrafficContext } from "./rolling-context";

const context = new RollingTrafficContext({
  recentWindowMs: 2000,
  maxHistorySize: 1000,
  hostWindowSize: 100,
});

const aggregator = new FlowAggregator(
  (aggregatedFlow) => {
    try {
      const networkFlow =
        createNetworkFlow(
          aggregatedFlow
        );

      const statistics =
        context.recordFlow(
          aggregatedFlow
        );

      /*
       * Replace the single-flow contextual fields
       * with statistics calculated from REAL observed flows.
       */
      networkFlow.count =
        statistics.count;

      networkFlow.srvCount =
        statistics.srvCount;

      networkFlow.serrorRate =
        statistics.serrorRate;

      networkFlow.srvSerrorRate =
        statistics.srvSerrorRate;

      networkFlow.rerrorRate =
        statistics.rerrorRate;

      networkFlow.srvRerrorRate =
        statistics.srvRerrorRate;

      networkFlow.sameSrvRate =
        statistics.sameSrvRate;

      networkFlow.diffSrvRate =
        statistics.diffSrvRate;

      networkFlow.srvDiffHostRate =
        statistics.srvDiffHostRate;

      networkFlow.dstHostCount =
        statistics.dstHostCount;

      networkFlow.dstHostSrvCount =
        statistics.dstHostSrvCount;

      networkFlow.dstHostSameSrvRate =
        statistics.dstHostSameSrvRate;

      networkFlow.dstHostDiffSrvRate =
        statistics.dstHostDiffSrvRate;

      networkFlow.dstHostSameSrcPortRate =
        statistics.dstHostSameSrcPortRate;

      networkFlow.dstHostSrvDiffHostRate =
        statistics.dstHostSrvDiffHostRate;

      networkFlow.dstHostSerrorRate =
        statistics.dstHostSerrorRate;

      networkFlow.dstHostSrvSerrorRate =
        statistics.dstHostSrvSerrorRate;

      networkFlow.dstHostRerrorRate =
        statistics.dstHostRerrorRate;

      networkFlow.dstHostSrvRerrorRate =
        statistics.dstHostSrvRerrorRate;

      console.log(
        formatNetworkFlowSummary(
          networkFlow
        )
      );

      console.log(
        "[AEGIS CONTEXT]",
        {
          count:
            networkFlow.count,

          srvCount:
            networkFlow.srvCount,

          sameSrvRate:
            networkFlow.sameSrvRate,

          diffSrvRate:
            networkFlow.diffSrvRate,

          serrorRate:
            networkFlow.serrorRate,

          rerrorRate:
            networkFlow.rerrorRate,

          dstHostCount:
            networkFlow.dstHostCount,

          dstHostSrvCount:
            networkFlow.dstHostSrvCount,

          dstHostSameSrvRate:
            networkFlow.dstHostSameSrvRate,

          dstHostDiffSrvRate:
            networkFlow.dstHostDiffSrvRate,
        }
      );

      console.log(
        "[AEGIS CONTEXT SIZE]",
        context.size()
      );
    } catch (error) {
      console.error(
        "[AEGIS CONTEXT TEST ERROR]",
        error instanceof Error
          ? error.message
          : String(error)
      );
    }
  },
  {
    idleTimeoutMs: 3000,
    maxFlowAgeMs: 30000,
  }
);

const capture =
  createTSharkCapture(
    {
      interfaceId: 7,
      captureFilter:
        "host 192.168.2.128",
    },

    (packet) => {
      aggregator.processPacket(
        packet
      );

      /*
       * Expire flows according to packet time so
       * the test remains deterministic.
       */
      aggregator.flushExpired(
        packet.timestamp * 1000
      );
    },

    (error) => {
      console.error(
        "[AEGIS CAPTURE ERROR]",
        error.message
      );
    },

    () => {
      aggregator.flushAll();

      console.log(
        "[AEGIS CONTEXT TEST] Capture stopped"
      );

      console.log(
        "[AEGIS CONTEXT TEST] Final context size:",
        context.size()
      );

      console.log(
        "[AEGIS CONTEXT TEST] Aggregator stats:",
        aggregator.getStats()
      );
    }
  );

console.log(
  "[AEGIS CONTEXT TEST] Starting real capture..."
);

capture.start();

const timer =
  setInterval(() => {
    aggregator.flushExpired();
  }, 1000);

process.on(
  "SIGINT",
  () => {
    clearInterval(timer);

    capture.stop();
  }
);