import { createTSharkCapture } from "./tshark-capture";
import {
  FlowAggregator,
} from "./flow-aggregator";
import {
  createNetworkFlow,
  formatNetworkFlowSummary,
} from "./network-flow-adapter";

const aggregator =
  new FlowAggregator(
    (flow) => {
      console.log(
        formatNetworkFlowSummary(
          createNetworkFlow(flow)
        )
      );

      console.log(
        "[AEGIS FLOW DETAILS]",
        {
          sourceIp: flow.sourceIp,
          sourcePort: flow.sourcePort,
          destinationIp: flow.destinationIp,
          destinationPort: flow.destinationPort,
          protocol: flow.protocol,
          duration: flow.duration,
          srcPackets: flow.srcPackets,
          dstPackets: flow.dstPackets,
          srcBytes: flow.srcBytes,
          dstBytes: flow.dstBytes,
          tcpSynCount: flow.tcpSynCount,
          tcpSynAckCount: flow.tcpSynAckCount,
          tcpFinCount: flow.tcpFinCount,
          tcpRstCount: flow.tcpRstCount,
          tcpEstablished: flow.tcpEstablished,
        }
      );
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
      const accepted =
        aggregator.processPacket(
          packet
        );

      if (!accepted) {
        return;
      }

      aggregator.flushExpired(
        packet.timestamp * 1000
      );
    },
    (error) => {
      console.error(
        "[AEGIS FLOW TEST ERROR]",
        error.message
      );
    },
    () => {
      aggregator.flushAll();

      console.log(
        "[AEGIS FLOW TEST] Capture stopped"
      );

      console.log(
        "[AEGIS FLOW TEST] Stats",
        aggregator.getStats()
      );
    }
  );

console.log(
  "[AEGIS FLOW TEST] Starting..."
);

capture.start();

const expiryTimer =
  setInterval(() => {
    aggregator.flushExpired();
  }, 1000);

process.on(
  "SIGINT",
  () => {
    clearInterval(
      expiryTimer
    );

    capture.stop();
  }
);