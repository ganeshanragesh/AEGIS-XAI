/**
 * AEGIS-XAI Benign Baseline Evaluator
 *
 * Captures REAL benign HTTP traffic generated from the Kali
 * test machine and evaluates the current AEGIS-XAI detector.
 *
 * This program:
 *   - captures REAL packets with TShark/Npcap
 *   - aggregates REAL packets into flows
 *   - calculates REAL rolling traffic context
 *   - converts flows into NetworkFlow objects
 *   - runs the existing AEGIS detection pipeline
 *   - reports prediction/confidence/anomaly/severity statistics
 *
 * This program does NOT:
 *   - generate synthetic network packets
 *   - write results to PostgreSQL
 *   - modify the live monitor
 *   - modify the ML engine
 *
 * Current baseline target:
 *
 *   Kali 192.168.2.128
 *          ↓
 *   HTTP/TCP
 *          ↓
 *   AEGIS 192.168.2.1:3000
 *
 * Capture filter:
 *
 *   host 192.168.2.128 and tcp port 3000
 */

import {
  createTSharkCapture,
} from "./tshark-capture";

import {
  FlowAggregator,
} from "./flow-aggregator";

import {
  createNetworkFlow,
} from "./network-flow-adapter";

import {
  RollingTrafficContext,
} from "./rolling-context";

import {
  runDetectionPipeline,
} from "../aegis/detection-pipeline";

/* -------------------------------------------------------------------------- */
/* Types                                                                      */
/* -------------------------------------------------------------------------- */

interface BaselineResult {
  eventId: string;

  sourceIp: string;
  destinationIp: string;

  sourcePort: number;
  destinationPort: number;

  protocol: string;

  prediction: string;
  confidence: number;

  severity:
    | "CRITICAL"
    | "HIGH"
    | "MEDIUM"
    | "NORMAL";

  anomalyDetected: boolean;
  anomalyScore: number;

  lowConfidence: boolean;
}

/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

const KALI_IP =
  "192.168.2.128";

const AEGIS_IP =
  "192.168.2.1";

const AEGIS_PORT =
  3000;

const CAPTURE_INTERFACE_ID =
  7;

const RECENT_WINDOW_MS =
  2000;

const MAX_HISTORY_SIZE =
  1000;

const HOST_WINDOW_SIZE =
  100;

const FLOW_IDLE_TIMEOUT_MS =
  3000;

const FLOW_MAX_AGE_MS =
  30000;

/* -------------------------------------------------------------------------- */
/* Runtime state                                                              */
/* -------------------------------------------------------------------------- */

const results:
  BaselineResult[] = [];

const predictionCounts =
  new Map<string, number>();

const severityCounts =
  new Map<
    "CRITICAL" |
    "HIGH" |
    "MEDIUM" |
    "NORMAL",
    number
  >();

let anomalyCount =
  0;

let totalConfidence =
  0;

let stopping =
  false;

/* -------------------------------------------------------------------------- */
/* Context and aggregation                                                    */
/* -------------------------------------------------------------------------- */

const context =
  new RollingTrafficContext({
    recentWindowMs:
      RECENT_WINDOW_MS,

    maxHistorySize:
      MAX_HISTORY_SIZE,

    hostWindowSize:
      HOST_WINDOW_SIZE,
  });

const aggregator =
  new FlowAggregator(
    (aggregatedFlow) => {
      try {
        /*
         * Convert the completed REAL flow into the
         * AEGIS NetworkFlow representation.
         */
        const networkFlow =
          createNetworkFlow(
            aggregatedFlow
          );

        /*
         * Calculate rolling statistics from other
         * REAL flows observed by this capture session.
         */
        const statistics =
          context.recordFlow(
            aggregatedFlow
          );

        /*
         * Apply rolling context.
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

        /*
         * Run the actual AEGIS detection pipeline.
         */
        const detection =
          runDetectionPipeline(
            networkFlow
          );

        const baselineResult:
          BaselineResult = {
            eventId:
              detection.eventId,

            sourceIp:
              detection.sourceIp,

            destinationIp:
              detection.destinationIp,

            sourcePort:
              detection.sourcePort,

            destinationPort:
              detection.destinationPort,

            protocol:
              detection.protocol,

            prediction:
              detection.prediction,

            confidence:
              detection.confidence,

            severity:
              detection.severity,

            anomalyDetected:
              detection.anomalyDetected,

            anomalyScore:
              detection.anomalyScore,

            lowConfidence:
              detection.lowConfidence,
          };

        results.push(
          baselineResult
        );

        /*
         * Prediction histogram.
         */
        predictionCounts.set(
          detection.prediction,
          (
            predictionCounts.get(
              detection.prediction
            ) ?? 0
          ) + 1
        );

        /*
         * Severity histogram.
         */
        severityCounts.set(
          detection.severity,
          (
            severityCounts.get(
              detection.severity
            ) ?? 0
          ) + 1
        );

        /*
         * Anomaly statistics.
         */
        if (
          detection.anomalyDetected
        ) {
          anomalyCount += 1;
        }

        totalConfidence +=
          detection.confidence;

        /*
         * Print each observed detection.
         */
        console.log(
          [
            "[BASELINE]",
            detection.eventId,
            `${detection.sourceIp}:${detection.sourcePort}`,
            "→",
            `${detection.destinationIp}:${detection.destinationPort}`,
            `protocol=${detection.protocol.toUpperCase()}`,
            `prediction=${detection.prediction}`,
            `confidence=${(
              detection.confidence * 100
            ).toFixed(1)}%`,
            `severity=${detection.severity}`,
            `anomaly=${
              detection.anomalyDetected
                ? "YES"
                : "NO"
            }`,
            `lowConfidence=${
              detection.lowConfidence
                ? "YES"
                : "NO"
            }`,
          ].join(" | ")
        );
      } catch (error) {
        console.error(
          "[BASELINE PROCESSING ERROR]",
          error instanceof Error
            ? error.message
            : String(error)
        );
      }
    },

    {
      idleTimeoutMs:
        FLOW_IDLE_TIMEOUT_MS,

      maxFlowAgeMs:
        FLOW_MAX_AGE_MS,
    }
  );

/* -------------------------------------------------------------------------- */
/* TShark capture                                                              */
/* -------------------------------------------------------------------------- */

const capture =
  createTSharkCapture(
    {
      /*
       * VMware VMnet1.
       *
       * Your TShark enumeration showed interface 7 as:
       *
       *   VMware Network Adapter VMnet1
       */
      interfaceId:
        CAPTURE_INTERFACE_ID,

      /*
       * ONLY capture the intended benign HTTP
       * test traffic between Kali and AEGIS.
       *
       * This excludes DNS, DHCP and unrelated
       * background traffic.
       */
      captureFilter:
        `host ${KALI_IP} and host ${AEGIS_IP} and tcp port ${AEGIS_PORT}`,
    },

    /*
     * Packet callback.
     */
    (packet) => {
      if (
        stopping
      ) {
        return;
      }

      aggregator.processPacket(
        packet
      );

      /*
       * Use packet timestamps so expiration follows
       * the actual observed traffic timeline.
       */
      aggregator.flushExpired(
        packet.timestamp *
          1000
      );
    },

    /*
     * Capture error callback.
     */
    (error) => {
      console.error(
        "[BASELINE CAPTURE ERROR]",
        error.message
      );
    },

    /*
     * Capture stopped callback.
     */
    () => {
      if (
        stopping
      ) {
        return;
      }

      stopping = true;

      /*
       * Emit any still-active flows.
       */
      aggregator.flushAll();

      printBaselineReport();

      console.log(
        "[BASELINE] Capture stopped."
      );
    }
  );

/* -------------------------------------------------------------------------- */
/* Baseline report                                                            */
/* -------------------------------------------------------------------------- */

function printBaselineReport(): void {
  const total =
    results.length;

  const averageConfidence =
    total > 0
      ? totalConfidence /
        total
      : 0;

  const criticalCount =
    severityCounts.get(
      "CRITICAL"
    ) ?? 0;

  const highCount =
    severityCounts.get(
      "HIGH"
    ) ?? 0;

  const mediumCount =
    severityCounts.get(
      "MEDIUM"
    ) ?? 0;

  const normalCount =
    severityCounts.get(
      "NORMAL"
    ) ?? 0;

  const alertCount =
    criticalCount +
    highCount +
    mediumCount;

  const alertRate =
    total > 0
      ? alertCount /
        total
      : 0;

  const anomalyRate =
    total > 0
      ? anomalyCount /
        total
      : 0;

  console.log("");

  console.log(
    "============================================================"
  );

  console.log(
    "                 AEGIS-XAI BASELINE"
  );

  console.log(
    "============================================================"
  );

  console.log(
    `Capture source        : Kali ${KALI_IP}`
  );

  console.log(
    `Capture destination   : AEGIS ${AEGIS_IP}:${AEGIS_PORT}`
  );

  console.log(
    `Capture interface     : VMnet1 (TShark ID ${CAPTURE_INTERFACE_ID})`
  );

  console.log(
    "Traffic profile       : Benign HTTP"
  );

  console.log(
    `Total completed flows : ${total}`
  );

  console.log(
    `Average confidence    : ${(
      averageConfidence *
      100
    ).toFixed(2)}%`
  );

  console.log(
    `Anomalies detected    : ${anomalyCount}`
  );

  console.log(
    `Anomaly rate          : ${(
      anomalyRate *
      100
    ).toFixed(2)}%`
  );

  console.log(
    `Alert decisions       : ${alertCount}`
  );

  console.log(
    `Alert rate            : ${(
      alertRate *
      100
    ).toFixed(2)}%`
  );

  console.log("");

  console.log(
    "Severity distribution:"
  );

  console.log(
    `  CRITICAL : ${criticalCount}`
  );

  console.log(
    `  HIGH     : ${highCount}`
  );

  console.log(
    `  MEDIUM   : ${mediumCount}`
  );

  console.log(
    `  NORMAL   : ${normalCount}`
  );

  console.log("");

  console.log(
    "Prediction distribution:"
  );

  const sortedPredictions =
    [...predictionCounts.entries()]
      .sort(
        ([, a], [, b]) =>
          b - a
      );

  for (
    const [
      prediction,
      count,
    ] of sortedPredictions
  ) {
    console.log(
      `  ${prediction.padEnd(
        10
      )} : ${count}`
    );
  }

  console.log("");

  console.log(
    "Flow aggregator:"
  );

  console.log(
    aggregator.getStats()
  );

  console.log("");

  console.log(
    `Rolling context size : ${context.size()}`
  );

  console.log(
    "============================================================"
  );

  console.log("");
}

/* -------------------------------------------------------------------------- */
/* Startup                                                                    */
/* -------------------------------------------------------------------------- */

console.log(
  "[BASELINE] Starting REAL benign HTTP baseline capture..."
);

console.log(
  `[BASELINE] Kali source: ${KALI_IP}`
);

console.log(
  `[BASELINE] AEGIS target: ${AEGIS_IP}:${AEGIS_PORT}`
);

console.log(
  `[BASELINE] TShark interface: ${CAPTURE_INTERFACE_ID} (VMware VMnet1)`
);

console.log(
  "[BASELINE] Capture filter: Kali ↔ AEGIS TCP/3000 only"
);

console.log(
  "[BASELINE] Press Ctrl+C after the benign test traffic is complete."
);

capture.start();

/* -------------------------------------------------------------------------- */
/* Periodic flow expiration                                                   */
/* -------------------------------------------------------------------------- */

const expiryTimer =
  setInterval(
    () => {
      if (
        stopping
      ) {
        return;
      }

      aggregator.flushExpired();
    },
    1000
  );

/* -------------------------------------------------------------------------- */
/* Graceful shutdown                                                          */
/* -------------------------------------------------------------------------- */

process.on(
  "SIGINT",
  () => {
    if (
      stopping
    ) {
      return;
    }

    stopping = true;

    clearInterval(
      expiryTimer
    );

    capture.stop();

    /*
     * The capture stop callback performs the final flush
     * and prints the report.
     */
  }
);

process.on(
  "SIGTERM",
  () => {
    if (
      stopping
    ) {
      return;
    }

    stopping = true;

    clearInterval(
      expiryTimer
    );

    capture.stop();
  }
);