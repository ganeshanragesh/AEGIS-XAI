/**
 * AEGIS-XAI Real Traffic Detection Test
 *
 * Purpose:
 *   Validate the complete real-packet detection chain:
 *
 *   Kali
 *      ↓
 *   TShark / Npcap
 *      ↓
 *   CapturedPacket
 *      ↓
 *   FlowAggregator
 *      ↓
 *   RollingTrafficContext
 *      ↓
 *   NetworkFlow
 *      ↓
 *   AEGIS Detection Pipeline
 *      ↓
 *   ML + Anomaly + SHAP + MITRE
 *
 * This test:
 *   - captures REAL traffic only
 *   - does NOT generate synthetic traffic
 *   - does NOT write to PostgreSQL
 *   - does NOT start the production monitor
 *   - prints the exact NetworkFlow passed to the detector
 *
 * Current lab:
 *
 *   Kali:  192.168.2.128
 *   AEGIS: 192.168.2.1:3000
 *   TShark interface: 7 (VMware VMnet1)
 */

import {
  createTSharkCapture,
} from "./tshark-capture";

import {
  FlowAggregator,
} from "./flow-aggregator";

import {
  createNetworkFlow,
  formatNetworkFlowSummary,
} from "./network-flow-adapter";

import {
  RollingTrafficContext,
} from "./rolling-context";

import {
  runDetectionPipeline,
} from "../aegis/detection-pipeline";

/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

const KALI_IP =
  "192.168.2.128";

const AEGIS_IP =
  "192.168.2.1";

const AEGIS_PORT =
  3000;

const TSHARK_INTERFACE_ID =
  7;

const FLOW_IDLE_TIMEOUT_MS =
  3000;

const FLOW_MAX_AGE_MS =
  30000;

const CONTEXT_RECENT_WINDOW_MS =
  2000;

const CONTEXT_MAX_HISTORY_SIZE =
  1000;

const CONTEXT_HOST_WINDOW_SIZE =
  100;

/* -------------------------------------------------------------------------- */
/* Rolling context                                                            */
/* -------------------------------------------------------------------------- */

const context =
  new RollingTrafficContext({
    recentWindowMs:
      CONTEXT_RECENT_WINDOW_MS,

    maxHistorySize:
      CONTEXT_MAX_HISTORY_SIZE,

    hostWindowSize:
      CONTEXT_HOST_WINDOW_SIZE,
  });

/* -------------------------------------------------------------------------- */
/* Counters                                                                   */
/* -------------------------------------------------------------------------- */

let completedFlows =
  0;

let detectionCount =
  0;

let processingErrors =
  0;

let stopped =
  false;

/* -------------------------------------------------------------------------- */
/* Helper                                                                      */
/* -------------------------------------------------------------------------- */

/**
 * Apply the rolling-context statistics to a NetworkFlow.
 */
function applyRollingContext(
  networkFlow: ReturnType<
    typeof createNetworkFlow
  >,
  statistics: ReturnType<
    RollingTrafficContext["recordFlow"]
  >
): void {
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
}

/**
 * Print the complete feature-bearing NetworkFlow.
 */
function printNetworkFlow(
  networkFlow: ReturnType<
    typeof createNetworkFlow
  >
): void {
  console.log("");
  console.log(
    "============================================================"
  );

  console.log(
    "[AEGIS NETWORK FLOW]"
  );

  console.log(
    "============================================================"
  );

  console.dir(
    networkFlow,
    {
      depth: null,
      colors: true,
    }
  );

  console.log(
    "============================================================"
  );
}

/**
 * Print the detection result.
 */
function printDetectionResult(
  result: ReturnType<
    typeof runDetectionPipeline
  >
): void {
  console.log("");

  console.log(
    formatNetworkFlowSummary(
      result.flow as Parameters<
        typeof formatNetworkFlowSummary
      >[0]
    )
  );

  console.log(
    formatDetectionSummarySafe(
      result
    )
  );

  console.log(
    "[AEGIS DETECTION]",
    {
      prediction:
        result.prediction,

      predictionIndex:
        result.predictionIndex,

      confidence:
        result.confidence,

      rfConfidence:
        result.rfConfidence,

      xgbConfidence:
        result.xgbConfidence,

      ensembleProbabilities:
        result.ensembleProbs,

      lowConfidence:
        result.lowConfidence,

      anomalyDetected:
        result.anomalyDetected,

      anomalyScore:
        result.anomalyScore,

      anomalyRawScore:
        result.anomalyRawScore,

      severity:
        result.severity,

      supervisedAlert:
        result.supervisedAlert,

      shapFeatures:
        result.shapFeatures.length,

      inferenceTimeMs:
        result.inferenceTimeMs,

      shapTimeMs:
        result.shapTimeMs,

      mitre:
        result.mitre,
    }
  );

  console.log(
    "[AEGIS EXPLANATION]",
    result.explanation
  );

  console.log(
    "[AEGIS TOP SHAP FEATURES]"
  );

  console.table(
    result.shapFeatures
      .slice(0, 10)
      .map(
        (feature) => ({
          rank:
            feature.rank,

          feature:
            feature.featureName,

          value:
            feature.featureValue,

          shap:
            feature.shapValue,

          direction:
            feature.direction,
        })
      )
  );
}

/**
 * Keep the summary call isolated so that the test does not
 * fail merely because of a formatting mismatch.
 */
function formatDetectionSummarySafe(
  result: ReturnType<
    typeof runDetectionPipeline
  >
): string {
  return [
    `[${result.eventId}]`,
    result.timestamp.toISOString(),
    `${result.sourceIp}:${result.sourcePort} → ${result.destinationIp}:${result.destinationPort}`,
    `Protocol: ${result.protocol.toUpperCase()}`,
    `Prediction: ${result.prediction}`,
    `Confidence: ${(result.confidence * 100).toFixed(1)}%`,
    `Severity: ${result.severity}`,
    `Anomaly: ${
      result.anomalyDetected
        ? "YES"
        : "NO"
    }`,
    `MITRE: ${result.mitre.tacticId} - ${result.mitre.tacticName}`,
  ].join(" | ");
}

/* -------------------------------------------------------------------------- */
/* Flow aggregator                                                            */
/* -------------------------------------------------------------------------- */

const aggregator =
  new FlowAggregator(
    (aggregatedFlow) => {
      if (stopped) {
        return;
      }

      completedFlows += 1;

      try {
        /*
         * Convert the REAL aggregated flow into the
         * AEGIS NetworkFlow contract.
         */
        const networkFlow =
          createNetworkFlow(
            aggregatedFlow
          );

        /*
         * Add contextual statistics derived from
         * previously captured REAL flows.
         */
        const statistics =
          context.recordFlow(
            aggregatedFlow
          );

        applyRollingContext(
          networkFlow,
          statistics
        );

        /*
         * Print the exact object entering the detector.
         *
         * This is the critical debugging output:
         * it allows us to see which feature values cause
         * the model to classify the traffic as suspicious.
         */
        printNetworkFlow(
          networkFlow
        );

        /*
         * Run the real AEGIS detection engine.
         */
        const result =
          runDetectionPipeline(
            networkFlow
          );

        detectionCount += 1;

        printDetectionResult(
          result
        );
      } catch (error) {
        processingErrors += 1;

        console.error(
          "[AEGIS DETECTION TEST ERROR]",
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
/* TShark capture                                                             */
/* -------------------------------------------------------------------------- */

const capture =
  createTSharkCapture(
    {
      interfaceId:
        TSHARK_INTERFACE_ID,

      /*
       * IMPORTANT:
       *
       * Restrict the test to the exact connection we
       * intentionally generate from Kali.
       *
       * This excludes:
       *   - DNS
       *   - DHCP
       *   - NTP
       *   - unrelated traffic
       *   - other services
       */
      captureFilter:
        `host ${KALI_IP} and host ${AEGIS_IP} and tcp port ${AEGIS_PORT}`,
    },

    /*
     * Packet callback.
     */
    (packet) => {
      if (stopped) {
        return;
      }

      aggregator.processPacket(
        packet
      );

      /*
       * Expire flows against the captured packet's
       * own timestamp for deterministic behavior.
       */
      aggregator.flushExpired(
        packet.timestamp * 1000
      );
    },

    /*
     * Capture error callback.
     */
    (error) => {
      console.error(
        "[AEGIS CAPTURE ERROR]",
        error.message
      );
    },

    /*
     * Capture stopped callback.
     */
    () => {
      if (stopped) {
        return;
      }

      stopped = true;

      /*
       * Emit all remaining active flows.
       */
      aggregator.flushAll();

      printFinalStatistics();
    }
  );

/* -------------------------------------------------------------------------- */
/* Final statistics                                                           */
/* -------------------------------------------------------------------------- */

function printFinalStatistics(): void {
  console.log("");
  console.log(
    "============================================================"
  );

  console.log(
    "[AEGIS DETECTION TEST SUMMARY]"
  );

  console.log(
    "============================================================"
  );

  console.log(
    `Completed flows : ${completedFlows}`
  );

  console.log(
    `Detections      : ${detectionCount}`
  );

  console.log(
    `Processing errors: ${processingErrors}`
  );

  console.log(
    `Context size    : ${context.size()}`
  );

  console.log(
    "Aggregator stats:"
  );

  console.dir(
    aggregator.getStats(),
    {
      depth: null,
      colors: true,
    }
  );

  console.log(
    "============================================================"
  );
}

/* -------------------------------------------------------------------------- */
/* Start                                                                      */
/* -------------------------------------------------------------------------- */

console.log(
  "[AEGIS DETECTION TEST] Starting REAL packet capture..."
);

console.log(
  `[AEGIS DETECTION TEST] Kali: ${KALI_IP}`
);

console.log(
  `[AEGIS DETECTION TEST] AEGIS: ${AEGIS_IP}:${AEGIS_PORT}`
);

console.log(
  `[AEGIS DETECTION TEST] TShark interface: ${TSHARK_INTERFACE_ID} (VMware VMnet1)`
);

console.log(
  `[AEGIS DETECTION TEST] Filter: host ${KALI_IP} and host ${AEGIS_IP} and tcp port ${AEGIS_PORT}`
);

console.log(
  "[AEGIS DETECTION TEST] Waiting for real traffic..."
);

console.log(
  "[AEGIS DETECTION TEST] Press Ctrl+C to stop."
);

capture.start();

/* -------------------------------------------------------------------------- */
/* Periodic expiry                                                            */
/* -------------------------------------------------------------------------- */

const expiryTimer =
  setInterval(
    () => {
      if (stopped) {
        return;
      }

      aggregator.flushExpired();
    },
    1000
  );

/* -------------------------------------------------------------------------- */
/* Graceful shutdown                                                          */
/* -------------------------------------------------------------------------- */

function shutdown(): void {
  if (stopped) {
    return;
  }

  clearInterval(
    expiryTimer
  );

  /*
   * capture.stop() invokes the capture stopped
   * callback, which performs the final flush/report.
   */
  capture.stop();
}

process.once(
  "SIGINT",
  shutdown
);

process.once(
  "SIGTERM",
  shutdown
);