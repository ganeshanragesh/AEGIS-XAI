/**
 * AEGIS-XAI Real Monitor State Manager
 *
 * Production orchestration layer for the AEGIS-XAI live monitor.
 *
 * REAL pipeline:
 *
 *   Windows Npcap
 *        ↓
 *      TShark
 *        ↓
 *   CapturedPacket
 *        ↓
 *   FlowAggregator
 *        ↓
 *   RollingTrafficContext
 *        ↓
 *    NetworkFlow
 *        ↓
 * Detection Pipeline
 *    ┌────┼─────┐
 *    ↓    ↓     ↓
 *   RF   XGB   Anomaly
 *    └────┼─────┘
 *         ↓
 *       SHAP
 *         ↓
 *       MITRE
 *         ↓
 *   Flow persistence
 *         ↓
 *   Alert persistence
 *         ↓
 *      PostgreSQL
 *         ↓
 *        SSE
 *
 * IMPORTANT:
 *
 * This file contains NO synthetic packet generation.
 * All production monitoring traffic comes from the real TShark/Npcap
 * capture adapter.
 */

import {
  createTSharkCapture,
  type TSharkCapture,
  type CapturedPacket,
} from "../capture/tshark-capture";

import {
  FlowAggregator,
  type AggregatedFlow,
} from "../capture/flow-aggregator";

import {
  createNetworkFlow,
} from "../capture/network-flow-adapter";

import {
  RollingTrafficContext,
} from "../capture/rolling-context";

import {
  runDetectionPipeline,
  type DetectionResult,
} from "./detection-pipeline";

import {
  saveFlow,
  saveDetectionResult,
  updateMonitorSession,
  logSystemEvent,
} from "./repository";

/* -------------------------------------------------------------------------- */
/* Monitor mode                                                               */
/* -------------------------------------------------------------------------- */

export type MonitorMode =
  | "live"
  | "pcap"
  | "stopped";

/* -------------------------------------------------------------------------- */
/* Monitor state                                                              */
/* -------------------------------------------------------------------------- */

export interface MonitorState {
  isRunning: boolean;

  mode: MonitorMode;

  sessionId: string | null;

  networkInterface: string | null;

  pcapFile: string | null;

  startedAt: Date | null;

  /*
   * Existing API/UI compatibility:
   *
   * The project historically exposes the misspelled property
   * "packetsCapured". Keep it unchanged so existing consumers
   * continue to work.
   */
  packetsCapured: number;

  flowsProcessed: number;

  alertsGenerated: number;

  lastActivity: Date | null;

  engineStatus: {
    capture:
      | "online"
      | "offline"
      | "error";

    flow:
      | "online"
      | "offline"
      | "error";

    ml:
      | "online"
      | "offline"
      | "error";

    shap:
      | "online"
      | "offline"
      | "error";

    database:
      | "online"
      | "offline"
      | "error";

    api:
      | "online"
      | "offline"
      | "error";
  };
}

/* -------------------------------------------------------------------------- */
/* Runtime resources                                                          */
/* -------------------------------------------------------------------------- */

interface MonitorRuntime {
  capture:
    TSharkCapture | null;

  aggregator:
    FlowAggregator | null;

  context:
    RollingTrafficContext | null;

  /*
   * Prevent callbacks from an older capture session from modifying
   * a newly-created session.
   */
  generation: number;

  /*
   * Number of packets received from TShark during the current session.
   */
  packetsSeen: number;

  /*
   * Number of completed flow callbacks handled during the current session.
   */
  flowsSeen: number;

  /*
   * Async detection/database jobs currently running.
   */
  pendingJobs:
    Set<Promise<void>>;
}

/* -------------------------------------------------------------------------- */
/* SSE subscribers                                                            */
/* -------------------------------------------------------------------------- */

const subscribers =
  new Set<(data: string) => void>();

export function subscribeToEvents(
  handler: (data: string) => void
): () => void {
  subscribers.add(
    handler
  );

  return () => {
    subscribers.delete(
      handler
    );
  };
}

export function broadcastEvent(
  type: string,
  payload: unknown
): void {
  const message =
    JSON.stringify({
      type,

      payload,

      timestamp:
        new Date().toISOString(),
    });

  for (
    const handler of subscribers
  ) {
    try {
      handler(
        message
      );
    } catch {
      subscribers.delete(
        handler
      );
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Global singleton                                                           */
/* -------------------------------------------------------------------------- */

const globalThis_ =
  globalThis as typeof globalThis & {
    __aegisMonitorState?:
      MonitorState;

    __aegisMonitorRuntime?:
      MonitorRuntime;
  };

/* -------------------------------------------------------------------------- */
/* Initial state                                                              */
/* -------------------------------------------------------------------------- */

function createInitialState():
  MonitorState {
  return {
    isRunning:
      false,

    mode:
      "stopped",

    sessionId:
      null,

    networkInterface:
      null,

    pcapFile:
      null,

    startedAt:
      null,

    packetsCapured:
      0,

    flowsProcessed:
      0,

    alertsGenerated:
      0,

    lastActivity:
      null,

    engineStatus: {
      capture:
        "offline",

      flow:
        "offline",

      /*
       * The model engine is local/in-process and available even
       * before the packet-capture engine starts.
       */
      ml:
        "online",

      shap:
        "online",

      database:
        "online",

      api:
        "online",
    },
  };
}

/* -------------------------------------------------------------------------- */
/* Runtime factory                                                            */
/* -------------------------------------------------------------------------- */

function createRuntime():
  MonitorRuntime {
  return {
    capture:
      null,

    aggregator:
      null,

    context:
      null,

    generation:
      0,

    packetsSeen:
      0,

    flowsSeen:
      0,

    pendingJobs:
      new Set<
        Promise<void>
      >(),
  };
}

/* -------------------------------------------------------------------------- */
/* Global accessors                                                           */
/* -------------------------------------------------------------------------- */

function getState():
  MonitorState {
  if (
    !globalThis_.__aegisMonitorState
  ) {
    globalThis_.__aegisMonitorState =
      createInitialState();
  }

  return globalThis_
    .__aegisMonitorState;
}

function getRuntime():
  MonitorRuntime {
  if (
    !globalThis_.__aegisMonitorRuntime
  ) {
    globalThis_.__aegisMonitorRuntime =
      createRuntime();
  }

  return globalThis_
    .__aegisMonitorRuntime;
}

/* -------------------------------------------------------------------------- */
/* Public state helpers                                                       */
/* -------------------------------------------------------------------------- */

export function getMonitorState():
  MonitorState {
  const state =
    getState();

  return {
    ...state,

    engineStatus: {
      ...state.engineStatus,
    },
  };
}

export function updateMonitorState(
  updates:
    Partial<MonitorState>
): void {
  Object.assign(
    getState(),
    updates
  );
}

/* -------------------------------------------------------------------------- */
/* Capture-interface mapping                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Resolve a UI/API interface name to the numeric TShark interface.
 *
 * Current lab mapping:
 *
 *   5  = Wi-Fi
 *   6  = VMware Network Adapter VMnet8
 *   7  = VMware Network Adapter VMnet1
 *   10 = Ethernet 2
 *   12 = Ethernet
 *
 * eth0 intentionally maps to VMnet1 because the current AEGIS lab
 * uses Kali on VMware VMnet1.
 */
function resolveTSharkInterface(
  networkInterface?:
    string
): number {
  const value =
    (
      networkInterface ??
      "7"
    ).trim();

  if (
    /^\d+$/.test(
      value
    )
  ) {
    const interfaceId =
      Number(
        value
      );

    if (
      Number.isInteger(
        interfaceId
      ) &&
      interfaceId >= 0
    ) {
      return interfaceId;
    }
  }

  const normalized =
    value.toLowerCase();

  switch (
    normalized
  ) {
    case "eth0":
    case "vmnet1":
    case "vmware network adapter vmnet1":
      return 7;

    case "wlan0":
    case "wi-fi":
    case "wifi":
      return 5;

    case "vmnet8":
    case "vmware network adapter vmnet8":
      return 6;

    case "ethernet 2":
      return 10;

    case "ethernet":
      return 12;

    default:
      throw new Error(
        `Unsupported capture interface "${networkInterface}". ` +
        `Use a TShark interface number or one of the configured Windows interfaces.`
      );
  }
}

/* -------------------------------------------------------------------------- */
/* Rolling-context application                                                */
/* -------------------------------------------------------------------------- */

function applyRollingContext(
  networkFlow: ReturnType<
    typeof createNetworkFlow
  >,
  statistics: ReturnType<
    RollingTrafficContext[
      "recordFlow"
    ]
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

/* -------------------------------------------------------------------------- */
/* Runtime persistence helper                                                 */
/* -------------------------------------------------------------------------- */

function trackJob(
  job: Promise<void>
): void {
  const runtime =
    getRuntime();

  runtime.pendingJobs.add(
    job
  );

  void job.finally(
    () => {
      runtime.pendingJobs.delete(
        job
      );
    }
  );
}

/* -------------------------------------------------------------------------- */
/* Session telemetry                                                          */
/* -------------------------------------------------------------------------- */

function persistSessionCounters():
  void {
  const state =
    getState();

  const sessionId =
    state.sessionId;

  if (
    !sessionId
  ) {
    return;
  }

  const job =
    updateMonitorSession(
      sessionId,
      {
        packetsCapured:
          state.packetsCapured,

        flowsProcessed:
          state.flowsProcessed,

        alertsGenerated:
          state.alertsGenerated,
      }
    ).catch(
      () => {
        /*
         * Telemetry persistence failure must never terminate
         * packet capture.
         */
      }
    );

  trackJob(
    job
  );
}

/* -------------------------------------------------------------------------- */
/* Completed-flow processing                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Process exactly one completed REAL flow.
 *
 * Flow persistence is deliberately separated from alert persistence:
 *
 *   every completed flow
 *       ↓
 *      flows
 *
 *   suspicious flow
 *       ↓
 *     alerts
 *       ↓
 *   detections + SHAP
 */
function processCompletedFlow(
  aggregatedFlow:
    AggregatedFlow,
  generation:
    number
): void {
  const runtime =
    getRuntime();

  /*
   * Ignore callbacks belonging to an older monitor session.
   */
  if (
    generation !==
    runtime.generation
  ) {
    return;
  }

  const state =
    getState();

  if (
    !state.isRunning
  ) {
    return;
  }

  runtime.flowsSeen +=
    1;

  state.flowsProcessed =
    runtime.flowsSeen;

  state.lastActivity =
    new Date();

  const context =
    runtime.context;

  if (!context) {
    state.engineStatus.flow =
      "error";

    void logSystemEvent(
      "FlowEngine",
      "context_unavailable",
      "Rolling traffic context is not available",
      "error"
    ).catch(
      () => {}
    );

    return;
  }

  try {
    /*
     * Convert REAL aggregated traffic into the NetworkFlow contract.
     */
    const networkFlow =
      createNetworkFlow(
        aggregatedFlow
      );

    /*
     * Calculate contextual statistics from REAL observed flows.
     */
    const statistics =
      context.recordFlow(
        aggregatedFlow
      );

    applyRollingContext(
      networkFlow,
      statistics
    );

    state.engineStatus.flow =
      "online";

    /*
     * ML/database work is asynchronous so the TShark callback
     * remains lightweight.
     */
    const job =
      processDetection(
        networkFlow,
        generation
      );

    trackJob(
      job
    );
  } catch (error) {
    state.engineStatus.flow =
      "error";

    const message =
      error instanceof Error
        ? error.message
        : String(error);

    void logSystemEvent(
      "FlowEngine",
      "flow_processing_error",
      message,
      "error"
    ).catch(
      () => {}
    );
  }
}

/* -------------------------------------------------------------------------- */
/* Detection pipeline                                                         */
/* -------------------------------------------------------------------------- */

async function processDetection(
  networkFlow: ReturnType<
    typeof createNetworkFlow
  >,
  generation:
    number
): Promise<void> {
  const state =
    getState();

  const runtime =
    getRuntime();

  /*
   * Ignore stale asynchronous work.
   */
  if (
    generation !==
    runtime.generation
  ) {
    return;
  }

  let result:
    DetectionResult;

  /*
   * ------------------------------------------------------------------------
   * Run ML + anomaly + SHAP + MITRE
   * ------------------------------------------------------------------------
   */
  try {
    result =
      runDetectionPipeline(
        networkFlow
      );
  } catch (error) {
    state.engineStatus.ml =
      "error";

    const message =
      error instanceof Error
        ? error.message
        : String(error);

    await logSystemEvent(
      "MLEngine",
      "inference_error",
      message,
      "error"
    ).catch(
      () => {}
    );

    return;
  }

  /*
   * The monitor may have been stopped while inference was running.
   */
  if (
    generation !==
    runtime.generation
  ) {
    return;
  }

  state.engineStatus.ml =
    "online";

  state.engineStatus.shap =
    "online";

  /*
   * ------------------------------------------------------------------------
   * Persist EVERY completed flow
   * ------------------------------------------------------------------------
   *
   * This is the critical persistence fix.
   *
   * NORMAL traffic is still real traffic and must exist in the
   * `flows` table.
   */
  let flowId:
    number;

  try {
    flowId =
      await saveFlow(
        result,
        state.mode,
        state.pcapFile ||
          undefined
      );

    state.engineStatus.database =
      "online";
  } catch (error) {
    state.engineStatus.database =
      "error";

    const message =
      error instanceof Error
        ? error.message
        : String(error);

    await logSystemEvent(
      "Database",
      "flow_write_error",
      message,
      "error"
    ).catch(
      () => {}
    );

    /*
     * Never generate an alert without a persisted underlying flow.
     */
    return;
  }

  /*
   * ------------------------------------------------------------------------
   * Determine alert status
   * ------------------------------------------------------------------------
   */
  const isAlert =
    result.severity !==
    "NORMAL";

  if (
    isAlert
  ) {
    state.alertsGenerated +=
      1;
  }

  /*
   * ------------------------------------------------------------------------
   * Live dashboard event
   * ------------------------------------------------------------------------
   *
   * Broadcast both normal and suspicious detections.
   */
  broadcastEvent(
    "detection",
    {
      eventId:
        result.eventId,

      timestamp:
        result.timestamp,

      sourceIp:
        result.sourceIp,

      destinationIp:
        result.destinationIp,

      sourcePort:
        result.sourcePort,

      destinationPort:
        result.destinationPort,

      protocol:
        result.protocol,

      service:
        result.service,

      prediction:
        result.prediction,

      confidence:
        result.confidence,

      severity:
        result.severity,

      anomalyDetected:
        result.anomalyDetected,

      anomalyScore:
        result.anomalyScore,

      lowConfidence:
        result.lowConfidence,

      /*
       * Evidence-gate fields are included when exposed by
       * DetectionResult.
       */
      modelAgreement:
        result.modelAgreement,

      classMargin:
        result.classMargin,

      supervisedAlert:
        result.supervisedAlert,

      mitreTacticId:
        result.mitre.tacticId,

      mitreTacticName:
        result.mitre.tacticName,
    }
  );

  /*
   * ------------------------------------------------------------------------
   * Persist alert-specific evidence
   * ------------------------------------------------------------------------
   *
   * NORMAL flow:
   *
   *   saveFlow()
   *
   * Suspicious flow:
   *
   *   saveFlow()
   *       ↓
   *   saveDetectionResult()
   *       ↓
   *   alerts + detections + SHAP
   */
  if (
    isAlert
  ) {
    try {
      /*
       * The repository receives the exact flow ID that was already
       * persisted above. This prevents duplicate flow rows.
       */
      await saveDetectionResult(
        result,
        flowId,
        state.mode,
        state.pcapFile ||
          undefined
      );

      state.engineStatus.database =
        "online";
    } catch (error) {
      state.engineStatus.database =
        "error";

      const message =
        error instanceof Error
          ? error.message
          : String(error);

      await logSystemEvent(
        "Database",
        "alert_write_error",
        message,
        "error"
      ).catch(
        () => {}
      );
    }
  }

  /*
   * ------------------------------------------------------------------------
   * Updated counters
   * ------------------------------------------------------------------------
   */
  broadcastEvent(
    "stats",
    {
      packetsCapured:
        state.packetsCapured,

      flowsProcessed:
        state.flowsProcessed,

      alertsGenerated:
        state.alertsGenerated,
    }
  );

  /*
   * Persist session telemetry every 10 completed flows.
   */
  if (
    state.flowsProcessed >
      0 &&
    state.flowsProcessed %
      10 ===
      0
  ) {
    persistSessionCounters();
  }
}

/* -------------------------------------------------------------------------- */
/* Packet callback                                                            */
/* -------------------------------------------------------------------------- */

function handleCapturedPacket(
  packet:
    CapturedPacket,
  generation:
    number
): void {
  const runtime =
    getRuntime();

  if (
    generation !==
    runtime.generation
  ) {
    return;
  }

  const state =
    getState();

  if (
    !state.isRunning
  ) {
    return;
  }

  runtime.packetsSeen +=
    1;

  state.packetsCapured =
    runtime.packetsSeen;

  state.lastActivity =
    new Date();

  state.engineStatus.capture =
    "online";

  const aggregator =
    runtime.aggregator;

  if (
    !aggregator
  ) {
    state.engineStatus.flow =
      "error";

    void logSystemEvent(
      "FlowEngine",
      "aggregator_unavailable",
      "Flow aggregator is not available while monitor is running",
      "error"
    ).catch(
      () => {}
    );

    return;
  }

  try {
    aggregator.processPacket(
      packet
    );

    /*
     * TShark timestamps are UNIX epoch seconds.
     */
    aggregator.flushExpired(
      packet.timestamp *
        1000
    );
  } catch (error) {
    state.engineStatus.flow =
      "error";

    const message =
      error instanceof Error
        ? error.message
        : String(error);

    void logSystemEvent(
      "FlowEngine",
      "packet_processing_error",
      message,
      "error"
    ).catch(
      () => {}
    );
  }

  broadcastEvent(
    "stats",
    {
      packetsCapured:
        state.packetsCapured,

      flowsProcessed:
        state.flowsProcessed,

      alertsGenerated:
        state.alertsGenerated,
    }
  );
}

/* -------------------------------------------------------------------------- */
/* Stop capture resource                                                      */
/* -------------------------------------------------------------------------- */

function stopRuntimeCapture():
  void {
  const runtime =
    getRuntime();

  const capture =
    runtime.capture;

  runtime.capture =
    null;

  runtime.aggregator =
    null;

  runtime.context =
    null;

  if (
    capture
  ) {
    try {
      capture.stop();
    } catch {
      /*
       * TShark may already have exited.
       */
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Start monitoring                                                           */
/* -------------------------------------------------------------------------- */

export async function startMonitoring(
  sessionId:
    string,
  mode:
    MonitorMode,
  networkInterface?:
    string,
  pcapFile?:
    string
): Promise<void> {
  const state =
    getState();

  const runtime =
    getRuntime();

  /*
   * PCAP replay has not been connected to the real capture adapter here.
   */
  if (
    mode ===
    "pcap"
  ) {
    throw new Error(
      "PCAP replay mode is not connected to the real capture adapter yet. Use live mode for real-time TShark/Npcap monitoring."
    );
  }

  /*
   * Only one monitor may own the runtime at a time.
   */
  if (
    state.isRunning
  ) {
    await stopMonitoring();
  }

  /*
   * Invalidate callbacks from any previous session.
   */
  runtime.generation +=
    1;

  const generation =
    runtime.generation;

  /*
   * Reset runtime state for the new session.
   */
  runtime.capture =
    null;

  runtime.aggregator =
    null;

  runtime.context =
    null;

  runtime.packetsSeen =
    0;

  runtime.flowsSeen =
    0;

  runtime.pendingJobs.clear();

  /*
   * Resolve the real Windows TShark interface.
   */
  const interfaceId =
    resolveTSharkInterface(
      networkInterface
    );

  /*
   * Fresh context for each monitoring session.
   */
  const context =
    new RollingTrafficContext({
      recentWindowMs:
        2000,

      maxHistorySize:
        1000,

      hostWindowSize:
        100,
    });

  runtime.context =
    context;

  /*
   * Initialize in-memory monitor state.
   */
  Object.assign(
    state,
    {
      isRunning:
        true,

      mode,

      sessionId,

      networkInterface:
        networkInterface ||
        `tshark:${interfaceId}`,

      pcapFile:
        pcapFile ||
        null,

      startedAt:
        new Date(),

      packetsCapured:
        0,

      flowsProcessed:
        0,

      alertsGenerated:
        0,

      lastActivity:
        new Date(),

      engineStatus: {
        capture:
          "online",

        flow:
          "online",

        ml:
          "online",

        shap:
          "online",

        database:
          "online",

        api:
          "online",
      },
    }
  );

  /*
   * Create real-flow aggregator.
   */
  const aggregator =
    new FlowAggregator(
      (
        aggregatedFlow
      ) => {
        processCompletedFlow(
          aggregatedFlow,
          generation
        );
      },
      {
        idleTimeoutMs:
          3000,

        maxFlowAgeMs:
          30000,
      }
    );

  runtime.aggregator =
    aggregator;

  /*
   * Create the real TShark/Npcap capture.
   *
   * No synthetic data and no artificial traffic.
   */
  const capture =
    createTSharkCapture(
      {
        interfaceId,

        /*
         * Capture all traffic visible to the selected interface.
         * Filtering is performed by the flow layer rather than
         * artificially restricting the capture here.
         */
        captureFilter:
          undefined,
      },

      /*
       * Packet callback.
       */
      (packet) => {
        handleCapturedPacket(
          packet,
          generation
        );
      },

      /*
       * Capture error callback.
       */
      (error) => {
        if (
          generation !==
          runtime.generation
        ) {
          return;
        }

        state.engineStatus.capture =
          "error";

        void logSystemEvent(
          "Capture",
          "capture_error",
          error.message,
          "error"
        ).catch(
          () => {}
        );

        broadcastEvent(
          "monitor_error",
          {
            message:
              error.message,
          }
        );
      },

      /*
       * Capture stopped callback.
       */
      () => {
        if (
          generation !==
          runtime.generation
        ) {
          return;
        }

        /*
         * Flush any final flows before runtime resources disappear.
         */
        const currentAggregator =
          runtime.aggregator;

        if (
          currentAggregator
        ) {
          try {
            currentAggregator.flushAll();
          } catch {
            state.engineStatus.flow =
              "error";
          }
        }

        state.engineStatus.capture =
          "offline";

        broadcastEvent(
          "monitor_status",
          {
            status:
              state.isRunning
                ? "capture_stopped"
                : "stopped",

            sessionId:
              state.sessionId,

            packetsCapured:
              state.packetsCapured,

            flowsProcessed:
              state.flowsProcessed,

            alertsGenerated:
              state.alertsGenerated,
          }
        );
      }
    );

  runtime.capture =
    capture;

  /*
   * Record monitor startup in the audit log.
   */
  try {
    await logSystemEvent(
      "Monitor",
      "monitoring_started",
      `Real packet monitoring started in ${mode} mode on TShark interface ${interfaceId}${
        networkInterface
          ? ` (${networkInterface})`
          : ""
      }`,
      "info",
      {
        mode,

        interfaceId,

        networkInterface:
          networkInterface ||
          null,

        pcapFile:
          pcapFile ||
          null,

        sessionId,
      }
    );
  } catch {
    /*
     * Audit logging failure must not prevent packet capture.
     */
  }

  /*
   * Notify SSE/dashboard clients.
   */
  broadcastEvent(
    "monitor_status",
    {
      status:
        "running",

      mode,

      sessionId,

      networkInterface:
        networkInterface ||
        `tshark:${interfaceId}`,

      interfaceId,
    }
  );

  /*
   * Start TShark after all runtime components and callbacks
   * are ready.
   */
  try {
    capture.start();
  } catch (error) {
    state.isRunning =
      false;

    state.mode =
      "stopped";

    state.engineStatus.capture =
      "error";

    const message =
      error instanceof Error
        ? error.message
        : String(error);

    await logSystemEvent(
      "Capture",
      "capture_start_error",
      message,
      "error"
    ).catch(
      () => {}
    );

    throw error;
  }
}

/* -------------------------------------------------------------------------- */
/* Stop monitoring                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Stop the real monitor cleanly.
 *
 * Shutdown order:
 *
 *   1. Flush current flows while the generation is valid.
 *   2. Stop TShark.
 *   3. Wait for outstanding detection/database jobs.
 *   4. Invalidate old callbacks.
 *   5. Release runtime resources.
 *   6. Persist the final session state.
 *   7. Broadcast final stopped state.
 */
export async function stopMonitoring():
  Promise<void> {
  const state =
    getState();

  const runtime =
    getRuntime();

  /*
   * Idempotent shutdown.
   */
  if (
    !state.isRunning &&
    !runtime.capture &&
    !runtime.aggregator
  ) {
    return;
  }

  const sessionId =
    state.sessionId;

  /*
   * Flush all current flows FIRST, while the current generation
   * remains valid.
   */
  const aggregator =
    runtime.aggregator;

  if (
    aggregator
  ) {
    try {
      aggregator.flushAll();
    } catch (error) {
      state.engineStatus.flow =
        "error";

      const message =
        error instanceof Error
          ? error.message
          : String(error);

      await logSystemEvent(
        "FlowEngine",
        "flush_error",
        message,
        "error"
      ).catch(
        () => {}
      );
    }
  }

  /*
   * Stop TShark.
   */
  const capture =
    runtime.capture;

  if (
    capture
  ) {
    try {
      capture.stop();
    } catch {
      /*
       * Capture process may already have exited.
       */
    }
  }

  /*
   * Allow asynchronous ML/database jobs created by flushed flows
   * to finish before reading final counters.
   */
  const pendingJobs =
    Array.from(
      runtime.pendingJobs
    );

  if (
    pendingJobs.length >
      0
  ) {
    await Promise.allSettled(
      pendingJobs
    );
  }

  const finalPackets =
    state.packetsCapured;

  const finalFlows =
    state.flowsProcessed;

  const finalAlerts =
    state.alertsGenerated;

  /*
   * Invalidate callbacks belonging to this old session.
   */
  runtime.generation +=
    1;

  /*
   * Release runtime resources.
   */
  runtime.capture =
    null;

  runtime.aggregator =
    null;

  runtime.context =
    null;

  runtime.packetsSeen =
    0;

  runtime.flowsSeen =
    0;

  runtime.pendingJobs.clear();

  /*
   * Mark in-memory monitor stopped.
   */
  Object.assign(
    state,
    {
      isRunning:
        false,

      mode:
        "stopped" as MonitorMode,

      sessionId:
        null,

      networkInterface:
        null,

      pcapFile:
        null,

      startedAt:
        null,

      lastActivity:
        null,

      engineStatus: {
        ...state.engineStatus,

        capture:
          "offline" as const,

        flow:
          "offline" as const,
      },
    }
  );

  /*
   * IMPORTANT:
   *
   * Persist final session state and WAIT for PostgreSQL.
   */
  if (
    sessionId
  ) {
    try {
      await updateMonitorSession(
        sessionId,
        {
          status:
            "stopped",

          packetsCapured:
            finalPackets,

          flowsProcessed:
            finalFlows,

          alertsGenerated:
            finalAlerts,

          stoppedAt:
            new Date(),
        }
      );

      state.engineStatus.database =
        "online";
    } catch (error) {
      state.engineStatus.database =
        "error";

      const message =
        error instanceof Error
          ? error.message
          : String(error);

      await logSystemEvent(
        "Database",
        "monitor_stop_write_error",
        message,
        "error",
        {
          sessionId,

          packetsCapured:
            finalPackets,

          flowsProcessed:
            finalFlows,

          alertsGenerated:
            finalAlerts,
        }
      ).catch(
        () => {}
      );

      /*
       * In-memory state is stopped, but the caller must know that
       * PostgreSQL did not accept the final state.
       */
      throw error;
    }
  }

  /*
   * Broadcast the final state only after the database has been updated.
   */
  broadcastEvent(
    "monitor_status",
    {
      status:
        "stopped",

      sessionId,

      packetsCapured:
        finalPackets,

      flowsProcessed:
        finalFlows,

      alertsGenerated:
        finalAlerts,
    }
  );

  broadcastEvent(
    "stats",
    {
      packetsCapured:
        finalPackets,

      flowsProcessed:
        finalFlows,

      alertsGenerated:
        finalAlerts,
    }
  );

  /*
   * Final audit log.
   */
  await logSystemEvent(
    "Monitor",
    "monitoring_stopped",
    "Real packet monitoring stopped",
    "info",
    {
      sessionId,

      packetsCapured:
        finalPackets,

      flowsProcessed:
        finalFlows,

      alertsGenerated:
        finalAlerts,
    }
  ).catch(
    () => {}
  );
}

/* -------------------------------------------------------------------------- */
/* Available interfaces                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Interfaces exposed to the UI.
 *
 * Current lab:
 *
 *   eth0  → VMware VMnet1 → TShark 7
 *   wlan0 → Windows Wi-Fi → TShark 5
 */
export const AVAILABLE_INTERFACES = [
  {
    name:
      "eth0",

    description:
      "Lab capture interface: VMware Network Adapter VMnet1 (TShark ID 7)",

    available:
      true,
  },

  {
    name:
      "wlan0",

    description:
      "Windows Wi-Fi adapter (TShark ID 5)",

    available:
      true,
  },

  {
    name:
      "VMnet1",

    description:
      "VMware Network Adapter VMnet1 (TShark ID 7)",

    available:
      true,
  },

  {
    name:
      "VMnet8",

    description:
      "VMware Network Adapter VMnet8 (TShark ID 6)",

    available:
      true,
  },

  {
    name:
      "Wi-Fi",

    description:
      "Intel Wi-Fi adapter (TShark ID 5)",

    available:
      true,
  },
];