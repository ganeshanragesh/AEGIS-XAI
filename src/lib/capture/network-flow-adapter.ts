/**
 * AEGIS-XAI Real Network Flow Adapter
 *
 * Converts a completed AggregatedFlow produced by the real
 * TShark/Npcap capture pipeline into the NetworkFlow contract
 * expected by AEGIS-XAI.
 *
 * Architecture:
 *
 *   Npcap / TShark
 *          ↓
 *   CapturedPacket
 *          ↓
 *   FlowAggregator
 *          ↓
 *   AggregatedFlow
 *          ↓
 *   NetworkFlow
 *          ↓
 *   extractFeatureVector()
 *          ↓
 *   AEGIS-XAI detection pipeline
 *
 * Important:
 *   This adapter does not generate synthetic traffic.
 *
 * Packet-observable values are derived from real traffic.
 *
 * Features requiring host/application telemetry that is not
 * available from the packet stream are kept at conservative
 * zero/false values rather than being fabricated.
 */

import {
  inferFlag,
  portToService,
  type NetworkFlow,
} from "../aegis/features";

import type {
  AggregatedFlow,
} from "./flow-aggregator";

/**
 * Return a finite number or a safe fallback.
 */
function finite(
  value: number,
  fallback = 0
): number {
  return Number.isFinite(value)
    ? value
    : fallback;
}

/**
 * Clamp a numerical ratio to [0, 1].
 */
function clampRate(
  value: number
): number {
  if (!Number.isFinite(value)) {
    return 0;
  }

  return Math.min(
    1,
    Math.max(0, value)
  );
}

/**
 * Determine whether the observed TCP flow looks like
 * an unsuccessful SYN attempt.
 */
function hasSynError(
  flow: AggregatedFlow
): boolean {
  if (flow.protocol !== "tcp") {
    return false;
  }

  return (
    flow.tcpSynCount > 0 &&
    !flow.tcpEstablished
  );
}

/**
 * Determine whether the flow observed a reset/rejection.
 */
function hasRejectError(
  flow: AggregatedFlow
): boolean {
  if (flow.protocol !== "tcp") {
    return false;
  }

  return flow.tcpReset;
}

/**
 * Convert the observed TCP state into the
 * NSL-KDD-style flag categories used by AEGIS-XAI.
 */
function determineConnectionFlag(
  flow: AggregatedFlow
): string {
  if (flow.protocol !== "tcp") {
    return "OTH";
  }

  const synSent =
    flow.tcpSynCount > 0;

  const ackReceived =
    flow.tcpEstablished;

  const finSeen =
    flow.tcpFinCount > 0;

  const rstSeen =
    flow.tcpRstCount > 0;

  const rejected =
    flow.tcpReset;

  return inferFlag(
    synSent,
    ackReceived,
    finSeen,
    rstSeen,
    rejected
  );
}

/**
 * Convert a real packet-derived flow into the existing
 * AEGIS-XAI NetworkFlow structure.
 */
export function aggregatedFlowToNetworkFlow(
  flow: AggregatedFlow
): NetworkFlow {
  /*
   * Determine the application/service category from
   * the observed destination port.
   */
  const service =
    portToService(
      flow.destinationPort,
      flow.protocol
    );

  /*
   * Determine the NSL-KDD-style connection state.
   */
  const flag =
    determineConnectionFlag(flow);

  /*
   * Determine packet-derived error signals.
   */
  const synError =
    hasSynError(flow);

  const rejectError =
    hasRejectError(flow);

  /*
   * Current-flow count statistics.
   *
   * These are intentionally conservative. A future rolling
   * context collector will replace them with measurements
   * across the preceding connection window.
   */
  const count = 1;

  const srvCount = 1;

  const sameSrvRate =
    clampRate(1);

  const diffSrvRate =
    clampRate(0);

  /*
   * Same-service traffic to the observed destination host.
   */
  const srvDiffHostRate =
    clampRate(0);

  const dstHostCount = 1;

  const dstHostSrvCount = 1;

  const dstHostSameSrvRate =
    clampRate(1);

  const dstHostDiffSrvRate =
    clampRate(0);

  const dstHostSameSrcPortRate =
    clampRate(1);

  const dstHostSrvDiffHostRate =
    clampRate(0);

  /*
   * Current-flow error rates.
   */
  const serrorRate =
    synError ? 1 : 0;

  const srvSerrorRate =
    synError ? 1 : 0;

  const rerrorRate =
    rejectError ? 1 : 0;

  const srvRerrorRate =
    rejectError ? 1 : 0;

  const dstHostSerrorRate =
    synError ? 1 : 0;

  const dstHostSrvSerrorRate =
    synError ? 1 : 0;

  const dstHostRerrorRate =
    rejectError ? 1 : 0;

  const dstHostSrvRerrorRate =
    rejectError ? 1 : 0;

  /*
   * These fields require host/application telemetry rather
   * than ordinary packet headers. We deliberately do not
   * pretend that packet capture observed them.
   */
  const wrongFragment = 0;
  const urgent = 0;
  const hot = 0;

  const numFailedLogins = 0;
  const loggedIn = false;
  const numCompromised = 0;
  const rootShell = false;
  const suAttempted = false;
  const numRoot = 0;
  const numFileCreations = 0;
  const numShells = 0;
  const numAccessFiles = 0;
  const numOutboundCmds = 0;
  const isHostLogin = false;
  const isGuestLogin = false;

  /*
   * LAND condition.
   *
   * This uses the source/destination IP and port pair.
   */
  const land =
    flow.sourceIp === flow.destinationIp &&
    flow.sourcePort === flow.destinationPort;

  /*
   * NetworkFlow requires numeric source/destination ports.
   *
   * ICMP has no TCP/UDP ports, so the adapter uses zero.
   */
  const sourcePort =
    Math.max(
      0,
      Math.trunc(
        finite(
          flow.sourcePort,
          0
        )
      )
    );

  const destinationPort =
    Math.max(
      0,
      Math.trunc(
        finite(
          flow.destinationPort,
          0
        )
      )
    );

  /*
   * Sanitize basic flow measurements.
   */
  const duration =
    Math.max(
      0,
      finite(flow.duration)
    );

  const srcBytes =
    Math.max(
      0,
      Math.trunc(
        finite(flow.srcBytes)
      )
    );

  const dstBytes =
    Math.max(
      0,
      Math.trunc(
        finite(flow.dstBytes)
      )
    );

  const srcPackets =
    Math.max(
      0,
      Math.trunc(
        finite(flow.srcPackets)
      )
    );

  const dstPackets =
    Math.max(
      0,
      Math.trunc(
        finite(flow.dstPackets)
      )
    );

  return {
    /*
     * Network identity
     */
    sourceIp:
      flow.sourceIp,

    destinationIp:
      flow.destinationIp,

    sourcePort,

    destinationPort,

    protocol:
      flow.protocol,

    /*
     * Flow measurements
     */
    duration,

    srcBytes,

    dstBytes,

    srcPackets,

    dstPackets,

    /*
     * Application/service state
     */
    service,

    flag,

    /*
     * Basic packet-derived structural features
     */
    land,

    wrongFragment,

    urgent,

    hot,

    /*
     * Host/application telemetry not available
     * from this capture source.
     */
    numFailedLogins,

    loggedIn,

    numCompromised,

    rootShell,

    suAttempted,

    numRoot,

    numFileCreations,

    numShells,

    numAccessFiles,

    numOutboundCmds,

    isHostLogin,

    isGuestLogin,

    /*
     * Connection context
     */
    count,

    srvCount,

    serrorRate,

    srvSerrorRate,

    rerrorRate,

    srvRerrorRate,

    sameSrvRate,

    diffSrvRate,

    srvDiffHostRate,

    dstHostCount,

    dstHostSrvCount,

    dstHostSameSrvRate,

    dstHostDiffSrvRate,

    dstHostSameSrcPortRate,

    dstHostSrvDiffHostRate,

    dstHostSerrorRate,

    dstHostSrvSerrorRate,

    dstHostRerrorRate,

    dstHostSrvRerrorRate,
  };
}

/**
 * Validate a NetworkFlow before it is passed to the
 * AEGIS-XAI feature encoder.
 */
export function validateNetworkFlow(
  flow: NetworkFlow
): void {
  const numericFields: Array<
    [string, number]
  > = [
    ["sourcePort", flow.sourcePort],
    ["destinationPort", flow.destinationPort],
    ["duration", flow.duration],
    ["srcBytes", flow.srcBytes],
    ["dstBytes", flow.dstBytes],
    ["srcPackets", flow.srcPackets],
    ["dstPackets", flow.dstPackets],
    ["wrongFragment", flow.wrongFragment],
    ["urgent", flow.urgent],
    ["hot", flow.hot],
    ["numFailedLogins", flow.numFailedLogins],
    ["numCompromised", flow.numCompromised],
    ["numRoot", flow.numRoot],
    ["numFileCreations", flow.numFileCreations],
    ["numShells", flow.numShells],
    ["numAccessFiles", flow.numAccessFiles],
    ["numOutboundCmds", flow.numOutboundCmds],
    ["count", flow.count],
    ["srvCount", flow.srvCount],
    ["serrorRate", flow.serrorRate],
    ["srvSerrorRate", flow.srvSerrorRate],
    ["rerrorRate", flow.rerrorRate],
    ["srvRerrorRate", flow.srvRerrorRate],
    ["sameSrvRate", flow.sameSrvRate],
    ["diffSrvRate", flow.diffSrvRate],
    ["srvDiffHostRate", flow.srvDiffHostRate],
    ["dstHostCount", flow.dstHostCount],
    ["dstHostSrvCount", flow.dstHostSrvCount],
    ["dstHostSameSrvRate", flow.dstHostSameSrvRate],
    ["dstHostDiffSrvRate", flow.dstHostDiffSrvRate],
    ["dstHostSameSrcPortRate", flow.dstHostSameSrcPortRate],
    ["dstHostSrvDiffHostRate", flow.dstHostSrvDiffHostRate],
    ["dstHostSerrorRate", flow.dstHostSerrorRate],
    ["dstHostSrvSerrorRate", flow.dstHostSrvSerrorRate],
    ["dstHostRerrorRate", flow.dstHostRerrorRate],
    ["dstHostSrvRerrorRate", flow.dstHostSrvRerrorRate],
  ];

  for (
    const [
      field,
      value,
    ] of numericFields
  ) {
    if (!Number.isFinite(value)) {
      throw new Error(
        `Invalid NetworkFlow numeric field: ${field}`
      );
    }
  }

  if (
    !flow.sourceIp ||
    !flow.destinationIp
  ) {
    throw new Error(
      "NetworkFlow requires sourceIp and destinationIp"
    );
  }

  if (!flow.protocol) {
    throw new Error(
      "NetworkFlow requires protocol"
    );
  }

  if (!flow.service) {
    throw new Error(
      "NetworkFlow requires service"
    );
  }

  if (!flow.flag) {
    throw new Error(
      "NetworkFlow requires flag"
    );
  }
}

/**
 * Convert and validate an AggregatedFlow.
 */
export function createNetworkFlow(
  flow: AggregatedFlow
): NetworkFlow {
  const networkFlow =
    aggregatedFlowToNetworkFlow(
      flow
    );

  validateNetworkFlow(
    networkFlow
  );

  return networkFlow;
}

/**
 * Format a NetworkFlow for diagnostics.
 */
export function formatNetworkFlowSummary(
  flow: NetworkFlow
): string {
  const totalPackets =
    flow.srcPackets +
    flow.dstPackets;

  const totalBytes =
    flow.srcBytes +
    flow.dstBytes;

  return [
    "[AEGIS REAL FLOW]",
    `${flow.sourceIp}:${flow.sourcePort}`,
    "→",
    `${flow.destinationIp}:${flow.destinationPort}`,
    `protocol=${flow.protocol}`,
    `service=${flow.service}`,
    `flag=${flow.flag}`,
    `duration=${flow.duration.toFixed(3)}s`,
    `packets=${totalPackets}`,
    `bytes=${totalBytes}`,
  ].join(" | ");
}