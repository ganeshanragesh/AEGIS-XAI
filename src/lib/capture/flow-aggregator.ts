/**
 * AEGIS-XAI Flow Aggregator
 *
 * Converts individual packets captured by TShark/Npcap into
 * bidirectional network-flow records.
 *
 * Architecture:
 *
 *   TShark/Npcap
 *          ↓
 *   CapturedPacket
 *          ↓
 *   FlowAggregator
 *          ↓
 *   AggregatedFlow
 *          ↓
 *   NetworkFlow adapter
 *          ↓
 *   AEGIS-XAI detection pipeline
 *
 * Responsibilities:
 *   - identify bidirectional flows
 *   - count packets in both directions
 *   - count bytes in both directions
 *   - track flow duration
 *   - track TCP connection flags
 *   - expire idle flows
 *   - flush flows when capture stops
 *
 * This module does NOT:
 *   - generate synthetic packets
 *   - run ML
 *   - generate alerts
 *   - write to PostgreSQL
 */

import type {
  CapturedPacket,
  CapturedProtocol,
} from "./tshark-capture";

/**
 * A completed bidirectional network flow.
 */
export interface AggregatedFlow {
  /**
   * Original direction of the first packet observed.
   */
  sourceIp: string;
  destinationIp: string;

  sourcePort: number;
  destinationPort: number;

  protocol: CapturedProtocol;

  /**
   * UNIX epoch seconds.
   */
  firstSeen: number;

  /**
   * UNIX epoch seconds.
   */
  lastSeen: number;

  /**
   * Duration in seconds.
   */
  duration: number;

  /**
   * Bytes sent from the original source
   * toward the original destination.
   */
  srcBytes: number;

  /**
   * Bytes sent from the original destination
   * toward the original source.
   */
  dstBytes: number;

  /**
   * Number of packets in the original source direction.
   */
  srcPackets: number;

  /**
   * Number of packets in the reverse direction.
   */
  dstPackets: number;

  /**
   * TCP SYN packets without ACK.
   */
  tcpSynCount: number;

  /**
   * TCP SYN+ACK packets.
   */
  tcpSynAckCount: number;

  /**
   * TCP FIN packets.
   */
  tcpFinCount: number;

  /**
   * TCP RST packets.
   */
  tcpRstCount: number;

  /**
   * Whether a TCP handshake was observed.
   */
  tcpEstablished: boolean;

  /**
   * Whether the flow observed a clean TCP FIN.
   */
  tcpClosed: boolean;

  /**
   * Whether the flow observed a TCP reset.
   */
  tcpReset: boolean;
}

/**
 * Internal mutable flow state.
 */
interface InternalFlow {
  key: string;

  sourceIp: string;
  destinationIp: string;

  sourcePort: number;
  destinationPort: number;

  protocol: CapturedProtocol;

  firstSeen: number;
  lastSeen: number;

  srcBytes: number;
  dstBytes: number;

  srcPackets: number;
  dstPackets: number;

  tcpSynCount: number;
  tcpSynAckCount: number;
  tcpFinCount: number;
  tcpRstCount: number;

  tcpEstablished: boolean;
  tcpClosed: boolean;
  tcpReset: boolean;
}

/**
 * Flow aggregation configuration.
 */
export interface FlowAggregatorOptions {
  /**
   * Emit a flow after this amount of inactivity.
   *
   * Default: 30 seconds.
   */
  idleTimeoutMs?: number;

  /**
   * Emit a flow after it reaches this maximum age.
   *
   * Default: 60 seconds.
   */
  maxFlowAgeMs?: number;
}

/**
 * Callback invoked when a flow is completed.
 */
export type FlowHandler = (
  flow: AggregatedFlow
) => void;

/**
 * Default flow timeout values.
 */
const DEFAULT_IDLE_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_FLOW_AGE_MS = 60_000;

/**
 * TCP flag masks.
 */
const TCP_FIN = 0x0001;
const TCP_SYN = 0x0002;
const TCP_RST = 0x0004;
const TCP_ACK = 0x0010;

/**
 * Produce a stable endpoint representation.
 */
function endpointKey(
  ip: string,
  port: number
): string {
  return `${ip}:${port}`;
}

/**
 * Build a stable flow key.
 *
 * For TCP/UDP:
 *
 *   protocol + endpoint A + endpoint B
 *
 * For ICMP:
 *
 *   protocol + IP A + IP B
 *
 * Endpoint ordering is normalized so both directions map
 * to the same flow.
 */
function buildFlowKey(
  packet: CapturedPacket
): string | null {
  if (
    !packet.sourceIp ||
    !packet.destinationIp
  ) {
    return null;
  }

  const sourceEndpoint =
    endpointKey(
      packet.sourceIp,
      packet.sourcePort ?? 0
    );

  const destinationEndpoint =
    endpointKey(
      packet.destinationIp,
      packet.destinationPort ?? 0
    );

  const ordered =
    sourceEndpoint <= destinationEndpoint
      ? [
          sourceEndpoint,
          destinationEndpoint,
        ]
      : [
          destinationEndpoint,
          sourceEndpoint,
        ];

  return [
    packet.protocol,
    ordered[0],
    ordered[1],
  ].join("|");
}

/**
 * Determine whether a packet belongs to the
 * original source → destination direction.
 */
function isForwardPacket(
  flow: InternalFlow,
  packet: CapturedPacket
): boolean {
  return (
    packet.sourceIp === flow.sourceIp &&
    packet.destinationIp ===
      flow.destinationIp &&
    (packet.sourcePort ?? 0) ===
      flow.sourcePort &&
    (packet.destinationPort ?? 0) ===
      flow.destinationPort
  );
}

/**
 * Create a new mutable flow from the first packet.
 */
function createInternalFlow(
  packet: CapturedPacket,
  key: string
): InternalFlow | null {
  if (
    !packet.sourceIp ||
    !packet.destinationIp
  ) {
    return null;
  }

  const flow: InternalFlow = {
    key,

    sourceIp:
      packet.sourceIp,

    destinationIp:
      packet.destinationIp,

    sourcePort:
      packet.sourcePort ?? 0,

    destinationPort:
      packet.destinationPort ?? 0,

    protocol:
      packet.protocol,

    firstSeen:
      packet.timestamp,

    lastSeen:
      packet.timestamp,

    srcBytes: 0,
    dstBytes: 0,

    srcPackets: 0,
    dstPackets: 0,

    tcpSynCount: 0,
    tcpSynAckCount: 0,
    tcpFinCount: 0,
    tcpRstCount: 0,

    tcpEstablished: false,
    tcpClosed: false,
    tcpReset: false,
  };

  addPacketToFlow(
    flow,
    packet
  );

  return flow;
}

/**
 * Add one packet to a mutable flow.
 */
function addPacketToFlow(
  flow: InternalFlow,
  packet: CapturedPacket
): void {
  flow.lastSeen =
    Math.max(
      flow.lastSeen,
      packet.timestamp
    );

  const forward =
    isForwardPacket(
      flow,
      packet
    );

  if (forward) {
    flow.srcPackets += 1;
    flow.srcBytes += packet.length;
  } else {
    flow.dstPackets += 1;
    flow.dstBytes += packet.length;
  }

  /*
   * ICMP/UDP don't have TCP state.
   */
  if (packet.protocol !== "tcp") {
    return;
  }

  const flags =
    packet.tcpFlags;

  const syn =
    (flags & TCP_SYN) !== 0;

  const ack =
    (flags & TCP_ACK) !== 0;

  const fin =
    (flags & TCP_FIN) !== 0;

  const rst =
    (flags & TCP_RST) !== 0;

  /*
   * SYN without ACK.
   */
  if (syn && !ack) {
    flow.tcpSynCount += 1;
  }

  /*
   * SYN + ACK.
   */
  if (syn && ack) {
    flow.tcpSynAckCount += 1;
  }

  /*
   * FIN.
   */
  if (fin) {
    flow.tcpFinCount += 1;
  }

  /*
   * RST.
   */
  if (rst) {
    flow.tcpRstCount += 1;
    flow.tcpReset = true;
  }

  /*
   * Basic handshake detection.
   */
  if (
    flow.tcpSynCount > 0 &&
    flow.tcpSynAckCount > 0 &&
    ack
  ) {
    flow.tcpEstablished = true;
  }

  /*
   * A FIN indicates a graceful close.
   *
   * We mark it here but do not immediately flush the flow.
   * The reverse FIN/ACK packets may still arrive.
   */
  if (fin) {
    flow.tcpClosed = true;
  }
}

/**
 * Convert mutable flow state to an immutable completed flow.
 */
function toAggregatedFlow(
  flow: InternalFlow
): AggregatedFlow {
  const duration =
    Math.max(
      0,
      flow.lastSeen -
        flow.firstSeen
    );

  return {
    sourceIp:
      flow.sourceIp,

    destinationIp:
      flow.destinationIp,

    sourcePort:
      flow.sourcePort,

    destinationPort:
      flow.destinationPort,

    protocol:
      flow.protocol,

    firstSeen:
      flow.firstSeen,

    lastSeen:
      flow.lastSeen,

    duration,

    srcBytes:
      flow.srcBytes,

    dstBytes:
      flow.dstBytes,

    srcPackets:
      flow.srcPackets,

    dstPackets:
      flow.dstPackets,

    tcpSynCount:
      flow.tcpSynCount,

    tcpSynAckCount:
      flow.tcpSynAckCount,

    tcpFinCount:
      flow.tcpFinCount,

    tcpRstCount:
      flow.tcpRstCount,

    tcpEstablished:
      flow.tcpEstablished,

    tcpClosed:
      flow.tcpClosed,

    tcpReset:
      flow.tcpReset,
  };
}

/**
 * Runtime statistics for the aggregator.
 */
export interface FlowAggregatorStats {
  activeFlows: number;
  packetsProcessed: number;
  packetsIgnored: number;
  flowsCompleted: number;
}

/**
 * Maintains active bidirectional flows.
 */
export class FlowAggregator {
  private readonly flows =
    new Map<string, InternalFlow>();

  private readonly idleTimeoutMs: number;
  private readonly maxFlowAgeMs: number;

  private readonly onFlow: FlowHandler;

  private packetsProcessed = 0;
  private packetsIgnored = 0;
  private flowsCompleted = 0;

  constructor(
    onFlow: FlowHandler,
    options: FlowAggregatorOptions = {}
  ) {
    this.onFlow = onFlow;

    this.idleTimeoutMs =
      options.idleTimeoutMs ??
      DEFAULT_IDLE_TIMEOUT_MS;

    this.maxFlowAgeMs =
      options.maxFlowAgeMs ??
      DEFAULT_MAX_FLOW_AGE_MS;
  }

  /**
   * Add one captured packet to the aggregator.
   *
   * Returns true when the packet was accepted into
   * a flow, otherwise false.
   */
  processPacket(
    packet: CapturedPacket
  ): boolean {
    this.packetsProcessed += 1;

    const key =
      buildFlowKey(packet);

    if (!key) {
      this.packetsIgnored += 1;
      return false;
    }

    const existingFlow =
      this.flows.get(key);

    /*
     * First packet for this flow.
     */
    if (!existingFlow) {
      const newFlow =
        createInternalFlow(
          packet,
          key
        );

      if (!newFlow) {
        this.packetsIgnored += 1;
        return false;
      }

      this.flows.set(
        key,
        newFlow
      );

      return true;
    }

    /*
     * Existing flow.
     */
    addPacketToFlow(
      existingFlow,
      packet
    );

    /*
     * We intentionally do not immediately flush
     * FIN/RST packets here.
     *
     * A short idle timeout allows remaining packets
     * of the same connection to be captured.
     */
    return true;
  }

  /**
   * Flush flows that have been idle for too long.
   *
   * now may be supplied in either:
   *   - UNIX milliseconds
   *   - UNIX seconds
   */
  flushExpired(
    now: number =
      Date.now()
  ): number {
    const nowSeconds =
      now > 10_000_000_000
        ? now / 1000
        : now;

    let flushed = 0;

    for (
      const [
        key,
        flow,
      ] of this.flows
    ) {
      const idleMs =
        (
          nowSeconds -
          flow.lastSeen
        ) * 1000;

      const ageMs =
        (
          nowSeconds -
          flow.firstSeen
        ) * 1000;

      if (
        idleMs >=
          this.idleTimeoutMs ||
        ageMs >=
          this.maxFlowAgeMs
      ) {
        this.flushFlow(key);
        flushed += 1;
      }
    }

    return flushed;
  }

  /**
   * Flush every active flow immediately.
   *
   * This should be called when packet capture stops.
   */
  flushAll(): number {
    const keys =
      Array.from(
        this.flows.keys()
      );

    for (
      const key of keys
    ) {
      this.flushFlow(key);
    }

    return keys.length;
  }

  /**
   * Number of currently active flows.
   */
  size(): number {
    return this.flows.size;
  }

  /**
   * Return aggregator statistics.
   */
  getStats(): FlowAggregatorStats {
    return {
      activeFlows:
        this.flows.size,

      packetsProcessed:
        this.packetsProcessed,

      packetsIgnored:
        this.packetsIgnored,

      flowsCompleted:
        this.flowsCompleted,
    };
  }

  /**
   * Emit and remove one flow.
   */
  private flushFlow(
    key: string
  ): void {
    const flow =
      this.flows.get(key);

    if (!flow) {
      return;
    }

    const aggregated =
      toAggregatedFlow(flow);

    this.flows.delete(key);

    try {
      this.onFlow(
        aggregated
      );

      this.flowsCompleted += 1;
    } catch {
      /*
       * The consumer is responsible for logging its own
       * processing failures. The aggregator should not
       * leave a completed flow stuck in memory.
       */
    }
  }
}