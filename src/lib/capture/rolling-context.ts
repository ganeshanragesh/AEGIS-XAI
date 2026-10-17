/**
 * AEGIS-XAI Rolling Traffic Context
 *
 * Maintains a rolling history of REAL completed network flows
 * and calculates NSL-KDD-style contextual statistics.
 *
 * Architecture:
 *
 *   Real packets
 *        ↓
 *   FlowAggregator
 *        ↓
 *   AggregatedFlow
 *        ↓
 *   RollingTrafficContext
 *        ↓
 *   contextual statistics
 *        ↓
 *   NetworkFlow adapter
 *
 * The statistics calculated here are derived from observed
 * flows only. No synthetic connections are created.
 *
 * Windows:
 *
 *   Recent window:
 *     configurable, default 2 seconds
 *
 *   Host/service window:
 *     configurable, default 100 completed flows
 */

import type {
  AggregatedFlow,
} from "./flow-aggregator";

export interface FlowContextStatistics {
  /**
   * Connections to the same destination host in the
   * recent time window.
   */
  count: number;

  /**
   * Connections to the same service in the
   * recent time window.
   */
  srvCount: number;

  /**
   * Fraction of recent connections with SYN errors.
   */
  serrorRate: number;

  /**
   * Fraction of same-service recent connections
   * with SYN errors.
   */
  srvSerrorRate: number;

  /**
   * Fraction of recent connections with reset/rejection.
   */
  rerrorRate: number;

  /**
   * Fraction of same-service recent connections
   * with reset/rejection.
   */
  srvRerrorRate: number;

  /**
   * Fraction of recent connections using the same service.
   */
  sameSrvRate: number;

  /**
   * Fraction of recent connections using another service.
   */
  diffSrvRate: number;

  /**
   * Fraction of same-service recent connections
   * involving a different destination host.
   */
  srvDiffHostRate: number;

  /**
   * Number of flows in the host window involving
   * the same destination host.
   */
  dstHostCount: number;

  /**
   * Number of flows in the host window involving
   * the same host and service.
   */
  dstHostSrvCount: number;

  /**
   * Fraction of host-window flows using the same service.
   */
  dstHostSameSrvRate: number;

  /**
   * Fraction of host-window flows using a different service.
   */
  dstHostDiffSrvRate: number;

  /**
   * Fraction of host-window flows using the same source port.
   */
  dstHostSameSrcPortRate: number;

  /**
   * Fraction of same-service host-window flows coming
   * from different source hosts.
   */
  dstHostSrvDiffHostRate: number;

  /**
   * Fraction of host-window flows with SYN errors.
   */
  dstHostSerrorRate: number;

  /**
   * Fraction of same-service host-window flows
   * with SYN errors.
   */
  dstHostSrvSerrorRate: number;

  /**
   * Fraction of host-window flows with reset/rejection.
   */
  dstHostRerrorRate: number;

  /**
   * Fraction of same-service host-window flows
   * with reset/rejection.
   */
  dstHostSrvRerrorRate: number;
}

export interface RollingTrafficContextOptions {
  /**
   * Recent connection window.
   *
   * Default: 2000ms.
   */
  recentWindowMs?: number;

  /**
   * Maximum number of completed flows retained
   * globally.
   *
   * Default: 1000.
   */
  maxHistorySize?: number;

  /**
   * Number of historical flows considered by host-window
   * calculations.
   *
   * Default: 100.
   */
  hostWindowSize?: number;
}

interface HistoricalFlow {
  flow: AggregatedFlow;

  /**
   * Cached destination service.
   *
   * The context layer deliberately receives only
   * AggregatedFlow, so this stays protocol/port based.
   */
  service: string;

  /**
   * True when a SYN was observed without a completed
   * TCP handshake.
   */
  synError: boolean;

  /**
   * True when a reset/rejection was observed.
   */
  rejectError: boolean;
}

const DEFAULT_RECENT_WINDOW_MS = 2_000;
const DEFAULT_MAX_HISTORY_SIZE = 1_000;
const DEFAULT_HOST_WINDOW_SIZE = 100;

/**
 * Clamp ratios into [0, 1].
 */
function clampRate(
  numerator: number,
  denominator: number
): number {
  if (
    denominator <= 0 ||
    !Number.isFinite(numerator) ||
    !Number.isFinite(denominator)
  ) {
    return 0;
  }

  return Math.min(
    1,
    Math.max(
      0,
      numerator / denominator
    )
  );
}

/**
 * Convert protocol + port into the same service labels
 * understood by the existing AEGIS feature layer.
 *
 * This intentionally mirrors the existing feature contract.
 */
function inferService(
  flow: AggregatedFlow
): string {
  const port =
    flow.destinationPort;

  const protocol =
    flow.protocol.toLowerCase();

  if (protocol === "icmp") {
    return "eco_i";
  }

  if (protocol === "udp") {
    switch (port) {
      case 53:
        return "domain_u";

      case 123:
        return "ntp_u";

      case 67:
      case 68:
        return "private";

      default:
        return "other";
    }
  }

  if (protocol === "tcp") {
    switch (port) {
      case 20:
        return "ftp_data";

      case 21:
        return "ftp";

      case 22:
        return "ssh";

      case 23:
        return "telnet";

      case 25:
        return "smtp";

      case 53:
        return "dns";

      case 79:
        return "finger";

      case 80:
        return "http";

      case 110:
        return "pop3";

      case 119:
        return "nntp";

      case 123:
        return "ntp_u";

      case 143:
        return "imap";

      case 443:
        return "https";

      case 3306:
      case 5432:
        return "private";

      case 8080:
        return "http";

      case 8443:
        return "https";

      default:
        return "other";
    }
  }

  return "other";
}

/**
 * Whether the flow appears to have a SYN error.
 */
function isSynError(
  flow: AggregatedFlow
): boolean {
  return (
    flow.protocol === "tcp" &&
    flow.tcpSynCount > 0 &&
    !flow.tcpEstablished
  );
}

/**
 * Whether the flow appears reset/rejected.
 */
function isRejectError(
  flow: AggregatedFlow
): boolean {
  return (
    flow.protocol === "tcp" &&
    flow.tcpReset
  );
}

/**
 * Return the flow's packet-observation timestamp.
 *
 * AggregatedFlow timestamps are UNIX epoch seconds.
 */
function flowTimeMs(
  flow: AggregatedFlow
): number {
  return flow.lastSeen * 1000;
}

/**
 * Build a historical record from a completed flow.
 */
function createHistoricalFlow(
  flow: AggregatedFlow
): HistoricalFlow {
  return {
    flow,

    service:
      inferService(flow),

    synError:
      isSynError(flow),

    rejectError:
      isRejectError(flow),
  };
}

/**
 * Rolling history of completed real flows.
 */
export class RollingTrafficContext {
  private readonly history:
    HistoricalFlow[] = [];

  private readonly recentWindowMs: number;
  private readonly maxHistorySize: number;
  private readonly hostWindowSize: number;

  constructor(
    options: RollingTrafficContextOptions = {}
  ) {
    this.recentWindowMs =
      options.recentWindowMs ??
      DEFAULT_RECENT_WINDOW_MS;

    this.maxHistorySize =
      options.maxHistorySize ??
      DEFAULT_MAX_HISTORY_SIZE;

    this.hostWindowSize =
      options.hostWindowSize ??
      DEFAULT_HOST_WINDOW_SIZE;
  }

  /**
   * Record a completed real flow.
   *
   * Returns the contextual statistics for that flow.
   *
   * The new flow itself is included in the historical
   * population because the NSL-KDD-style measurements
   * describe the connection in relation to recent traffic.
   */
  recordFlow(
    flow: AggregatedFlow
  ): FlowContextStatistics {
    const current =
      createHistoricalFlow(flow);

    this.history.push(current);

    this.trimHistory(
      flowTimeMs(flow)
    );

    return this.calculate(
      current
    );
  }

  /**
   * Calculate contextual statistics without adding a
   * new flow to the history.
   */
  calculateForFlow(
    flow: AggregatedFlow
  ): FlowContextStatistics {
    const current =
      createHistoricalFlow(flow);

    return this.calculate(
      current
    );
  }

  /**
   * Remove old flows from memory.
   */
  private trimHistory(
    nowMs: number
  ): void {
    /*
     * First remove entries that can no longer contribute
     * to the 2-second window and are outside the host window.
     *
     * We retain the most recent host-window records.
     */
    const minimumRecentTime =
      nowMs -
      this.recentWindowMs;

    const minimumRetainedIndex =
      Math.max(
        0,
        this.history.length -
          this.hostWindowSize
      );

    /*
     * We need at least hostWindowSize entries, but older
     * entries may safely disappear once they're outside both
     * the recent window and the host window.
     */
    const keepFromTime =
      this.history[
        minimumRetainedIndex
      ]?.flow.firstSeen !== undefined
        ? Math.min(
            minimumRecentTime / 1000,
            this.history[
              minimumRetainedIndex
            ].flow.firstSeen
          )
        : minimumRecentTime / 1000;

    while (
      this.history.length >
        0 &&
      (
        this.history.length >
          this.maxHistorySize ||
        (
          this.history.length >
            this.hostWindowSize &&
          this.history[0].flow.lastSeen *
              1000 <
            keepFromTime * 1000
        )
      )
    ) {
      this.history.shift();
    }

    /*
     * Hard limit as a final safeguard.
     */
    if (
      this.history.length >
      this.maxHistorySize
    ) {
      this.history.splice(
        0,
        this.history.length -
          this.maxHistorySize
      );
    }
  }

  /**
   * Calculate the full contextual feature set.
   */
  private calculate(
    current: HistoricalFlow
  ): FlowContextStatistics {
    const currentTime =
      flowTimeMs(
        current.flow
      );

    const recent =
      this.history.filter(
        (entry) => {
          const age =
            currentTime -
            flowTimeMs(
              entry.flow
            );

          return (
            age >= 0 &&
            age <=
              this.recentWindowMs
          );
        }
      );

    /*
     * Make sure the flow currently being evaluated is
     * represented even when calculateForFlow() is used.
     */
    const recentWithCurrent =
      recent.includes(current)
        ? recent
        : [
            ...recent,
            current,
          ];

    const hostWindow =
      this.history.slice(
        -this.hostWindowSize
      );

    const hostWindowWithCurrent =
      hostWindow.includes(current)
        ? hostWindow
        : [
            ...hostWindow,
            current,
          ];

    /*
     * Current destination identity.
     */
    const destinationHost =
      current.flow.destinationIp;

    const currentService =
      current.service;

    const currentSourcePort =
      current.flow.sourcePort;

    /*
     * Recent host connections.
     */
    const sameDestinationHost =
      recentWithCurrent.filter(
        (entry) =>
          entry.flow.destinationIp ===
          destinationHost
      );

    const sameService =
      recentWithCurrent.filter(
        (entry) =>
          entry.service ===
          currentService
      );

    const sameServiceDifferentHost =
      sameService.filter(
        (entry) =>
          entry.flow.destinationIp !==
          destinationHost
      );

    /*
     * Error populations.
     */
    const recentSynErrors =
      recentWithCurrent.filter(
        (entry) =>
          entry.synError
      );

    const sameServiceSynErrors =
      sameService.filter(
        (entry) =>
          entry.synError
      );

    const recentRejectErrors =
      recentWithCurrent.filter(
        (entry) =>
          entry.rejectError
      );

    const sameServiceRejectErrors =
      sameService.filter(
        (entry) =>
          entry.rejectError
      );

    /*
     * Host-window populations.
     */
    const sameHostInWindow =
      hostWindowWithCurrent.filter(
        (entry) =>
          entry.flow.destinationIp ===
          destinationHost
      );

    const sameHostServiceInWindow =
      sameHostInWindow.filter(
        (entry) =>
          entry.service ===
          currentService
      );

    const sameServiceInWindow =
      hostWindowWithCurrent.filter(
        (entry) =>
          entry.service ===
          currentService
      );

    const sameServiceDifferentSourceHost =
      sameHostServiceInWindow.filter(
        (entry) =>
          entry.flow.sourceIp !==
          current.flow.sourceIp
      );

    const sameSourcePortInHostWindow =
      sameHostInWindow.filter(
        (entry) =>
          entry.flow.sourcePort ===
          currentSourcePort
      );

    const hostSynErrors =
      sameHostInWindow.filter(
        (entry) =>
          entry.synError
      );

    const hostServiceSynErrors =
      sameHostServiceInWindow.filter(
        (entry) =>
          entry.synError
      );

    const hostRejectErrors =
      sameHostInWindow.filter(
        (entry) =>
          entry.rejectError
      );

    const hostServiceRejectErrors =
      sameHostServiceInWindow.filter(
        (entry) =>
          entry.rejectError
      );

    const recentCount =
      sameDestinationHost.length;

    const recentServiceCount =
      sameService.length;

    const hostCount =
      sameHostInWindow.length;

    const hostServiceCount =
      sameHostServiceInWindow.length;

    return {
      /*
       * Recent connection counts.
       */
      count:
        Math.max(
          1,
          recentCount
        ),

      srvCount:
        Math.max(
          1,
          recentServiceCount
        ),

      /*
       * Recent error rates.
       */
      serrorRate:
        clampRate(
          recentSynErrors.length,
          recentWithCurrent.length
        ),

      srvSerrorRate:
        clampRate(
          sameServiceSynErrors.length,
          recentServiceCount
        ),

      rerrorRate:
        clampRate(
          recentRejectErrors.length,
          recentWithCurrent.length
        ),

      srvRerrorRate:
        clampRate(
          sameServiceRejectErrors.length,
          recentServiceCount
        ),

      /*
       * Recent service distribution.
       */
      sameSrvRate:
        clampRate(
          recentServiceCount,
          recentWithCurrent.length
        ),

      diffSrvRate:
        clampRate(
          recentWithCurrent.length -
            recentServiceCount,
          recentWithCurrent.length
        ),

      srvDiffHostRate:
        clampRate(
          sameServiceDifferentHost.length,
          recentServiceCount
        ),

      /*
       * Host-window measurements.
       */
      dstHostCount:
        Math.max(
          1,
          hostCount
        ),

      dstHostSrvCount:
        Math.max(
          1,
          hostServiceCount
        ),

      dstHostSameSrvRate:
        clampRate(
          hostServiceCount,
          hostCount
        ),

      dstHostDiffSrvRate:
        clampRate(
          hostCount -
            hostServiceCount,
          hostCount
        ),

      dstHostSameSrcPortRate:
        clampRate(
          sameSourcePortInHostWindow.length,
          hostCount
        ),

      dstHostSrvDiffHostRate:
        clampRate(
          sameServiceDifferentSourceHost.length,
          hostServiceCount
        ),

      /*
       * Host-window error rates.
       */
      dstHostSerrorRate:
        clampRate(
          hostSynErrors.length,
          hostCount
        ),

      dstHostSrvSerrorRate:
        clampRate(
          hostServiceSynErrors.length,
          hostServiceCount
        ),

      dstHostRerrorRate:
        clampRate(
          hostRejectErrors.length,
          hostCount
        ),

      dstHostSrvRerrorRate:
        clampRate(
          hostServiceRejectErrors.length,
          hostServiceCount
        ),
    };
  }

  /**
   * Number of historical flows currently retained.
   */
  size(): number {
    return this.history.length;
  }

  /**
   * Clear the context history.
   */
  clear(): void {
    this.history.length = 0;
  }

  /**
   * Return a read-only snapshot of the history.
   *
   * Useful for debugging/tests without exposing the mutable
   * internal array.
   */
  getHistorySnapshot(): AggregatedFlow[] {
    return this.history.map(
      (entry) => entry.flow
    );
  }
}