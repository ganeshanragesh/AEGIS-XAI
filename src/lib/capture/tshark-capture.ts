/**
 * AEGIS-XAI TShark Capture Adapter
 *
 * Real packet-capture layer for Windows.
 *
 * Pipeline:
 *
 *   Npcap
 *      ↓
 *   TShark
 *      ↓
 *   stdout
 *      ↓
 *   CapturedPacket
 *      ↓
 *   FlowAggregator
 *      ↓
 *   NetworkFlow
 *      ↓
 *   AEGIS-XAI
 *
 * This module:
 *   - captures REAL packets
 *   - parses TShark field output
 *   - exposes packets to the caller
 *
 * This module does NOT:
 *   - generate synthetic packets
 *   - perform ML classification
 *   - generate alerts
 *   - write to PostgreSQL
 */

import {
  spawn,
  type ChildProcessByStdio,
} from "node:child_process";

import {
  Readable,
} from "node:stream";

import {
  createInterface,
  type Interface,
} from "node:readline";

/* -------------------------------------------------------------------------- */
/* Public types                                                               */
/* -------------------------------------------------------------------------- */

export type CapturedProtocol =
  | "tcp"
  | "udp"
  | "icmp"
  | "other";

export interface CapturedPacket {
  /**
   * UNIX epoch timestamp in seconds.
   */
  timestamp: number;

  /**
   * IPv4 source address.
   */
  sourceIp: string | null;

  /**
   * IPv4 destination address.
   */
  destinationIp: string | null;

  /**
   * TCP/UDP source port.
   */
  sourcePort: number | null;

  /**
   * TCP/UDP destination port.
   */
  destinationPort: number | null;

  /**
   * Normalized network protocol.
   */
  protocol: CapturedProtocol;

  /**
   * TCP flags represented as a numeric bitmask.
   */
  tcpFlags: number;

  /**
   * Full Ethernet frame length.
   */
  length: number;

  /**
   * Source MAC address.
   */
  sourceMac: string | null;

  /**
   * Destination MAC address.
   */
  destinationMac: string | null;
}

export interface TSharkCaptureOptions {
  /**
   * Full path to tshark.exe.
   *
   * Default:
   *   C:\Program Files\Wireshark\tshark.exe
   */
  tsharkPath?: string;

  /**
   * Numeric TShark interface ID.
   *
   * Your current lab:
   *   VMnet1 = 7
   */
  interfaceId: number;

  /**
   * Optional Berkeley Packet Filter.
   *
   * Example:
   *   host 192.168.2.128
   */
  captureFilter?: string;
}

export type PacketHandler = (
  packet: CapturedPacket
) => void;

export type CaptureErrorHandler = (
  error: Error
) => void;

export type CaptureStoppedHandler = () => void;

export interface TSharkCapture {
  start(): void;
  stop(): void;
  isRunning(): boolean;
}

/* -------------------------------------------------------------------------- */
/* Internal process type                                                       */
/* -------------------------------------------------------------------------- */

type TSharkProcess =
  ChildProcessByStdio<
    null,
    Readable,
    Readable
  >;

/* -------------------------------------------------------------------------- */
/* Constants                                                                  */
/* -------------------------------------------------------------------------- */

const DEFAULT_TSHARK_PATH =
  "C:\\Program Files\\Wireshark\\tshark.exe";

/**
 * Output columns:
 *
 *  0 frame.time_epoch
 *  1 eth.src
 *  2 eth.dst
 *  3 ip.src
 *  4 ip.dst
 *  5 ip.proto
 *  6 tcp.srcport
 *  7 tcp.dstport
 *  8 tcp.flags
 *  9 udp.srcport
 * 10 udp.dstport
 * 11 frame.len
 */
const EXPECTED_FIELD_COUNT = 12;

/* -------------------------------------------------------------------------- */
/* Parsing helpers                                                            */
/* -------------------------------------------------------------------------- */

function parseNullableNumber(
  value: string | undefined
): number | null {
  if (
    value === undefined ||
    value.trim() === ""
  ) {
    return null;
  }

  const parsed =
    Number(
      value.trim()
    );

  return Number.isFinite(
    parsed
  )
    ? parsed
    : null;
}

function protocolFromNumber(
  value: number
): CapturedProtocol {
  switch (value) {
    case 6:
      return "tcp";

    case 17:
      return "udp";

    case 1:
      return "icmp";

    default:
      return "other";
  }
}

function parseTcpFlags(
  value: string | undefined
): number {
  if (
    value === undefined ||
    value.trim() === ""
  ) {
    return 0;
  }

  const normalized =
    value.trim();

  if (
    normalized
      .toLowerCase()
      .startsWith("0x")
  ) {
    const parsed =
      Number.parseInt(
        normalized,
        16
      );

    return Number.isFinite(
      parsed
    )
      ? parsed
      : 0;
  }

  const parsed =
    Number(
      normalized
    );

  return Number.isFinite(
    parsed
  )
    ? parsed
    : 0;
}

function isValidIPv4(
  value: string
): boolean {
  const parts =
    value.split(".");

  if (
    parts.length !== 4
  ) {
    return false;
  }

  return parts.every(
    (part) => {
      if (
        !/^\d+$/.test(
          part
        )
      ) {
        return false;
      }

      const numeric =
        Number(
          part
        );

      return (
        Number.isInteger(
          numeric
        ) &&
        numeric >= 0 &&
        numeric <= 255
      );
    }
  );
}

function normalizeIp(
  value: string | undefined
): string | null {
  if (
    value === undefined
  ) {
    return null;
  }

  const normalized =
    value.trim();

  if (
    normalized === ""
  ) {
    return null;
  }

  return isValidIPv4(
    normalized
  )
    ? normalized
    : null;
}

function normalizeMac(
  value: string | undefined
): string | null {
  if (
    value === undefined
  ) {
    return null;
  }

  const normalized =
    value.trim();

  return normalized.length > 0
    ? normalized
    : null;
}

/* -------------------------------------------------------------------------- */
/* Packet parser                                                              */
/* -------------------------------------------------------------------------- */

function parsePacketLine(
  line: string
): CapturedPacket | null {
  const fields =
    line.split("|");

  if (
    fields.length <
    EXPECTED_FIELD_COUNT
  ) {
    return null;
  }

  const [
    timestampText,
    sourceMacText,
    destinationMacText,
    sourceIpText,
    destinationIpText,
    protocolText,
    tcpSourcePortText,
    tcpDestinationPortText,
    tcpFlagsText,
    udpSourcePortText,
    udpDestinationPortText,
    frameLengthText,
  ] = fields;

  const timestamp =
    Number(
      timestampText
    );

  if (
    !Number.isFinite(
      timestamp
    )
  ) {
    return null;
  }

  const frameLength =
    Number(
      frameLengthText
    );

  if (
    !Number.isFinite(
      frameLength
    ) ||
    frameLength < 0
  ) {
    return null;
  }

  const ipProtocol =
    Number(
      protocolText
    );

  /*
   * Non-IP packets have no ip.proto value.
   * They are not useful to the current IP-based flow pipeline.
   */
  if (
    !Number.isFinite(
      ipProtocol
    )
  ) {
    return null;
  }

  const protocol =
    protocolFromNumber(
      ipProtocol
    );

  const sourceIp =
    normalizeIp(
      sourceIpText
    );

  const destinationIp =
    normalizeIp(
      destinationIpText
    );

  /*
   * Current NetworkFlow processing is IPv4-based.
   */
  if (
    !sourceIp ||
    !destinationIp
  ) {
    return null;
  }

  const sourceMac =
    normalizeMac(
      sourceMacText
    );

  const destinationMac =
    normalizeMac(
      destinationMacText
    );

  let sourcePort:
    number | null = null;

  let destinationPort:
    number | null = null;

  if (
    protocol === "tcp"
  ) {
    sourcePort =
      parseNullableNumber(
        tcpSourcePortText
      );

    destinationPort =
      parseNullableNumber(
        tcpDestinationPortText
      );
  } else if (
    protocol === "udp"
  ) {
    sourcePort =
      parseNullableNumber(
        udpSourcePortText
      );

    destinationPort =
      parseNullableNumber(
        udpDestinationPortText
      );
  }

  const tcpFlags =
    protocol === "tcp"
      ? parseTcpFlags(
          tcpFlagsText
        )
      : 0;

  return {
    timestamp,

    sourceIp,
    destinationIp,

    sourcePort,
    destinationPort,

    protocol,

    tcpFlags,

    length:
      Math.trunc(
        frameLength
      ),

    sourceMac,
    destinationMac,
  };
}

/* -------------------------------------------------------------------------- */
/* TShark command construction                                                 */
/* -------------------------------------------------------------------------- */

function buildTSharkArguments(
  options: TSharkCaptureOptions
): string[] {
  const args: string[] = [
    /*
     * Capture interface.
     */
    "-i",
    String(
      options.interfaceId
    ),

    /*
     * IMPORTANT:
     *
     * Force line-buffered output.
     *
     * This is essential when stdout is being consumed
     * through a Node.js pipe/readline interface.
     */
    "-l",

    /*
     * Do not resolve addresses/names while capturing.
     *
     * This makes output faster and deterministic.
     */
    "-n",

    /*
     * Field-oriented output.
     */
    "-T",
    "fields",

    /*
     * Exactly one record per line.
     */
    "-E",
    "separator=|",

    /*
     * Do not emit a header row.
     */
    "-E",
    "header=n",

    /*
     * First occurrence of each field.
     */
    "-E",
    "occurrence=f",

    /*
     * Fields consumed by parsePacketLine().
     */
    "-e",
    "frame.time_epoch",

    "-e",
    "eth.src",

    "-e",
    "eth.dst",

    "-e",
    "ip.src",

    "-e",
    "ip.dst",

    "-e",
    "ip.proto",

    "-e",
    "tcp.srcport",

    "-e",
    "tcp.dstport",

    "-e",
    "tcp.flags",

    "-e",
    "udp.srcport",

    "-e",
    "udp.dstport",

    "-e",
    "frame.len",
  ];

  if (
    options.captureFilter &&
    options.captureFilter.trim()
      .length > 0
  ) {
    args.push(
      "-f",
      options.captureFilter.trim()
    );
  }

  return args;
}

/* -------------------------------------------------------------------------- */
/* Capture implementation                                                      */
/* -------------------------------------------------------------------------- */

export function createTSharkCapture(
  options: TSharkCaptureOptions,
  onPacket: PacketHandler,
  onError?: CaptureErrorHandler,
  onStopped?: CaptureStoppedHandler
): TSharkCapture {
  const tsharkPath =
    options.tsharkPath ??
    DEFAULT_TSHARK_PATH;

  let childProcess:
    | TSharkProcess
    | null = null;

  let stdoutReader:
    | Interface
    | null = null;

  let running =
    false;

  let stopRequested =
    false;

  /*
   * Prevent multiple onStopped() callbacks.
   */
  let stoppedNotified =
    false;

  /**
   * Report an error safely.
   */
  function reportError(
    error: unknown
  ): void {
    const normalized =
      error instanceof Error
        ? error
        : new Error(
            String(error)
          );

    try {
      onError?.(
        normalized
      );
    } catch {
      /*
       * User error callbacks must never
       * break the capture lifecycle.
       */
    }
  }

  /**
   * Notify that capture stopped exactly once.
   */
  function notifyStopped(): void {
    if (
      stoppedNotified
    ) {
      return;
    }

    stoppedNotified =
      true;

    try {
      onStopped?.();
    } catch (error) {
      reportError(
        error
      );
    }
  }

  /**
   * Start TShark.
   */
  function start(): void {
    if (
      running
    ) {
      return;
    }

    stoppedNotified =
      false;

    stopRequested =
      false;

    const args =
      buildTSharkArguments(
        options
      );

    let spawned:
      TSharkProcess;

    try {
      /*
       * Explicit stdin/stdout/stderr configuration keeps
       * the Node child-process types correct.
       */
      spawned =
        spawn(
          tsharkPath,
          args,
          {
            windowsHide:
              true,

            stdio: [
              "ignore",
              "pipe",
              "pipe",
            ],
          }
        );
    } catch (error) {
      running =
        false;

      reportError(
        error
      );

      notifyStopped();

      return;
    }

    childProcess =
      spawned;

    running =
      true;

    stdoutReader =
      createInterface({
        input:
          spawned.stdout,

        crlfDelay:
          Infinity,
      });

    /*
     * TShark stdout is line-buffered because of -l above.
     */
    stdoutReader.on(
      "line",
      (line: string) => {
        if (
          stopRequested
        ) {
          return;
        }

        const trimmed =
          line.trim();

        if (
          trimmed.length ===
          0
        ) {
          return;
        }

        const packet =
          parsePacketLine(
            trimmed
          );

        if (!packet) {
          return;
        }

        try {
          onPacket(
            packet
          );
        } catch (error) {
          reportError(
            error
          );
        }
      }
    );

    /*
     * TShark informational messages normally arrive through
     * stderr, including "Capturing on ...".
     *
     * We intentionally do not treat ordinary stderr output
     * as an application error.
     */
    spawned.stderr.on(
      "data",
      (_chunk: Buffer) => {
        /*
         * Intentionally ignored.
         */
      }
    );

    /*
     * Child-process startup/runtime error.
     */
    spawned.once(
      "error",
      (error: Error) => {
        running =
          false;

        reportError(
          error
        );
      }
    );

    /*
     * Child-process termination.
     */
    spawned.once(
      "close",
      () => {
        running =
          false;

        stdoutReader?.close();

        stdoutReader =
          null;

        if (
          childProcess ===
          spawned
        ) {
          childProcess =
            null;
        }

        notifyStopped();
      }
    );
  }

  /**
   * Stop TShark.
   */
  function stop(): void {
    const currentProcess =
      childProcess;

    stopRequested =
      true;

    if (
      stdoutReader
    ) {
      stdoutReader.close();
      stdoutReader =
        null;
    }

    if (
      !currentProcess
    ) {
      running =
        false;

      childProcess =
        null;

      notifyStopped();

      return;
    }

    running =
      false;

    try {
      currentProcess.kill();
    } catch {
      /*
       * The process may already have exited.
       */
    }

    if (
      childProcess ===
      currentProcess
    ) {
      childProcess =
        null;
    }
  }

  /**
   * Return capture state.
   */
  function isRunning(): boolean {
    return running;
  }

  return {
    start,
    stop,
    isRunning,
  };
}