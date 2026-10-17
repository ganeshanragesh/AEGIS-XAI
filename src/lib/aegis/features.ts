/**
 * AEGIS-XAI Feature Schema
 *
 * 41 NSL-KDD-style structural features.
 *
 * This file is the single authoritative feature registry
 * used by the real packet/flow pipeline and the ML pipeline.
 *
 * IMPORTANT:
 * The order of FEATURE_NAMES MUST remain unchanged because
 * model inference depends on the exact training feature order.
 */

export interface NetworkFlow {
  // Network identity
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;

  // Basic flow measurements
  duration: number;
  srcBytes: number;
  dstBytes: number;
  srcPackets: number;
  dstPackets: number;

  // Service / TCP state
  service: string;
  flag: string;

  // Basic NSL-KDD structural features
  land: boolean;
  wrongFragment: number;
  urgent: number;
  hot: number;

  // Host/application features
  numFailedLogins: number;
  loggedIn: boolean;
  numCompromised: number;
  rootShell: boolean;
  suAttempted: boolean;
  numRoot: number;
  numFileCreations: number;
  numShells: number;
  numAccessFiles: number;
  numOutboundCmds: number;
  isHostLogin: boolean;
  isGuestLogin: boolean;

  // Recent-traffic context
  count: number;
  srvCount: number;
  serrorRate: number;
  srvSerrorRate: number;
  rerrorRate: number;
  srvRerrorRate: number;
  sameSrvRate: number;
  diffSrvRate: number;
  srvDiffHostRate: number;

  // Destination-host context
  dstHostCount: number;
  dstHostSrvCount: number;
  dstHostSameSrvRate: number;
  dstHostDiffSrvRate: number;
  dstHostSameSrcPortRate: number;
  dstHostSrvDiffHostRate: number;
  dstHostSerrorRate: number;
  dstHostSrvSerrorRate: number;
  dstHostRerrorRate: number;
  dstHostSrvRerrorRate: number;
}

/**
 * Authoritative 41-feature ordering.
 *
 * NEVER reorder this array without retraining every model
 * that depends on this representation.
 */
export const FEATURE_NAMES: (keyof NetworkFlow)[] = [
  "duration",                  // 0
  "protocol",                  // 1
  "service",                   // 2
  "flag",                      // 3
  "srcBytes",                  // 4
  "dstBytes",                  // 5
  "land",                      // 6
  "wrongFragment",             // 7
  "urgent",                    // 8
  "hot",                       // 9
  "numFailedLogins",           // 10
  "loggedIn",                  // 11
  "numCompromised",            // 12
  "rootShell",                 // 13
  "suAttempted",               // 14
  "numRoot",                   // 15
  "numFileCreations",          // 16
  "numShells",                 // 17
  "numAccessFiles",             // 18
  "numOutboundCmds",           // 19
  "isHostLogin",               // 20
  "isGuestLogin",              // 21
  "count",                     // 22
  "srvCount",                  // 23
  "serrorRate",                // 24
  "srvSerrorRate",             // 25
  "rerrorRate",                // 26
  "srvRerrorRate",             // 27
  "sameSrvRate",               // 28
  "diffSrvRate",               // 29
  "srvDiffHostRate",            // 30
  "dstHostCount",              // 31
  "dstHostSrvCount",             // 32
  "dstHostSameSrvRate",         // 33
  "dstHostDiffSrvRate",         // 34
  "dstHostSameSrcPortRate",     // 35
  "dstHostSrvDiffHostRate",     // 36
  "dstHostSerrorRate",          // 37
  "dstHostSrvSerrorRate",       // 38
  "dstHostRerrorRate",          // 39
  "dstHostSrvRerrorRate",       // 40
];

/**
 * Human-readable descriptions for the 41 features.
 */
export const FEATURE_DESCRIPTIONS: Record<
  string,
  string
> = {
  duration:
    "Duration of connection (seconds)",

  protocol:
    "Network protocol (TCP/UDP/ICMP)",

  service:
    "Network service on destination (e.g. http, ftp)",

  flag:
    "Connection status flag (e.g. SF, S0, REJ)",

  srcBytes:
    "Bytes from source to destination",

  dstBytes:
    "Bytes from destination to source",

  land:
    "1 if connection is from/to same host/port; 0 otherwise",

  wrongFragment:
    "Number of wrong fragments",

  urgent:
    "Number of urgent packets",

  hot:
    "Number of hot indicators",

  numFailedLogins:
    "Number of failed login attempts",

  loggedIn:
    "1 if successfully logged in; 0 otherwise",

  numCompromised:
    "Number of compromised conditions",

  rootShell:
    "1 if root shell is obtained; 0 otherwise",

  suAttempted:
    "1 if su root command attempted; 0 otherwise",

  numRoot:
    "Number of root accesses",

  numFileCreations:
    "Number of file creation operations",

  numShells:
    "Number of shell prompts",

  numAccessFiles:
    "Number of operations on access control files",

  numOutboundCmds:
    "Number of outbound commands in ftp session",

  isHostLogin:
    "1 if login belongs to host list; 0 otherwise",

  isGuestLogin:
    "1 if login is guest login; 0 otherwise",

  count:
    "Connections to same host in past 2 seconds",

  srvCount:
    "Connections to same service in past 2 seconds",

  serrorRate:
    "% connections with SYN errors",

  srvSerrorRate:
    "% same-service connections with SYN errors",

  rerrorRate:
    "% connections with REJ errors",

  srvRerrorRate:
    "% same-service connections with REJ errors",

  sameSrvRate:
    "% connections to same service",

  diffSrvRate:
    "% connections to different services",

  srvDiffHostRate:
    "% same-service connections to different hosts",

  dstHostCount:
    "Connections with same destination host (100-connection window)",

  dstHostSrvCount:
    "Connections with same host and service (100-connection window)",

  dstHostSameSrvRate:
    "% connections to same service (host window)",

  dstHostDiffSrvRate:
    "% connections to different services (host window)",

  dstHostSameSrcPortRate:
    "% connections with same source port (host window)",

  dstHostSrvDiffHostRate:
    "% same-service connections with different source hosts",

  dstHostSerrorRate:
    "% connections with SYN errors (host window)",

  dstHostSrvSerrorRate:
    "% same-service connections with SYN errors (host window)",

  dstHostRerrorRate:
    "% connections with REJ errors (host window)",

  dstHostSrvRerrorRate:
    "% same-service connections with REJ errors (host window)",
};

/**
 * Protocol encoding.
 */
export const PROTOCOL_MAP: Record<
  string,
  number
> = {
  tcp: 0,
  udp: 1,
  icmp: 2,
};

/**
 * Service encoding.
 *
 * Port 3000 is included as HTTP because your AEGIS
 * web application is actually exposed on TCP/3000.
 */
export const SERVICE_MAP: Record<
  string,
  number
> = {
  http: 0,
  ftp: 1,
  smtp: 2,
  ssh: 3,
  dns: 4,
  telnet: 5,
  pop3: 6,
  imap: 7,
  https: 8,
  ftp_data: 9,
  private: 10,
  other: 11,
  domain_u: 12,
  auth: 13,
  finger: 14,
  eco_i: 15,
  ntp_u: 16,
  ecr_i: 17,
  nntp: 18,
  urp_i: 19,
};

/**
 * NSL-KDD connection-state encoding.
 */
export const FLAG_MAP: Record<
  string,
  number
> = {
  SF: 0,
  S0: 1,
  REJ: 2,
  RSTO: 3,
  RSTR: 4,
  SH: 5,
  S1: 6,
  S2: 7,
  S3: 8,
  OTH: 9,
};

/**
 * Normalize a categorical value for lookup.
 */
function normalizeCategory(
  value: string
): string {
  return value.trim().toLowerCase();
}

/**
 * Encode a categorical value using a case-insensitive
 * lookup while preserving uppercase FLAG_MAP keys.
 *
 * Unknown values use the "other" category when available.
 */
function encode(
  map: Record<string, number>,
  value: string
): number {
  const normalized =
    normalizeCategory(value);

  for (
    const [
      key,
      encoded,
    ] of Object.entries(map)
  ) {
    if (
      key.toLowerCase() ===
      normalized
    ) {
      return encoded;
    }
  }

  return map.other ?? 11;
}

/**
 * Convert a boolean to the numeric representation expected
 * by the feature vector.
 */
function booleanToNumber(
  value: boolean
): number {
  return value ? 1 : 0;
}

/**
 * Extract the authoritative 41-element numerical vector.
 *
 * This is the ONLY feature encoding path that should be used
 * by model inference.
 */
export function extractFeatureVector(
  flow: NetworkFlow
): number[] {
  const vector: number[] = [
    flow.duration,
    encode(
      PROTOCOL_MAP,
      flow.protocol
    ),
    encode(
      SERVICE_MAP,
      flow.service
    ),
    encode(
      FLAG_MAP,
      flow.flag
    ),
    flow.srcBytes,
    flow.dstBytes,
    booleanToNumber(flow.land),
    flow.wrongFragment,
    flow.urgent,
    flow.hot,
    flow.numFailedLogins,
    booleanToNumber(flow.loggedIn),
    flow.numCompromised,
    booleanToNumber(flow.rootShell),
    booleanToNumber(flow.suAttempted),
    flow.numRoot,
    flow.numFileCreations,
    flow.numShells,
    flow.numAccessFiles,
    flow.numOutboundCmds,
    booleanToNumber(flow.isHostLogin),
    booleanToNumber(flow.isGuestLogin),
    flow.count,
    flow.srvCount,
    flow.serrorRate,
    flow.srvSerrorRate,
    flow.rerrorRate,
    flow.srvRerrorRate,
    flow.sameSrvRate,
    flow.diffSrvRate,
    flow.srvDiffHostRate,
    flow.dstHostCount,
    flow.dstHostSrvCount,
    flow.dstHostSameSrvRate,
    flow.dstHostDiffSrvRate,
    flow.dstHostSameSrcPortRate,
    flow.dstHostSrvDiffHostRate,
    flow.dstHostSerrorRate,
    flow.dstHostSrvSerrorRate,
    flow.dstHostRerrorRate,
    flow.dstHostSrvRerrorRate,
  ];

  if (
    vector.length !==
    FEATURE_NAMES.length
  ) {
    throw new Error(
      `Feature vector length mismatch: expected ${FEATURE_NAMES.length}, received ${vector.length}`
    );
  }

  return vector;
}

/**
 * Derive a service name from a destination port.
 *
 * This function is used by the real packet-capture pipeline.
 */
export function portToService(
  port: number,
  protocol: string
): string {
  const normalizedProtocol =
    protocol
      .trim()
      .toLowerCase();

  if (
    normalizedProtocol ===
    "icmp"
  ) {
    return "eco_i";
  }

  if (
    normalizedProtocol ===
    "udp"
  ) {
    const udpServices: Record<
      number,
      string
    > = {
      53: "domain_u",
      123: "ntp_u",
      67: "private",
      68: "private",
    };

    return (
      udpServices[port] ??
      "other"
    );
  }

  if (
    normalizedProtocol ===
    "tcp"
  ) {
    const tcpServices: Record<
      number,
      string
    > = {
      20: "ftp_data",
      21: "ftp",
      22: "ssh",
      23: "telnet",
      25: "smtp",
      53: "dns",
      79: "finger",
      80: "http",
      110: "pop3",
      119: "nntp",
      123: "ntp_u",
      143: "imap",
      443: "https",
      3306: "private",
      5432: "private",
      8080: "http",
      8443: "https",

      /*
       * AEGIS-XAI web application.
       */
      3000: "http",
    };

    return (
      tcpServices[port] ??
      "other"
    );
  }

  return "other";
}

/**
 * Infer an NSL-KDD-style TCP connection flag from
 * observed TCP state.
 */
export function inferFlag(
  synSent: boolean,
  ackReceived: boolean,
  finSeen: boolean,
  rstSeen: boolean,
  rejected: boolean
): string {
  /*
   * Explicit reset/rejection takes precedence.
   */
  if (rejected) {
    return "REJ";
  }

  /*
   * Reset without a normal established flow.
   */
  if (rstSeen) {
    return "RSTO";
  }

  /*
   * Successful connection that closed cleanly.
   */
  if (
    synSent &&
    ackReceived &&
    finSeen
  ) {
    return "SF";
  }

  /*
   * SYN observed without handshake completion.
   */
  if (
    synSent &&
    !ackReceived
  ) {
    return "S0";
  }

  /*
   * SYN + ACK / established connection
   * with no FIN observed yet.
   */
  if (
    synSent &&
    ackReceived &&
    !finSeen
  ) {
    return "S1";
  }

  /*
   * Fallback for states that do not match the
   * simplified categories above.
   */
  return "OTH";
}

/**
 * Verify that the feature registry itself is internally
 * consistent.
 */
export function validateFeatureSchema(): void {
  if (
    FEATURE_NAMES.length !== 41
  ) {
    throw new Error(
      `AEGIS-XAI requires exactly 41 features, found ${FEATURE_NAMES.length}`
    );
  }

  const seen =
    new Set<string>();

  for (
    const featureName of
    FEATURE_NAMES
  ) {
    if (
      seen.has(featureName)
    ) {
      throw new Error(
        `Duplicate feature in FEATURE_NAMES: ${featureName}`
      );
    }

    seen.add(featureName);

    if (
      FEATURE_DESCRIPTIONS[
        featureName
      ] === undefined
    ) {
      throw new Error(
        `Missing feature description: ${featureName}`
      );
    }
  }
}

/**
 * Validate a NetworkFlow before model inference.
 */
export function validateNetworkFlow(
  flow: NetworkFlow
): void {
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

  const numericFields: Array<
    [string, number]
  > = [
    [
      "sourcePort",
      flow.sourcePort,
    ],
    [
      "destinationPort",
      flow.destinationPort,
    ],
    [
      "duration",
      flow.duration,
    ],
    [
      "srcBytes",
      flow.srcBytes,
    ],
    [
      "dstBytes",
      flow.dstBytes,
    ],
    [
      "srcPackets",
      flow.srcPackets,
    ],
    [
      "dstPackets",
      flow.dstPackets,
    ],
    [
      "wrongFragment",
      flow.wrongFragment,
    ],
    [
      "urgent",
      flow.urgent,
    ],
    [
      "hot",
      flow.hot,
    ],
    [
      "numFailedLogins",
      flow.numFailedLogins,
    ],
    [
      "numCompromised",
      flow.numCompromised,
    ],
    [
      "numRoot",
      flow.numRoot,
    ],
    [
      "numFileCreations",
      flow.numFileCreations,
    ],
    [
      "numShells",
      flow.numShells,
    ],
    [
      "numAccessFiles",
      flow.numAccessFiles,
    ],
    [
      "numOutboundCmds",
      flow.numOutboundCmds,
    ],
    [
      "count",
      flow.count,
    ],
    [
      "srvCount",
      flow.srvCount,
    ],
    [
      "serrorRate",
      flow.serrorRate,
    ],
    [
      "srvSerrorRate",
      flow.srvSerrorRate,
    ],
    [
      "rerrorRate",
      flow.rerrorRate,
    ],
    [
      "srvRerrorRate",
      flow.srvRerrorRate,
    ],
    [
      "sameSrvRate",
      flow.sameSrvRate,
    ],
    [
      "diffSrvRate",
      flow.diffSrvRate,
    ],
    [
      "srvDiffHostRate",
      flow.srvDiffHostRate,
    ],
    [
      "dstHostCount",
      flow.dstHostCount,
    ],
    [
      "dstHostSrvCount",
      flow.dstHostSrvCount,
    ],
    [
      "dstHostSameSrvRate",
      flow.dstHostSameSrvRate,
    ],
    [
      "dstHostDiffSrvRate",
      flow.dstHostDiffSrvRate,
    ],
    [
      "dstHostSameSrcPortRate",
      flow.dstHostSameSrcPortRate,
    ],
    [
      "dstHostSrvDiffHostRate",
      flow.dstHostSrvDiffHostRate,
    ],
    [
      "dstHostSerrorRate",
      flow.dstHostSerrorRate,
    ],
    [
      "dstHostSrvSerrorRate",
      flow.dstHostSrvSerrorRate,
    ],
    [
      "dstHostRerrorRate",
      flow.dstHostRerrorRate,
    ],
    [
      "dstHostSrvRerrorRate",
      flow.dstHostSrvRerrorRate,
    ],
  ];

  for (
    const [
      name,
      value,
    ] of numericFields
  ) {
    if (!Number.isFinite(value)) {
      throw new Error(
        `NetworkFlow field "${name}" is not finite`
      );
    }
  }
}

/*
 * Validate the static schema at module load time.
 *
 * This catches accidental feature-registry corruption
 * immediately during development.
 */
validateFeatureSchema();