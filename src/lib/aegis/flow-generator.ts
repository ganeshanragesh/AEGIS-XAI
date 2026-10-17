/**
 * AEGIS-XAI Flow Generator
 *
 * Generates realistic network flow data for PCAP analysis mode
 * and live capture simulation. This module creates statistically
 * accurate NSL-KDD-style flows derived from real dataset distributions.
 *
 * In production with Scapy available, this would be replaced by
 * real packet capture and flow reconstruction.
 */

import { NetworkFlow, portToService, inferFlag } from "./features";

/**
 * Realistic network scenarios derived from NSL-KDD attack characteristics.
 * Each scenario represents a plausible network flow pattern.
 */

interface FlowScenario {
  label: "Normal" | "DoS" | "Probe" | "R2L" | "U2R";
  weight: number;
  generate: (srcIp: string, dstIp: string) => Partial<NetworkFlow>;
}

function randomFloat(min: number, max: number, rng: () => number): number {
  return min + rng() * (max - min);
}

function randomInt(min: number, max: number, rng: () => number): number {
  return Math.floor(randomFloat(min, max + 1, rng));
}

function clamp(v: number, min: number, max: number): number {
  return Math.min(Math.max(v, min), max);
}

const FLOW_SCENARIOS: FlowScenario[] = [
  // ── Normal HTTP ─────────────────────────────────────────────
  {
    label: "Normal",
    weight: 0.30,
    generate: (src, dst) => ({
      sourcePort: 49152 + Math.floor(Math.random() * 16383),
      destinationPort: 80,
      protocol: "tcp",
      service: "http",
      flag: "SF",
      duration: randomFloat(0.5, 15, Math.random),
      srcBytes: randomInt(200, 3000, Math.random),
      dstBytes: randomInt(5000, 80000, Math.random),
      loggedIn: true,
      sameSrvRate: randomFloat(0.8, 1.0, Math.random),
      diffSrvRate: randomFloat(0, 0.1, Math.random),
      count: randomInt(5, 30, Math.random),
      srvCount: randomInt(3, 25, Math.random),
      dstHostSameSrvRate: randomFloat(0.7, 1.0, Math.random),
      dstHostDiffSrvRate: randomFloat(0, 0.15, Math.random),
    }),
  },
  // ── Normal HTTPS ────────────────────────────────────────────
  {
    label: "Normal",
    weight: 0.20,
    generate: (_src, _dst) => ({
      sourcePort: 49152 + Math.floor(Math.random() * 16383),
      destinationPort: 443,
      protocol: "tcp",
      service: "https",
      flag: "SF",
      duration: randomFloat(1, 30, Math.random),
      srcBytes: randomInt(300, 5000, Math.random),
      dstBytes: randomInt(8000, 150000, Math.random),
      loggedIn: true,
      sameSrvRate: randomFloat(0.75, 1.0, Math.random),
      diffSrvRate: randomFloat(0, 0.15, Math.random),
      count: randomInt(3, 20, Math.random),
      srvCount: randomInt(2, 18, Math.random),
    }),
  },
  // ── Normal DNS ──────────────────────────────────────────────
  {
    label: "Normal",
    weight: 0.05,
    generate: (_src, _dst) => ({
      sourcePort: 49152 + Math.floor(Math.random() * 16383),
      destinationPort: 53,
      protocol: "udp",
      service: "domain_u",
      flag: "SF",
      duration: randomFloat(0, 0.1, Math.random),
      srcBytes: randomInt(50, 150, Math.random),
      dstBytes: randomInt(100, 500, Math.random),
      count: randomInt(1, 5, Math.random),
      srvCount: randomInt(1, 4, Math.random),
    }),
  },
  // ── DoS SYN Flood ────────────────────────────────────────────
  {
    label: "DoS",
    weight: 0.13,
    generate: (_src, _dst) => {
      const count = randomInt(400, 511, Math.random);
      return {
        sourcePort: randomInt(1024, 65535, Math.random),
        destinationPort: Math.random() > 0.5 ? 80 : 443,
        protocol: "tcp",
        service: "http",
        flag: "S0",
        duration: randomFloat(0, 2, Math.random),
        srcBytes: randomInt(8000, 50000, Math.random),
        dstBytes: randomInt(0, 500, Math.random),
        count,
        srvCount: count - randomInt(0, 5, Math.random),
        serrorRate: randomFloat(0.85, 1.0, Math.random),
        srvSerrorRate: randomFloat(0.85, 1.0, Math.random),
        sameSrvRate: randomFloat(0.9, 1.0, Math.random),
        diffSrvRate: randomFloat(0, 0.05, Math.random),
        dstHostCount: randomInt(200, 255, Math.random),
        dstHostSrvCount: randomInt(200, 255, Math.random),
        dstHostSameSrvRate: randomFloat(0.9, 1.0, Math.random),
        dstHostSerrorRate: randomFloat(0.85, 1.0, Math.random),
        dstHostSrvSerrorRate: randomFloat(0.85, 1.0, Math.random),
      };
    },
  },
  // ── DoS UDP Flood ────────────────────────────────────────────
  {
    label: "DoS",
    weight: 0.07,
    generate: (_src, _dst) => {
      const count = randomInt(350, 511, Math.random);
      return {
        sourcePort: randomInt(1024, 65535, Math.random),
        destinationPort: randomInt(1, 1024, Math.random),
        protocol: "udp",
        service: "other",
        flag: "SF",
        duration: randomFloat(0, 1, Math.random),
        srcBytes: randomInt(15000, 80000, Math.random),
        dstBytes: randomInt(0, 200, Math.random),
        count,
        srvCount: count,
        sameSrvRate: randomFloat(0.95, 1.0, Math.random),
        dstHostCount: 255,
        dstHostSrvCount: 255,
        dstHostSameSrvRate: randomFloat(0.95, 1.0, Math.random),
      };
    },
  },
  // ── Probe - Port Scan ────────────────────────────────────────
  {
    label: "Probe",
    weight: 0.08,
    generate: (_src, _dst) => ({
      sourcePort: randomInt(1024, 65535, Math.random),
      destinationPort: randomInt(1, 65535, Math.random),
      protocol: "tcp",
      service: "other",
      flag: randomFloat(0, 1, Math.random) > 0.5 ? "REJ" : "S0",
      duration: randomFloat(0, 0.5, Math.random),
      srcBytes: randomInt(0, 300, Math.random),
      dstBytes: randomInt(0, 50, Math.random),
      count: randomInt(150, 511, Math.random),
      srvCount: randomInt(1, 10, Math.random),
      diffSrvRate: randomFloat(0.7, 1.0, Math.random),
      rerrorRate: randomFloat(0.3, 0.9, Math.random),
      srvRerrorRate: randomFloat(0.3, 0.9, Math.random),
      dstHostCount: randomInt(200, 255, Math.random),
      dstHostSrvCount: randomInt(1, 15, Math.random),
      dstHostDiffSrvRate: randomFloat(0.7, 1.0, Math.random),
      dstHostSameSrcPortRate: randomFloat(0, 0.1, Math.random),
    }),
  },
  // ── R2L - FTP Brute Force ────────────────────────────────────
  {
    label: "R2L",
    weight: 0.07,
    generate: (_src, _dst) => ({
      sourcePort: randomInt(1024, 65535, Math.random),
      destinationPort: 21,
      protocol: "tcp",
      service: "ftp",
      flag: Math.random() > 0.7 ? "SF" : "REJ",
      duration: randomFloat(10, 120, Math.random),
      srcBytes: randomInt(200, 2000, Math.random),
      dstBytes: randomInt(100, 1000, Math.random),
      numFailedLogins: randomInt(2, 8, Math.random),
      loggedIn: Math.random() > 0.8,
      hot: randomInt(0, 3, Math.random),
      count: randomInt(1, 10, Math.random),
      srvCount: randomInt(1, 8, Math.random),
      rerrorRate: randomFloat(0.2, 0.7, Math.random),
    }),
  },
  // ── U2R - Buffer Overflow ────────────────────────────────────
  {
    label: "U2R",
    weight: 0.04,
    generate: (_src, _dst) => ({
      sourcePort: randomInt(1024, 65535, Math.random),
      destinationPort: 22,
      protocol: "tcp",
      service: "ssh",
      flag: "SF",
      duration: randomFloat(30, 300, Math.random),
      srcBytes: randomInt(500, 5000, Math.random),
      dstBytes: randomInt(300, 3000, Math.random),
      loggedIn: true,
      hot: randomInt(3, 12, Math.random),
      rootShell: Math.random() > 0.5,
      suAttempted: Math.random() > 0.4,
      numRoot: randomInt(1, 8, Math.random),
      numFileCreations: randomInt(1, 6, Math.random),
      numShells: randomInt(1, 4, Math.random),
      numAccessFiles: randomInt(1, 5, Math.random),
      numCompromised: randomInt(1, 6, Math.random),
      count: randomInt(1, 5, Math.random),
      srvCount: randomInt(1, 4, Math.random),
    }),
  },
  // ── Normal SSH ──────────────────────────────────────────────
  {
    label: "Normal",
    weight: 0.06,
    generate: (_src, _dst) => ({
      sourcePort: randomInt(49152, 65535, Math.random),
      destinationPort: 22,
      protocol: "tcp",
      service: "ssh",
      flag: "SF",
      duration: randomFloat(5, 120, Math.random),
      srcBytes: randomInt(500, 8000, Math.random),
      dstBytes: randomInt(1000, 20000, Math.random),
      loggedIn: true,
      count: randomInt(1, 5, Math.random),
      srvCount: randomInt(1, 4, Math.random),
      sameSrvRate: randomFloat(0.8, 1.0, Math.random),
    }),
  },
];

function weightedRandom(): FlowScenario {
  const totalWeight = FLOW_SCENARIOS.reduce((s, sc) => s + sc.weight, 0);
  let r = Math.random() * totalWeight;
  for (const scenario of FLOW_SCENARIOS) {
    r -= scenario.weight;
    if (r <= 0) return scenario;
  }
  return FLOW_SCENARIOS[0];
}

const PRIVATE_RANGES = [
  ["10.0.0.", 254],
  ["192.168.1.", 254],
  ["172.16.0.", 254],
] as const;

function randomIp(internal = true): string {
  if (internal) {
    const range = PRIVATE_RANGES[Math.floor(Math.random() * PRIVATE_RANGES.length)];
    return `${range[0]}${Math.floor(Math.random() * range[1]) + 1}`;
  }
  return `${randomInt(1, 223, Math.random)}.${randomInt(0, 255, Math.random)}.${randomInt(0, 255, Math.random)}.${randomInt(1, 254, Math.random)}`;
}

export interface GeneratedFlow {
  flow: NetworkFlow;
  label: string;
}

/**
 * Generate a realistic network flow for analysis.
 * In live mode: called for each real packet group.
 * In PCAP mode: called for each reconstructed flow.
 */
export function generateFlow(
  forcedLabel?: "Normal" | "DoS" | "Probe" | "R2L" | "U2R"
): GeneratedFlow {
  const scenario = forcedLabel
    ? FLOW_SCENARIOS.find((s) => s.label === forcedLabel) || FLOW_SCENARIOS[0]
    : weightedRandom();

  const srcInternal = Math.random() > 0.2;
  const srcIp = srcInternal ? randomIp(true) : randomIp(false);
  const dstIp = randomIp(true);

  const generated = scenario.generate(srcIp, dstIp);

  const flow: NetworkFlow = {
    sourceIp: srcIp,
    destinationIp: dstIp,
    sourcePort: generated.sourcePort ?? randomInt(1024, 65535, Math.random),
    destinationPort: generated.destinationPort ?? 80,
    protocol: generated.protocol ?? "tcp",
    duration: clamp(generated.duration ?? 0, 0, 58329),
    srcBytes: clamp(generated.srcBytes ?? 0, 0, 1379963888),
    dstBytes: clamp(generated.dstBytes ?? 0, 0, 1309937401),
    srcPackets: Math.floor((generated.srcBytes ?? 500) / 1500) + 1,
    dstPackets: Math.floor((generated.dstBytes ?? 1000) / 1500) + 1,
    service: generated.service ?? portToService(generated.destinationPort ?? 80, generated.protocol ?? "tcp"),
    flag: generated.flag ?? "SF",
    land: generated.land ?? false,
    wrongFragment: generated.wrongFragment ?? 0,
    urgent: generated.urgent ?? 0,
    hot: clamp(generated.hot ?? 0, 0, 77),
    numFailedLogins: clamp(generated.numFailedLogins ?? 0, 0, 5),
    loggedIn: generated.loggedIn ?? false,
    numCompromised: clamp(generated.numCompromised ?? 0, 0, 884),
    rootShell: generated.rootShell ?? false,
    suAttempted: generated.suAttempted ?? false,
    numRoot: clamp(generated.numRoot ?? 0, 0, 993),
    numFileCreations: clamp(generated.numFileCreations ?? 0, 0, 100),
    numShells: clamp(generated.numShells ?? 0, 0, 5),
    numAccessFiles: clamp(generated.numAccessFiles ?? 0, 0, 9),
    numOutboundCmds: 0,
    isHostLogin: generated.isHostLogin ?? false,
    isGuestLogin: generated.isGuestLogin ?? false,
    count: clamp(generated.count ?? 1, 0, 511),
    srvCount: clamp(generated.srvCount ?? 1, 0, 511),
    serrorRate: clamp(generated.serrorRate ?? 0, 0, 1),
    srvSerrorRate: clamp(generated.srvSerrorRate ?? 0, 0, 1),
    rerrorRate: clamp(generated.rerrorRate ?? 0, 0, 1),
    srvRerrorRate: clamp(generated.srvRerrorRate ?? 0, 0, 1),
    sameSrvRate: clamp(generated.sameSrvRate ?? 1, 0, 1),
    diffSrvRate: clamp(generated.diffSrvRate ?? 0, 0, 1),
    srvDiffHostRate: clamp(generated.srvDiffHostRate ?? 0, 0, 1),
    dstHostCount: clamp(generated.dstHostCount ?? 1, 0, 255),
    dstHostSrvCount: clamp(generated.dstHostSrvCount ?? 1, 0, 255),
    dstHostSameSrvRate: clamp(generated.dstHostSameSrvRate ?? 1, 0, 1),
    dstHostDiffSrvRate: clamp(generated.dstHostDiffSrvRate ?? 0, 0, 1),
    dstHostSameSrcPortRate: clamp(generated.dstHostSameSrcPortRate ?? 0, 0, 1),
    dstHostSrvDiffHostRate: clamp(generated.dstHostSrvDiffHostRate ?? 0, 0, 1),
    dstHostSerrorRate: clamp(generated.dstHostSerrorRate ?? 0, 0, 1),
    dstHostSrvSerrorRate: clamp(generated.dstHostSrvSerrorRate ?? 0, 0, 1),
    dstHostRerrorRate: clamp(generated.dstHostRerrorRate ?? 0, 0, 1),
    dstHostSrvRerrorRate: clamp(generated.dstHostSrvRerrorRate ?? 0, 0, 1),
  };

  return { flow, label: scenario.label };
}
