/**
 * AEGIS-XAI MITRE ATT&CK Mapper
 *
 * Maps attack families to MITRE ATT&CK tactics and techniques.
 * Data-driven mapping from configuration — not hard-coded logic.
 */

export interface MitreMapping {
  tacticId: string;
  tacticName: string;
  techniqueId?: string;
  techniqueName?: string;
  description: string;
  url: string;
}

/**
 * Attack family → MITRE ATT&CK mapping table.
 * Source: MITRE ATT&CK Framework v14
 */
export const MITRE_MAPPINGS: Record<string, MitreMapping> = {
  DoS: {
    tacticId: "TA0040",
    tacticName: "Impact",
    techniqueId: "T1498",
    techniqueName: "Network Denial of Service",
    description:
      "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users.",
    url: "https://attack.mitre.org/tactics/TA0040/",
  },
  Probe: {
    tacticId: "TA0043",
    tacticName: "Reconnaissance",
    techniqueId: "T1046",
    techniqueName: "Network Service Discovery",
    description:
      "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to exploitation.",
    url: "https://attack.mitre.org/tactics/TA0043/",
  },
  R2L: {
    tacticId: "TA0001",
    tacticName: "Initial Access",
    techniqueId: "T1078",
    techniqueName: "Valid Accounts",
    description:
      "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
    url: "https://attack.mitre.org/tactics/TA0001/",
  },
  U2R: {
    tacticId: "TA0004",
    tacticName: "Privilege Escalation",
    techniqueId: "T1068",
    techniqueName: "Exploitation for Privilege Escalation",
    description:
      "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.",
    url: "https://attack.mitre.org/tactics/TA0004/",
  },
  Normal: {
    tacticId: "N/A",
    tacticName: "No Threat",
    description: "Traffic classified as benign network activity.",
    url: "https://attack.mitre.org/",
  },
};

export function getMitreMapping(attackFamily: string): MitreMapping {
  return (
    MITRE_MAPPINGS[attackFamily] || {
      tacticId: "UNKNOWN",
      tacticName: "Unknown",
      description: "Attack family not found in MITRE mapping table.",
      url: "https://attack.mitre.org/",
    }
  );
}

/**
 * Returns all MITRE mappings for reference display.
 */
export function getAllMitreMappings(): Record<string, MitreMapping> {
  return { ...MITRE_MAPPINGS };
}
