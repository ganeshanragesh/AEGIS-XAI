/**
 * AEGIS-XAI Event ID Generator
 * Generates unique, traceable event identifiers.
 * Format: AX-YYYYMMDD-NNNNNN
 */

let eventCounter = 0;

export function generateEventId(): string {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const day = String(now.getDate()).padStart(2, "0");
  eventCounter = (eventCounter + 1) % 1000000;
  const seq = String(eventCounter).padStart(6, "0");
  return `AX-${year}${month}${day}-${seq}`;
}

export function generateSessionId(): string {
  const now = Date.now();
  const rand = Math.floor(Math.random() * 0xffffff).toString(16).padStart(6, "0");
  return `SES-${now}-${rand}`;
}
