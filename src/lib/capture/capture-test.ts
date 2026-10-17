import { createTSharkCapture } from "./tshark-capture";

const capture = createTSharkCapture(
  {
    interfaceId: 7,
    captureFilter: "host 192.168.2.128",
  },

  (packet) => {
    console.log(
      [
        "[AEGIS REAL PACKET]",
        new Date(packet.timestamp * 1000).toISOString(),
        `${packet.sourceIp ?? "-"}:${packet.sourcePort ?? "-"}`,
        "→",
        `${packet.destinationIp ?? "-"}:${packet.destinationPort ?? "-"}`,
        `protocol=${packet.protocol}`,
        `flags=0x${packet.tcpFlags.toString(16)}`,
        `length=${packet.length}`,
      ].join(" | ")
    );
  },

  (error) => {
    console.error(
      "[AEGIS CAPTURE ERROR]",
      error.message
    );
  },

  () => {
    console.log(
      "[AEGIS CAPTURE] TShark stopped"
    );
  }
);

console.log(
  "[AEGIS CAPTURE] Starting real packet capture..."
);

capture.start();

process.on("SIGINT", () => {
  console.log(
    "\n[AEGIS CAPTURE] Stopping..."
  );

  capture.stop();

  process.exit(0);
});