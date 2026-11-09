import net from "node:net";

export function installLoopbackEgressGuard() {
  const connections = [];
  const denied = [];
  const originalConnect = net.Socket.prototype.connect;
  net.Socket.prototype.connect = function (...args) {
    const first = Array.isArray(args[0]) ? args[0][0] : args[0];
    const host = typeof first === "object" ? first.host : typeof args[1] === "string" ? args[1] : "localhost";
    if (host !== "127.0.0.1") {
      denied.push(host ?? "unspecified");
      throw Object.assign(new Error("Test harness denies non-loopback egress before DNS/connect"), { code: "LAN_TEST_EGRESS" });
    }
    this.once("connect", () => connections.push({ address: this.remoteAddress, port: this.remotePort }));
    return originalConnect.apply(this, args);
  };
  return { connections, denied };
}
