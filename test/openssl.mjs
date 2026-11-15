import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

export function resolveOpenSsl({
  platform = process.platform, env = process.env,
  isFile = (filename) => fs.existsSync(filename) && fs.statSync(filename).isFile(),
} = {}) {
  const windows = platform === "win32";
  const paths = windows ? path.win32 : path.posix;
  const directories = String(env.PATH || "").split(windows ? ";" : ":")
    .map((entry) => entry.trim().replace(/^"(.*)"$/, "$1")).filter(Boolean);
  const executable = windows ? "openssl.exe" : "openssl";
  const fromPath = directories.map((directory) => paths.join(directory, executable)).find(isFile);
  if (fromPath) return fromPath;
  if (windows) {
    const git = directories.map((directory) => paths.join(directory, "git.exe")).find(isFile);
    const roots = [
      ...(git ? [paths.resolve(paths.dirname(git), ".."), paths.resolve(paths.dirname(git), "..", "..")] : []),
      paths.join(env.ProgramFiles || "C:\\Program Files", "Git"),
      paths.join(env["ProgramFiles(x86)"] || "C:\\Program Files (x86)", "Git"),
      ...(env.LOCALAPPDATA ? [paths.join(env.LOCALAPPDATA, "Programs", "Git")] : []),
    ];
    for (const root of roots) {
      for (const suffix of [["usr", "bin"], ["clangarm64", "bin"], ["mingw64", "bin"], ["bin"]]) {
        const candidate = paths.join(root, ...suffix, executable);
        if (isFile(candidate)) return candidate;
      }
    }
  }
  throw Object.assign(new Error("OpenSSL is required for isolated TLS qualification; checked PATH and Git for Windows installations"),
    { code: "OPENSSL_UNAVAILABLE" });
}

function selfSignedLocalhost() {
  const der = (tag, ...parts) => {
    const bytes = Buffer.concat(parts);
    let hex = bytes.length.toString(16);
    if (hex.length % 2) hex = `0${hex}`;
    const length = Buffer.from(hex, "hex");
    return Buffer.concat([Buffer.from([tag]), bytes.length < 128 ? Buffer.from([bytes.length])
      : Buffer.concat([Buffer.from([0x80 | length.length]), length]), bytes]);
  };
  const sequence = (...parts) => der(0x30, ...parts);
  const oid = (hex) => der(0x06, Buffer.from(hex, "hex"));
  const algorithm = sequence(oid("2a864886f70d01010b"), der(0x05));
  const name = sequence(der(0x31, sequence(oid("550403"), der(0x0c, Buffer.from("localhost")))));
  const time = (ms) => der(0x18, Buffer.from(new Date(ms).toISOString().replace(/[-:T]/g, "").replace(/\.\d{3}Z$/, "Z")));
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048, publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const serial = crypto.randomBytes(16);
  serial[0] = (serial[0] & 0x7f) | 1;
  const extensions = sequence(
    sequence(oid("551d13"), der(0x01, Buffer.from([0xff])),
      der(0x04, sequence(der(0x01, Buffer.from([0xff]))))),
    sequence(oid("551d11"), der(0x04, sequence(
      der(0x82, Buffer.from("localhost")), der(0x87, Buffer.from([127, 0, 0, 1]))))),
  );
  const now = Date.now();
  const body = sequence(der(0xa0, der(0x02, Buffer.from([2]))), der(0x02, serial),
    algorithm, name, sequence(time(now - 300000), time(now + 86400000)), name,
    publicKey, der(0xa3, extensions));
  const certificate = sequence(body, algorithm, der(0x03, Buffer.from([0]), crypto.sign("sha256", body, privateKey)));
  const pem = `-----BEGIN CERTIFICATE-----\n${certificate.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;
  return { key: privateKey, cert: pem };
}

export function createTlsFixture(root, { run = execFileSync, ...resolutionOptions } = {}) {
  const keyPath = path.join(root, "tls-key.pem");
  const certPath = path.join(root, "tls-cert.pem");
  let executable;
  try { executable = resolveOpenSsl(resolutionOptions); }
  catch (error) {
    if (error.code !== "OPENSSL_UNAVAILABLE") throw error;
    const { key, cert } = selfSignedLocalhost();
    fs.writeFileSync(keyPath, key, { mode: 0o600 });
    fs.writeFileSync(certPath, cert, { mode: 0o600 });
  }
  if (executable) {
    run(executable, ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyPath,
      "-out", certPath, "-days", "1", "-subj", "/CN=localhost",
      "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], { stdio: "ignore", windowsHide: true });
  }
  return { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath), certPath };
}
