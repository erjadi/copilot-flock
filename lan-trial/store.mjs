import { DatabaseSync } from "node:sqlite";
import { mkdirSync, chmodSync } from "node:fs";
import path from "node:path";
import { createHash, X509Certificate } from "node:crypto";
import { isIP } from "node:net";

export const LIMITS = Object.freeze({
  frame: 32768, text: 8192, snapshot: 8192, peers: 16, shares: 64,
  claims: 1024, ttl: 120000, connections: 16, requests: 16,
});
export const SESSION = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const fingerprint = (cert) => new X509Certificate(cert).fingerprint256.replaceAll(":", "").toLowerCase();
export const digest = (value) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
export function boundedText(value, bytes = LIMITS.text) {
  return typeof value === "string" && Buffer.byteLength(value) <= bytes;
}
export function privateAddress(address, allowLoopback = false) {
  if (isIP(address) !== 4) return false;
  const [a, b] = address.split(".").map(Number);
  return (allowLoopback && a === 127) || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}
export function endpoint(value, allowLoopback = false) {
  const u = new URL(value);
  if (u.protocol !== "wss:" || !privateAddress(u.hostname, allowLoopback) || !u.port ||
      u.username || u.password || u.search || u.hash || u.pathname !== "/") {
    throw new Error("Use an explicit private IPv4 wss://address:port/ endpoint");
  }
  return u;
}
export function validCertificate(pem) {
  const cert = new X509Certificate(pem);
  const now = Date.now();
  if (now < Date.parse(cert.validFrom) || now >= Date.parse(cert.validTo) ||
      !cert.verify(cert.publicKey)) throw new Error("Invalid or expired self-signed trial certificate");
  return cert;
}

export class Store {
  constructor(dir, { capacity = LIMITS.claims } = {}) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    if (process.platform !== "win32") chmodSync(dir, 0o700);
    this.db = new DatabaseSync(path.join(dir, "trial.sqlite"));
    this.capacity = capacity;
    this.db.exec(`
      PRAGMA journal_mode=WAL;
      PRAGMA synchronous=FULL;
      PRAGMA busy_timeout=1000;
      CREATE TABLE IF NOT EXISTS peers (
        pin TEXT PRIMARY KEY, cert TEXT NOT NULL, endpoint TEXT NOT NULL,
        active INTEGER NOT NULL, revision INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS shares (
        peer TEXT NOT NULL, session TEXT NOT NULL, title TEXT NOT NULL,
        snapshot TEXT NOT NULL, message INTEGER NOT NULL, transcript INTEGER NOT NULL,
        revision INTEGER NOT NULL, PRIMARY KEY(peer, session)
      );
      CREATE TABLE IF NOT EXISTS claims (
        peer TEXT NOT NULL, id TEXT NOT NULL, digest TEXT NOT NULL, expires INTEGER NOT NULL,
        PRIMARY KEY(peer, id)
      );
    `);
    if (process.platform !== "win32") chmodSync(path.join(dir, "trial.sqlite"), 0o600);
  }
  close() { this.db.close(); }
  peers() { return this.db.prepare("SELECT * FROM peers WHERE active=1 ORDER BY pin").all(); }
  peer(pin) { return this.db.prepare("SELECT * FROM peers WHERE pin=? AND active=1").get(pin); }
  approve({ cert, endpoint: url }, independentlyVerifiedPin, allowLoopback = false) {
    validCertificate(cert);
    const pin = fingerprint(cert);
    if (independentlyVerifiedPin !== pin) throw new Error("Independent fingerprint does not match");
    endpoint(url, allowLoopback);
    if (!this.peer(pin) && this.peers().length >= LIMITS.peers) throw new Error("Peer capacity reached");
    if (this.peers().some((p) => p.endpoint === url && p.pin !== pin)) {
      throw new Error("Revoke the old certificate before approving its replacement");
    }
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare(`INSERT INTO peers VALUES (?,?,?,1,1) ON CONFLICT(pin) DO UPDATE SET
        cert=excluded.cert, endpoint=excluded.endpoint, active=1, revision=peers.revision+1`).run(pin, cert, url);
      // Reapproval never restores old grants.
      this.db.prepare("DELETE FROM shares WHERE peer=?").run(pin);
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
    return pin;
  }
  revoke(pin) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("UPDATE peers SET active=0,revision=revision+1 WHERE pin=?").run(pin);
      this.db.prepare("DELETE FROM shares WHERE peer=?").run(pin);
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }
  share(pin, session, { title, snapshot = "", message = false, transcript = false }) {
    if (!this.peer(pin) || !SESSION.test(session) || !boundedText(title, 128) ||
        !boundedText(snapshot, LIMITS.snapshot) || typeof message !== "boolean" ||
        typeof transcript !== "boolean") throw new Error("Invalid local share");
    if (!this.grant(pin, session) && this.shares(pin).length >= LIMITS.shares) throw new Error("Share capacity reached");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare(`INSERT INTO shares VALUES (?,?,?,?,?,?,1) ON CONFLICT(peer,session) DO UPDATE SET
        title=excluded.title,snapshot=excluded.snapshot,message=excluded.message,
        transcript=excluded.transcript,revision=shares.revision+1`).run(pin, session, title, snapshot, +message, +transcript);
      this.db.prepare("UPDATE peers SET revision=revision+1 WHERE pin=?").run(pin);
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }
  unshare(pin, session) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("DELETE FROM shares WHERE peer=? AND session=?").run(pin, session);
      this.db.prepare("UPDATE peers SET revision=revision+1 WHERE pin=?").run(pin);
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }
  grant(pin, session) { return this.db.prepare("SELECT * FROM shares WHERE peer=? AND session=?").get(pin, session); }
  shares(pin) { return this.db.prepare("SELECT * FROM shares WHERE peer=? ORDER BY session LIMIT ?").all(pin, LIMITS.shares); }
  authorization(pin, request) {
    const peer = this.peer(pin);
    if (!peer) return null;
    validCertificate(peer.cert);
    if (request.action === "status" || request.action === "sessions") return `peer:${peer.revision}`;
    const grant = this.grant(pin, request.session);
    if (!grant || !grant[request.action]) return null;
    return `peer:${peer.revision}:share:${grant.revision}:${digest(grant)}`;
  }
  claim(pin, request, now = Date.now()) {
    const hash = digest([request.action, request.session, request.payload, request.expires]);
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("DELETE FROM claims WHERE expires<=?").run(now);
      const old = this.db.prepare("SELECT digest FROM claims WHERE peer=? AND id=?").get(pin, request.id);
      let result;
      if (old) result = old.digest === hash ? "UNKNOWN" : "DENIED";
      else if (this.db.prepare("SELECT count(*) AS n FROM claims").get().n >= this.capacity) result = "BUSY";
      else {
        this.db.prepare("INSERT INTO claims VALUES (?,?,?,?)").run(pin, request.id, hash, request.expires);
        result = "NEW";
      }
      this.db.exec("COMMIT");
      return result;
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }
}
