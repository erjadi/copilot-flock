import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import ts from "typescript";

const source = fs.readFileSync(new URL("../src/lib/fleet/membership-layout.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } });
const { membershipField } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);
const row = (machineId, ...ids) => ({ machineId, memberships: ids.map((flockId) => ({ flockId })) });
const polygon = (d) => [...d.matchAll(/[ML](-?[\d.]+),(-?[\d.]+)/g)].map((m) => ({ x: +m[1], y: +m[2] }));
const inside = (p, points) => {
  let result = false;
  for (let i = 0, j = points.length - 1; i < points.length; j = i++) {
    const a = points[i], b = points[j];
    if ((a.y > p.y) !== (b.y > p.y) && p.x < (b.x - a.x) * (p.y - a.y) / (b.y - a.y) + a.x) result = !result;
  }
  return result;
};

test("overlapping, identical and singleton memberships enclose exactly their machines at wide and narrow sizes", () => {
  const rows = [
    row("alpha", "root", "personal", "team"),
    row("beta", "root", "work", "team", "guest"),
    row("gamma", "root", "personal"),
    row("delta", "root", "work"),
    row("epsilon", "other-owner"),
    row("zeta", "root", "work"),
  ];
  const ids = ["root", "personal", "work", "team", "guest", "other-owner", "empty"];
  for (const width of [300, 390, 600, 1200]) {
    const field = membershipField(rows, ids, width);
    assert.equal(field.nodes.length, rows.length);
    for (const contour of field.contours) {
      for (const node of field.nodes) {
        const isMember = node.memberships.some((f) => f.flockId === contour.flockId);
        const points = [
          { x: node.x + node.width / 2, y: node.y + node.height / 2 },
          { x: node.x + 17, y: node.y + 17 },
          { x: node.x + node.width - 17, y: node.y + node.height - 17 },
        ];
        for (const p of points) assert.equal(contour.paths.some((d) => inside(p, polygon(d))), isMember, `${width}: ${contour.flockId}/${node.machineId}`);
      }
    }
    assert.deepEqual(field.contours.find((c) => c.flockId === "empty").paths, []);
  }
});

test("unsafe enclosures split rather than swallowing intervening nonmembers", () => {
  const rows = [row("a", "flock", "a"), row("b", "b"), row("c", "flock", "z")];
  const field = membershipField(rows, ["flock", "a", "b", "z"], 300);
  const contour = field.contours[0];
  assert.equal(contour.split, true);
  assert.equal(contour.paths.length, 2);
  const outsider = field.nodes.find((n) => n.machineId === "b");
  assert.equal(contour.paths.some((d) => inside({ x: outsider.x + 20, y: outsider.y + 20 }, polygon(d))), false);
});

test("long identifiers and many memberships stay inside scrollable field bounds without overlapping cards", () => {
  const ids = Array.from({ length: 35 }, (_, i) => `owner/team-${i}`);
  const rows = [row("MACHINE-".repeat(20), ...ids), row("short", ids[0]), row("third", ids[1])];
  const field = membershipField(rows, ids, 300);
  assert.ok(field.height > 468);
  for (let i = 0; i < field.nodes.length; i++) {
    const node = field.nodes[i];
    assert.ok(node.x >= 0 && node.x + node.width <= field.width);
    assert.ok(node.y >= 0 && node.y + node.height <= field.height);
    if (i) assert.ok(node.y > field.nodes[i - 1].y + field.nodes[i - 1].height);
  }
  assert.deepEqual(membershipField([...rows].reverse(), ids, 300), field);
});

test("contours leave holes and intervening cards out across all four-node membership combinations", () => {
  for (let mask = 1; mask < 16; mask++) {
    const rows = Array.from({ length: 4 }, (_, i) => row(`machine-${i}`, `sort-${i}`, ...(mask & (1 << i) ? ["target"] : [])));
    for (const width of [300, 600, 1200]) {
      const field = membershipField(rows, ["target"], width);
      for (const n of field.nodes) {
        const member = n.memberships.some((f) => f.flockId === "target");
        for (const dx of [17, n.width / 2, n.width - 17]) {
          for (const dy of [17, n.height / 2, n.height - 17]) {
            assert.equal(field.contours[0].paths.some((d) => inside({ x: n.x + dx, y: n.y + dy }, polygon(d))), member);
          }
        }
      }
    }
  }
});
