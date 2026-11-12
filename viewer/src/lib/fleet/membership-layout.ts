type Point = { x: number; y: number };
type MembershipRow = { machineId: string; memberships: { flockId: string }[] };
type Box = { x: number; y: number; width: number; height: number };

const cross = (a: Point, b: Point, c: Point) => (b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x);

function hull(points: Point[]): Point[] {
  const sorted = [...points].sort((a, b) => a.x - b.x || a.y - b.y);
  const half = (list: Point[]) => {
    const result: Point[] = [];
    for (const p of list) {
      while (result.length > 1 && cross(result[result.length - 2], result[result.length - 1], p) <= 0) result.pop();
      result.push(p);
    }
    return result.slice(0, -1);
  };
  return [...half(sorted), ...half(sorted.reverse())];
}

function outline(box: Box, padding: number): Point[] {
  const radius = 16 + padding;
  return [
    { x: box.x + 16, y: box.y + 16 }, { x: box.x + box.width - 16, y: box.y + 16 },
    { x: box.x + box.width - 16, y: box.y + box.height - 16 }, { x: box.x + 16, y: box.y + box.height - 16 },
  ].flatMap((p, corner) => Array.from({ length: 5 }, (_, i) => {
    const angle = (corner * 90 + 180 + i * 22.5) * Math.PI / 180;
    return { x: p.x + Math.cos(angle) * radius, y: p.y + Math.sin(angle) * radius };
  }));
}

// Separating axes include both polygons, so even a contour crossing a nonmember's card is rejected.
function intersects(a: Point[], b: Point[]): boolean {
  for (const polygon of [a, b]) {
    for (let i = 0; i < polygon.length; i++) {
      const p = polygon[i], q = polygon[(i + 1) % polygon.length];
      const axis = { x: p.y - q.y, y: q.x - p.x };
      const project = (points: Point[]) => points.map((v) => v.x * axis.x + v.y * axis.y);
      const aa = project(a), bb = project(b);
      if (Math.max(...aa) < Math.min(...bb) || Math.max(...bb) < Math.min(...aa)) return false;
    }
  }
  return true;
}

const path = (points: Point[]) => `${points.map((p, i) => `${i ? "L" : "M"}${p.x.toFixed(2)},${p.y.toFixed(2)}`).join(" ")} Z`;

export function membershipField(rows: MembershipRow[], flockIds: string[], availableWidth: number) {
  const width = Math.max(300, availableWidth);
  const columns = Math.max(1, Math.min(4, Math.floor(width / 250), rows.length));
  const cellWidth = width / columns, cellHeight = 156;
  const sorted = [...rows].sort((a, b) => {
    const key = (r: MembershipRow) => r.memberships.map((f) => f.flockId).sort().join("\0");
    return key(a).localeCompare(key(b)) || a.machineId.localeCompare(b.machineId);
  });
  let height = 0;
  const nodes: (MembershipRow & Box)[] = [];
  for (let i = 0; i < sorted.length; i += columns) {
    const group = sorted.slice(i, i + columns);
    const cardWidth = cellWidth - 68;
    const cardHeight = Math.max(88, ...group.map((row) =>
      Math.ceil(row.machineId.length / Math.max(1, Math.floor((cardWidth - 16) / 7))) * 16
      + Math.ceil(row.memberships.length / Math.max(1, Math.floor((cardWidth - 16) / 28))) * 18 + 28));
    group.forEach((row, column) => nodes.push({
      ...row, x: column * cellWidth + 34, y: height + 34, width: cardWidth, height: cardHeight,
    }));
    height += cardHeight + 68;
  }
  const contours = flockIds.map((flockId, index) => {
    const members = nodes.filter((n) => n.memberships.some((f) => f.flockId === flockId));
    const padding = 8 + 18 * index / Math.max(1, flockIds.length - 1);
    if (!members.length) return { flockId, paths: [], split: false };
    const boundary = hull(members.flatMap((n) => outline(n, padding)));
    const outsiders = nodes.filter((n) => !n.memberships.some((f) => f.flockId === flockId));
    const safe = (polygon: Point[]) => !outsiders.some((n) => intersects(polygon, outline(n, 3)));
    if (safe(boundary)) return { flockId, paths: [path(boundary)], split: false };
    // Keep compatible nearby members together instead of splitting the whole flock into individual rings.
    const regions: Point[][] = [];
    for (const member of members) {
      const points = outline(member, padding);
      const index = regions.findIndex((region) => safe(hull([...region, ...points])));
      if (index < 0) regions.push(points);
      else regions[index] = hull([...regions[index], ...points]);
    }
    return { flockId, paths: regions.map(path), split: true };
  });
  return { width, height: Math.max(cellHeight, height), nodes, contours };
}
