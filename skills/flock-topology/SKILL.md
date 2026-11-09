---
name: flock-topology
description: Generate and render live Copilot Flock topology diagrams (flowchart LR Mermaid diagrams, Markdown Overlap Matrices, and Dark or Light Warm-Alabaster Bipartite SVG maps) showing all enrolled flocks (<owner>/<flock>[/<machineId>]), online/offline PCs, multi-GPU VRAM telemetry, and shared threads. Use whenever the user asks for a flock topology diagram, network map, or flock visualization.
---

# Copilot Flock Topology Diagram Skill (`flock-topology`)

Use this skill whenever the user asks to visualize, diagram, or map **the flock** (`copilot-flock`), its `<owner>/<flock>[/<machineId>]` hierarchy (`<owner>`, `<owner>/personal`, `<owner>/work`, shared team flocks, or time-bound guest passes), or machine status.

## Architecture and disclosure boundary

These live topology commands are **legacy-profile only**. Fresh Zero-Broker
exposes signed roster membership through native `flock_status`, not online
telemetry or topology. Never invoke legacy discovery as a fallback, treat a
roster member as online, migrate a profile, or use these commands for the
separate LAN trial, which has no topology.

Use only authorized metadata in the selected scope. Owner-scope discovery does
not authorize exporting personal/work metadata to collaborators or guests.
Use placeholders in public examples; do not publish private host/session IDs,
tokens or transcripts. Diagram generation does not authorize profile changes,
network access grants, installation or deployment.

Offline status is not proof of queueing. Show `OFFLINE` or `UNKNOWN` unless an
actual receipt confirms the stage. Distinguish confirmed Service Bus publication,
legacy broker-file persistence and unknown runtime admission; none proves task
execution. Do not infer queue state from a stale topology snapshot.

## Visualization Design Principles (Synced with `TopologyView.tsx` & `FlockOverlap.tsx`)

1. **Semantic Color Palette (Dark `#0b0f19` & Light Warm-Alabaster `#faf9f5`)**:
   | Role / Flock Kind | Dark Mode (`--theme dark`) | Light Mode (`--theme light`) | Stroke / Badge Style |
   | :--- | :--- | :--- | :--- |
   | **Owner Root (`<owner>`)** | Stroke `#38bdf8`, Fill `#0f172a` | Stroke `#64748b`, Fill `#ffffff` | Solid `2px` |
   | **Personal (`<owner>/personal`)** | Emerald `#10b981`, Fill `#0f172a` | Emerald `#059669`, Fill `#ecfdf5` | Solid `2px` |
   | **Work (`<owner>/work`)** | Indigo/Violet `#8b5cf6`, Fill `#0f172a` | Violet `#6d28d9`, Fill `#f5f3ff` | Solid `2px` |
   | **Collaborator Team (`<owner>/<team>`)** | Cyan `#38bdf8`, Fill `#0f172a` | Sky `#0284c7`, Fill `#f0f9ff` | Dashed `stroke-dasharray="6 3"` |
   | **Guest Pass (`<owner>/<flock>/<machineId>`)** | Amber `#f59e0b`, Fill `#0f172a` | Amber `#d97706`, Fill `#fffbeb` | Dotted `stroke-dasharray="3 3"` |
   | **Offline / Unknown** | Slate `#64748b`, Fill `#1e293b` | Slate `#94a3b8`, Fill `#f1f5f9` | Dashed `stroke-dasharray="5 4"`; queue label only with a confirming receipt |

2. **Three Complementary Views**:
   - **Left-to-Right (`flowchart LR`) Mermaid Hierarchy + Colored `linkStyle` Edges**: Keeps full `<owner>/<scope>/<machineId>` paths and multi-GPU lines readable without horizontal clipping, highlighting overlap machines (`🔀 OVERLAP ×N`).
   - **Markdown Flock Overlap Matrix (`overlapMatrixMarkdown`)**: `Machine × Flock` table showing at a glance which machines span multiple flocks.
   - **Bipartite SVG Membership Graph (`flock-topology.svg`)**: Left column = Flocks, Right column = Machines sorted by overlap count descending then scope (`personal` -> `work`) so cubic Bézier ribbons (`M x1 y1 C cx y1, cx y2, x2 y2`) flow without unnecessary crossings, with **segmented multi-color outer rings** (`stroke-dasharray` rotated by `k * 360 / N - 90`) on each machine node encoding every non-root flock membership.

## How to Generate a Live Flock Topology Diagram

1. **Generate the live Mermaid diagram, Overlap Matrix, and Bipartite SVG via `flock.mjs topology` (or the `copilot-flock-flock_topology` MCP tool)**:
   ```powershell
   # PowerShell (Windows) — Dark or Light (Warm Alabaster #faf9f5)
   node "$HOME\.copilot\flock\flock.mjs" topology --theme dark --svg "$HOME\.copilot\flock\flock-topology.svg"
   node "$HOME\.copilot\flock\flock.mjs" topology --theme light --svg "$HOME\.copilot\flock\flock-topology-light.svg"
   ```
   ```bash
   # Bash (Linux / macOS) — Dark or Light (Warm Alabaster #faf9f5)
   node "$HOME/.copilot/flock/flock.mjs" topology --theme dark --svg "$HOME/.copilot/flock/flock-topology.svg"
   node "$HOME/.copilot/flock/flock.mjs" topology --theme light --svg "$HOME/.copilot/flock/flock-topology-light.svg"
   ```
2. **Present the diagram in chat**:
   - Render both the returned `mermaid` (`flowchart LR`) block and `overlapMatrixMarkdown` table directly in your response.
   - If the user asks to see the SVG or render light/dark mode, pass `--theme light` or `--theme dark` and open the SVG in the `browser` canvas or render a PNG (on Windows with headless Edge, always pass an isolated `--user-data-dir="$env:TEMP\edge-svg"` so an open GUI Edge session does not block `--headless=new`).
