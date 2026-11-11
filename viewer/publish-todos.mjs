import { readFile, realpath, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { validateTodoSnapshot } from "./todo-snapshot.mjs";

export async function publishTodos(sourcePath, destinationPath) {
  const source = validateTodoSnapshot(JSON.parse(await readFile(sourcePath, "utf8")));
  const destination = path.resolve(destinationPath);
  const parent = await realpath(path.dirname(destination));
  const repo = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  const relative = path.relative(repo, parent);
  if (!relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative) && relative !== "..") {
    throw new Error("Runtime TODO data must be outside the repository");
  }
  const target = path.join(parent, path.basename(destination));
  const content = `${JSON.stringify(source, null, 2)}\n`;
  if (Buffer.byteLength(content) > 1024 * 1024) throw new Error("TODO snapshot exceeds 1 MiB");
  let previous;
  try { previous = validateTodoSnapshot(JSON.parse(await readFile(target, "utf8"))); }
  catch (error) { if (error?.code !== "ENOENT") throw error; }
  if (previous) {
    if (source.revision < previous.revision) throw new Error("Refusing an older TODO revision");
    if (source.revision === previous.revision) {
      if (JSON.stringify(source) !== JSON.stringify(previous)) throw new Error("Changed TODO content requires a new revision");
      return source;
    }
    if (Date.parse(source.updatedAt) < Date.parse(previous.updatedAt)) throw new Error("Refusing an older TODO timestamp");
  }
  const temporary = `${target}.${crypto.randomUUID()}.tmp`;
  await writeFile(temporary, content, { flag: "wx", mode: 0o600 });
  try { await rename(temporary, target); }
  catch (error) { await unlink(temporary); throw error; }
  return source;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [source, destination, ...extra] = process.argv.slice(2);
  try {
    if (!source || !destination || extra.length) throw new Error("Expected source and private runtime destination paths");
    const snapshot = await publishTodos(source, destination);
    console.log(`Published TODO revision ${snapshot.revision} (${snapshot.issues.length} items)`);
  } catch (error) {
    console.error(`TODO publication failed: ${error.message}`);
    process.exitCode = 1;
  }
}
