/**
 * Validate the manifest and pack dist/ into an installable plugin zip.
 *
 * Manifest validation runs first and hard-fails: an invalid manifest produces a zip that Caido
 * rejects at install time with a far less useful message.
 */
import { readFileSync, writeFileSync, copyFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import JSZip from "jszip";
import { validateManifest } from "@caido/plugin-manifest";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dist = resolve(root, "dist");

for (const required of ["backend/script.js", "frontend/script.js"]) {
  if (!existsSync(join(dist, required))) {
    console.error(`[-] missing ${required} — run the builds first`);
    process.exit(1);
  }
}

console.log("[*] validating manifest");
const manifestPath = resolve(root, "manifest.json");
const manifest = JSON.parse(readFileSync(manifestPath, "utf-8"));
if (!validateManifest(manifest)) {
  console.error("[-] manifest validation failed");
  process.exit(1);
}
copyFileSync(manifestPath, join(dist, "manifest.json"));

// Attribution must ship inside the package: the probe catalogue is Apache-2.0 derived work and
// section 4 requires the notice to travel with the distribution, not just sit in the repo.
for (const file of ["NOTICE", "LICENSE-APACHE-2.0.txt"]) {
  const from = resolve(root, file);
  if (existsSync(from)) copyFileSync(from, join(dist, file));
}

function addDir(dirPath, folder) {
  for (const entry of readdirSync(dirPath)) {
    const full = join(dirPath, entry);
    if (statSync(full).isDirectory()) addDir(full, folder.folder(entry));
    else folder.file(entry, readFileSync(full));
  }
}

console.log("[*] packing plugin.zip");
const zip = new JSZip();
addDir(dist, zip);
const buffer = await zip.generateAsync({
  type: "nodebuffer",
  compression: "DEFLATE",
  compressionOptions: { level: 9 },
});
writeFileSync(join(dist, "plugin.zip"), buffer);
console.log(`[+] dist/plugin.zip (${buffer.length} bytes)`);
