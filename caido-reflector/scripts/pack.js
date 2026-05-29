import JSZip from "jszip";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { validateManifest } from "@caido/plugin-manifest";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DIST = path.resolve(__dirname, "../dist");

function addDirToZip(dirPath, zipFolder) {
  for (const file of fs.readdirSync(dirPath)) {
    const filePath = path.join(dirPath, file);
    const stat = fs.statSync(filePath);
    if (stat.isDirectory()) {
      addDirToZip(filePath, zipFolder.folder(file));
    } else {
      zipFolder.file(file, fs.readFileSync(filePath));
    }
  }
}

console.log("[*] Validating manifest");
const srcManifest = path.resolve(__dirname, "../manifest.json");
const data = JSON.parse(fs.readFileSync(srcManifest, "utf-8"));
if (!validateManifest(data)) {
  console.error("[-] Manifest validation failed");
  process.exit(1);
}
fs.copyFileSync(srcManifest, path.join(DIST, "manifest.json"));

console.log("[*] Packing plugin.zip");
const zip = new JSZip();
addDirToZip(DIST, zip);
const buf = await zip.generateAsync({
  type: "nodebuffer",
  compression: "DEFLATE",
  compressionOptions: { level: 9 },
});
fs.writeFileSync(path.join(DIST, "plugin.zip"), buf);
console.log(`[+] dist/plugin.zip (${buf.length} bytes)`);
