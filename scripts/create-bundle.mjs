import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const manifest = JSON.parse(fs.readFileSync("plugin.json", "utf8"));
fs.rmSync("out", { recursive: true, force: true });
fs.mkdirSync("out", { recursive: true });

const bundleName = `${manifest.id}-${manifest.version}.tgz`;
const bundlePath = path.join("out", bundleName);
const result = spawnSync("tar", ["-czf", bundlePath, "plugin.json", "README.md", "dist"], {
  stdio: "inherit"
});

if (result.status !== 0) {
  process.exit(result.status ?? 1);
}

const checksum = crypto.createHash("sha256").update(fs.readFileSync(bundlePath)).digest("hex");
fs.writeFileSync(path.join("out", `${bundleName}.sha256`), `${checksum}  ${bundleName}\n`);
console.log(`Created ${bundlePath}`);
console.log(`sha256: ${checksum}`);
