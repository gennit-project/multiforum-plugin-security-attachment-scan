import fs from "node:fs";

const manifest = JSON.parse(fs.readFileSync("plugin.json", "utf8"));
const errors = [];
const isObject = (value) => value && typeof value === "object" && !Array.isArray(value);
const isNonEmptyString = (value) => typeof value === "string" && value.trim().length > 0;
const isUrl = (value) => {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
};

for (const field of ["id", "name", "version", "description", "entry"]) {
  if (!isNonEmptyString(manifest[field])) errors.push(`${field} is required`);
}

if (manifest.entry !== "dist/index.js") {
  errors.push("entry must be dist/index.js");
}

if (!Array.isArray(manifest.events) || manifest.events.length === 0) {
  errors.push("events must include at least one event");
}

if (!Array.isArray(manifest.secrets)) {
  errors.push("secrets must be an array");
}

if (!isObject(manifest.metadata)) {
  errors.push("metadata is required");
}

if (!isObject(manifest.documentation) || manifest.documentation.readmePath !== "README.md") {
  errors.push("documentation.readmePath must be README.md");
}

if (!isObject(manifest.source) || !isUrl(manifest.source.repoUrl) || !isUrl(manifest.source.releaseNotesUrl)) {
  errors.push("source.repoUrl and source.releaseNotesUrl must be valid URLs");
}

if (!isObject(manifest.compatibility) || !isNonEmptyString(manifest.compatibility.minServerVersion) || !isNonEmptyString(manifest.compatibility.apiVersion)) {
  errors.push("compatibility.minServerVersion and compatibility.apiVersion are required");
}

if (errors.length) {
  console.error(errors.map((error) => `- ${error}`).join("\n"));
  process.exit(1);
}

console.log(`Validated ${manifest.id}@${manifest.version}`);
