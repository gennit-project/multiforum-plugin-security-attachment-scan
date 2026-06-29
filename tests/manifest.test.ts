import fs from "node:fs";
import { describe, expect, it } from "vitest";

const manifest = JSON.parse(fs.readFileSync("plugin.json", "utf8"));

describe("plugin manifest", () => {
  it("describes a versioned Multiforum plugin package", () => {
    expect(manifest.id).toMatch(/^[a-z0-9-]+$/);
    expect(manifest.version).toMatch(/^\d+\.\d+\.\d+/);
    expect(manifest.entry).toBe("dist/index.js");
    expect(manifest.events.length).toBeGreaterThan(0);
  });

  it("declares source and compatibility metadata for registry consumers", () => {
    expect(manifest.source.repoUrl).toMatch(/^https:\/\/github\.com\/gennit-project\/multiforum-plugin-/);
    expect(manifest.source.releaseNotesUrl).toContain(`/releases/tag/v${manifest.version}`);
    expect(manifest.compatibility.minServerVersion).toMatch(/^\d+\.\d+\.\d+/);
    expect(manifest.compatibility.apiVersion).toBe("1");
  });
});
