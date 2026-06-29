import { describe, expect, it, vi } from "vitest";
import Plugin from "../index";

describe("SecurityAttachmentScan", () => {
  it("requires a VirusTotal API key before scanning", async () => {
    const plugin = new Plugin({
      scope: "SERVER",
      settings: {},
      secrets: { server: {}, forum: {} },
      storeFlag: vi.fn(),
      log: vi.fn()
    });

    const result = await plugin.handleEvent({
      type: "downloadableFile.created",
      payload: { downloadableFileId: "file-1", attachmentUrls: ["https://example.com/file.pdf"] }
    });

    expect(result.success).toBe(false);
    expect(result.configurationRequired).toBe(true);
    expect(result.missingSecrets).toContain("VIRUS_TOTAL_API_KEY");
  });
});
