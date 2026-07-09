import { afterEach, describe, expect, it, vi } from "vitest";
import Plugin from "../index";

type Verdict = "clean" | "suspicious" | "malicious" | "error";

const CONFIGURED = {
  scope: "SERVER" as const,
  settings: { serviceUrl: "https://scan.example.com", blockOn: "malicious" },
  secrets: { server: { SCAN_SERVICE_API_KEY: "supersecret" }, forum: {} },
};

function mockFetchVerdict(verdict: Verdict, summary = "test") {
  const fetchMock = vi.fn(async () => ({
    ok: true,
    status: 200,
    json: async () => ({ verdict, summary, sha256: "a".repeat(64) }),
    text: async () => "",
  }));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("SecurityAttachmentScan", () => {
  it("requires configuration before scanning", async () => {
    const plugin = new Plugin({
      scope: "SERVER",
      settings: {},
      secrets: { server: {}, forum: {} },
      storeFlag: vi.fn(),
      log: vi.fn(),
    });

    const result = await plugin.handleEvent({
      type: "downloadableFile.created",
      payload: { downloadableFileId: "file-1", attachmentUrls: ["https://example.com/f.zip"] },
    });

    expect(result).toMatchObject({
      success: false,
      configurationRequired: true,
      missingConfig: ["serviceUrl", "SCAN_SERVICE_API_KEY"],
    });
  });

  it("succeeds with no attachments", async () => {
    mockFetchVerdict("clean");
    const plugin = new Plugin({ ...CONFIGURED, storeFlag: vi.fn(), log: vi.fn() });

    const result = await plugin.handleEvent({
      type: "downloadableFile.created",
      payload: { downloadableFileId: "file-1", attachmentUrls: [] },
    });

    expect(result.success).toBe(true);
  });

  it("passes a clean attachment", async () => {
    mockFetchVerdict("clean");
    const plugin = new Plugin({ ...CONFIGURED, storeFlag: vi.fn(), log: vi.fn() });

    const result = await plugin.handleEvent({
      type: "downloadableFile.created",
      payload: { downloadableFileId: "file-1", attachmentUrls: ["https://example.com/f.zip"] },
    });

    expect(result.success).toBe(true);
  });

  it("blocks a malicious attachment", async () => {
    mockFetchVerdict("malicious", "3 engines flagged this file");
    const plugin = new Plugin({ ...CONFIGURED, storeFlag: vi.fn(), log: vi.fn() });

    const result = await plugin.handleEvent({
      type: "downloadableFile.created",
      payload: { downloadableFileId: "file-1", attachmentUrls: ["https://example.com/f.zip"] },
    });

    expect(result.success).toBe(false);
  });

  it("stores a moderation flag when a threat is found", async () => {
    mockFetchVerdict("malicious", "flagged");
    const storeFlag = vi.fn();
    const plugin = new Plugin({ ...CONFIGURED, storeFlag, log: vi.fn() });

    await plugin.handleEvent({
      type: "downloadableFile.created",
      payload: { downloadableFileId: "file-1", attachmentUrls: ["https://example.com/f.zip"] },
    });

    expect(storeFlag).toHaveBeenCalledWith(
      expect.objectContaining({ targetId: "file-1", severity: "high", type: "security" }),
    );
  });

  it("does not block a suspicious verdict when blockOn is malicious", async () => {
    mockFetchVerdict("suspicious", "missing README");
    const plugin = new Plugin({ ...CONFIGURED, storeFlag: vi.fn(), log: vi.fn() });

    const result = await plugin.handleEvent({
      type: "downloadableFile.created",
      payload: { downloadableFileId: "file-1", attachmentUrls: ["https://example.com/f.zip"] },
    });

    expect(result.success).toBe(true);
  });

  it("sends the API key as the X-API-Key header", async () => {
    const fetchMock = mockFetchVerdict("clean");
    const plugin = new Plugin({ ...CONFIGURED, storeFlag: vi.fn(), log: vi.fn() });

    await plugin.handleEvent({
      type: "downloadableFile.created",
      payload: { downloadableFileId: "file-1", attachmentUrls: ["https://example.com/f.zip"] },
    });

    expect(fetchMock.mock.calls[0][1].headers["x-api-key"]).toBe("supersecret");
  });

  it("blocks on scan error by default (fail closed)", async () => {
    mockFetchVerdict("error", "scan service unreachable");
    const plugin = new Plugin({ ...CONFIGURED, storeFlag: vi.fn(), log: vi.fn() });

    const result = await plugin.handleEvent({
      type: "downloadableFile.created",
      payload: { downloadableFileId: "file-1", attachmentUrls: ["https://example.com/f.zip"] },
    });

    expect(result.success).toBe(false);
  });

  it("allows on scan error when onError is 'allow' (fail open)", async () => {
    mockFetchVerdict("error", "scan service unreachable");
    const plugin = new Plugin({
      ...CONFIGURED,
      settings: { ...CONFIGURED.settings, onError: "allow" },
      storeFlag: vi.fn(),
      log: vi.fn(),
    });

    const result = await plugin.handleEvent({
      type: "downloadableFile.created",
      payload: { downloadableFileId: "file-1", attachmentUrls: ["https://example.com/f.zip"] },
    });

    expect(result.success).toBe(true);
  });

  it("blocks a suspicious verdict when blockOn is 'suspicious'", async () => {
    mockFetchVerdict("suspicious", "missing README");
    const plugin = new Plugin({
      ...CONFIGURED,
      settings: { ...CONFIGURED.settings, blockOn: "suspicious" },
      storeFlag: vi.fn(),
      log: vi.fn(),
    });

    const result = await plugin.handleEvent({
      type: "downloadableFile.created",
      payload: { downloadableFileId: "file-1", attachmentUrls: ["https://example.com/f.zip"] },
    });

    expect(result.success).toBe(false);
  });
});
