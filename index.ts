// Security: Attachment Scan plugin
//
// Runs at server scope on downloadable-file events. Rather than talking to
// VirusTotal in-process, this plugin forwards each attachment to the Multiforum
// security-scan service — a standalone Python/FastAPI microservice that runs a
// VirusTotal reputation lookup *and* static ZIP analysis, then returns a single
// verdict. Keeping the third-party API key and the heavy file handling in that
// service (not in the backend process) is both safer and easier to scale.
//
// Service: https://github.com/gennit-project/multiforum-plugin-security-scan-service

interface HookContext {
  scope: "SERVER" | "FORUM";
  channelId?: string;
  settings: Record<string, unknown>;
  secrets?: {
    server?: Record<string, string>;
    forum?: Record<string, string>;
  };
  storeFlag: (input: {
    targetId: string;
    type: string;
    severity: "low" | "med" | "high";
    message: string;
    meta?: unknown;
  }) => Promise<void>;
  log: (...args: unknown[]) => void;
}

interface EventEnvelope {
  type:
    | "downloadableFile.created"
    | "downloadableFile.updated"
    | "downloadableFile.downloaded";
  payload: {
    commentId?: string;
    discussionId?: string;
    downloadableFileId?: string;
    attachmentUrls?: string[];
  };
}

type Verdict = "clean" | "suspicious" | "malicious" | "error";

interface ScanResult {
  verdict: Verdict;
  summary: string;
  sha256?: string;
  checks?: unknown[];
}

const VERDICT_SEVERITY: Record<Verdict, number> = {
  clean: 0,
  suspicious: 1,
  malicious: 2,
  error: 3,
};

// storeFlag severity per verdict.
const FLAG_SEVERITY: Record<Verdict, "low" | "med" | "high"> = {
  clean: "low",
  suspicious: "med",
  malicious: "high",
  error: "med",
};

export default class SecurityAttachmentScan {
  private context: HookContext;
  private logger: HookContext["log"];
  private fetchImpl: typeof fetch | null;
  private serviceUrl: string;
  private apiKey: string;
  private blockOn: Verdict;
  private policy: Record<string, unknown>;
  private isConfigured: boolean;

  constructor(context: HookContext) {
    this.context = context;
    this.logger = context.log;
    this.fetchImpl =
      typeof globalThis.fetch === "function"
        ? globalThis.fetch.bind(globalThis)
        : null;

    if (!this.fetchImpl) {
      this.logger("Fetch API is not available in this runtime");
    }

    const settings = context.settings ?? {};
    this.serviceUrl = String(settings.serviceUrl ?? "").replace(/\/+$/, "");
    this.apiKey = context.secrets?.server?.SCAN_SERVICE_API_KEY ?? "";
    this.blockOn = this.normalizeVerdict(settings.blockOn, "malicious");
    this.policy =
      settings.policy && typeof settings.policy === "object"
        ? (settings.policy as Record<string, unknown>)
        : {};

    this.isConfigured = Boolean(this.serviceUrl) && Boolean(this.apiKey);
    if (!this.isConfigured) {
      this.logger(
        "security-attachment-scan is not configured: serviceUrl and SCAN_SERVICE_API_KEY are required",
      );
    }
  }

  private normalizeVerdict(value: unknown, fallback: Verdict): Verdict {
    return value === "clean" ||
      value === "suspicious" ||
      value === "malicious" ||
      value === "error"
      ? value
      : fallback;
  }

  private missingConfig(): string[] {
    const missing: string[] = [];
    if (!this.serviceUrl) missing.push("serviceUrl");
    if (!this.apiKey) missing.push("SCAN_SERVICE_API_KEY");
    return missing;
  }

  async handleEvent(event: EventEnvelope) {
    if (!this.isConfigured || !this.fetchImpl) {
      return {
        success: false,
        error: "Plugin not configured - set serviceUrl and SCAN_SERVICE_API_KEY",
        configurationRequired: true,
        missingConfig: this.missingConfig(),
      };
    }

    const urls = event.payload.attachmentUrls ?? [];
    if (urls.length === 0) {
      this.logger("No attachments to scan");
      return { success: true, result: { message: "No attachments to scan" } };
    }

    const targetId =
      event.payload.downloadableFileId ||
      event.payload.commentId ||
      event.payload.discussionId ||
      "unknown";

    const scans: Array<{ url: string; scan: ScanResult }> = [];
    for (const url of urls) {
      const scan = await this.scanOne(url);
      scans.push({ url, scan });
      this.logger(`Scanned ${url} → ${scan.verdict} (${scan.summary})`);

      if (scan.verdict !== "clean") {
        await this.context.storeFlag({
          targetId,
          type: "security",
          severity: FLAG_SEVERITY[scan.verdict],
          message: `Attachment scan (${scan.verdict}): ${scan.summary}`,
          meta: { url, sha256: scan.sha256, verdict: scan.verdict },
        });
      }
    }

    const worst = scans.reduce<Verdict>(
      (acc, { scan }) =>
        VERDICT_SEVERITY[scan.verdict] > VERDICT_SEVERITY[acc]
          ? scan.verdict
          : acc,
      "clean",
    );

    const blocked = VERDICT_SEVERITY[worst] >= VERDICT_SEVERITY[this.blockOn];
    const summary = scans
      .map(({ url, scan }) => `${scan.verdict}: ${url} (${scan.summary})`)
      .join(" | ");

    return {
      success: !blocked,
      error: blocked ? `Attachment scan blocked upload — ${summary}` : undefined,
      result: {
        message: blocked ? `Blocked (${worst}).` : `Passed (${worst}).`,
        verdict: worst,
        scannedFiles: scans.length,
        eventType: event.type,
        scans: scans.map(({ url, scan }) => ({ url, ...scan })),
      },
    };
  }

  private async scanOne(fileUrl: string): Promise<ScanResult> {
    try {
      const res = await this.fetchImpl!(`${this.serviceUrl}/scan`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": this.apiKey,
        },
        body: JSON.stringify({ file_url: fileUrl, policy: this.policy }),
      });

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        return {
          verdict: "error",
          summary: `scan service returned HTTP ${res.status}: ${text.slice(0, 200)}`,
        };
      }

      return (await res.json()) as ScanResult;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { verdict: "error", summary: message };
    }
  }

  // Kept for parity with the previous release: lightweight validation the host
  // can call before saving secrets.
  static validateSecrets(secrets: Record<string, string>) {
    const errors: string[] = [];
    const key = secrets.SCAN_SERVICE_API_KEY;
    if (key !== undefined && key.trim().length < 8) {
      errors.push("SCAN_SERVICE_API_KEY must be at least 8 characters long");
    }
    return { isValid: errors.length === 0, errors };
  }
}
