// Security: Attachment Scan plugin
// Runs at server scope and scans attachments using the VirusTotal API.

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
    meta?: any;
  }) => Promise<void>;
  log: (...args: any[]) => void;
}

interface EventEnvelope {
  type: "downloadableFile.created" | "downloadableFile.updated" | "downloadableFile.downloaded";
  payload: {
    commentId?: string;
    discussionId?: string;
    downloadableFileId?: string;
    attachmentUrls?: string[];
  };
}

export default class SecurityAttachmentScan {
  private context: HookContext;
  private logger: HookContext['log'];
  private virusTotalKey?: string;
  private isConfigured: boolean;
  private fetchImpl: typeof fetch | null;

  constructor(context: HookContext) {
    this.context = context;
    this.logger = context.log;
    this.fetchImpl = typeof globalThis.fetch === "function" ? globalThis.fetch.bind(globalThis) : null;
    
    if (!this.fetchImpl) {
      this.logger("Fetch API is not available in this runtime");
    }
    
    // Access server-scoped secrets
    this.virusTotalKey = context.secrets?.server?.VIRUS_TOTAL_API_KEY;
    
    // Validate configuration
    this.isConfigured = this.validateConfiguration();
    
    if (!this.isConfigured || !this.fetchImpl) {
      this.logger("VIRUS_TOTAL_API_KEY is required but not configured");
    }
  }

  private validateConfiguration(): boolean {
    const requiredSecrets = ['VIRUS_TOTAL_API_KEY'];
    const missingSecrets = requiredSecrets.filter(key => 
      !this.context.secrets?.server?.[key]
    );
    
    if (missingSecrets.length > 0) {
      this.logger(`Missing required secrets: ${missingSecrets.join(', ')}`);
      return false;
    }
    
    return true;
  }

  async handleEvent(event: EventEnvelope) {
    // Always check configuration first
    if (!this.isConfigured || !this.fetchImpl) {
      return {
        success: false,
        error: 'Plugin not configured - missing required secrets',
        configurationRequired: true,
        missingSecrets: ['VIRUS_TOTAL_API_KEY']
      };
    }

    if (!event.payload.attachmentUrls || event.payload.attachmentUrls.length === 0) {
      this.logger("No attachments to scan");
      return { success: true, result: { message: "No attachments to scan" } };
    }

    try {
      const results = [];
      
      for (const url of event.payload.attachmentUrls) {
        try {
          this.logger(`Scanning attachment: ${url}`);
          
          // VirusTotal API call
          const res = await this.fetchImpl!("https://www.virustotal.com/api/v3/urls", {
            method: "POST",
            headers: {
              "x-apikey": this.virusTotalKey!,
              "content-type": "application/x-www-form-urlencoded",
            },
            body: `url=${encodeURIComponent(url)}`,
          });

          if (!res.ok) {
            this.logger(`Failed to scan ${url}: ${res.statusText}`);
            results.push({ url, error: `Failed to scan: ${res.statusText}` });
            continue;
          }

          const data = await res.json();
          this.logger(`Scan result for ${url}:`, data);

          // Store flag for successful scan
          const targetId = event.payload.downloadableFileId || event.payload.commentId || event.payload.discussionId || "unknown";
          await this.context.storeFlag({
            targetId,
            type: "security",
            severity: "low",
            message: `Scanned ${url} successfully with VirusTotal`,
          });
          
          results.push({ url, scanResult: data });
        } catch (err: any) {
          this.logger(`Error scanning ${url}:`, err.message);
          results.push({ url, error: err.message });
        }
      }
      
      return { 
        success: true, 
        result: { 
          scannedFiles: results.length,
          results,
          eventType: event.type
        }
      };
      
    } catch (error: any) {
      this.logger('Security attachment scan failed:', error);
      return { 
        success: false, 
        error: error.message,
        retryable: true
      };
    }
  }

  static validateSecrets(secrets: Record<string, string>) {
    const errors: string[] = [];
    
    if (secrets.VIRUS_TOTAL_API_KEY) {
      // Basic validation - VirusTotal API keys are typically alphanumeric
      if (secrets.VIRUS_TOTAL_API_KEY.length < 10) {
        errors.push('VIRUS_TOTAL_API_KEY must be at least 10 characters long');
      }
      
      if (!/^[a-zA-Z0-9]+$/.test(secrets.VIRUS_TOTAL_API_KEY)) {
        errors.push('VIRUS_TOTAL_API_KEY must contain only alphanumeric characters');
      }
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  }
}