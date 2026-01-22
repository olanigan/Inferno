/**
 * SARIF 2.1.0 Reporter for GitHub Security integration
 * Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import { BaseReporter } from './base.js';
import { ScanResult, Finding } from '../../types/findings.js';

interface SARIFLog {
  version: '2.1.0';
  $schema: string;
  runs: SARIFRun[];
}

interface SARIFRun {
  tool: SARIFTool;
  results: SARIFResult[];
  invocations?: SARIFInvocation[];
}

interface SARIFTool {
  driver: SARIFToolComponent;
}

interface SARIFToolComponent {
  name: string;
  version: string;
  informationUri: string;
  rules: SARIFRule[];
}

interface SARIFRule {
  id: string;
  name: string;
  shortDescription: SARIFMessage;
  fullDescription?: SARIFMessage;
  help?: SARIFMessage;
  defaultConfiguration: {
    level: 'error' | 'warning' | 'note';
  };
  properties?: {
    tags?: string[];
    'security-severity'?: string;
  };
}

interface SARIFResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: SARIFMessage;
  locations: SARIFLocation[];
  partialFingerprints?: Record<string, string>;
}

interface SARIFMessage {
  text: string;
}

interface SARIFLocation {
  physicalLocation: {
    artifactLocation: {
      uri: string;
      uriBaseId?: string;
    };
    region?: {
      startLine?: number;
      startColumn?: number;
      snippet?: {
        text: string;
      };
    };
  };
}

interface SARIFInvocation {
  executionSuccessful: boolean;
  endTimeUtc: string;
}

/**
 * SARIF Reporter for security dashboards (GitHub, Azure DevOps, etc.)
 */
export class SARIFReporter extends BaseReporter {
  async generate(results: ScanResult[]): Promise<string> {
    const metadata = this.generateMetadata(results);

    const sarifLog: SARIFLog = {
      version: '2.1.0',
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      runs: [
        {
          tool: {
            driver: {
              name: 'PackageInferno',
              version: metadata.scannerVersion,
              informationUri: 'https://github.com/MHaggis/Package-Inferno',
              rules: this.generateRules(),
            },
          },
          results: this.generateResults(results),
          invocations: [
            {
              executionSuccessful: true,
              endTimeUtc: metadata.generatedAt,
            },
          ],
        },
      ],
    };

    return JSON.stringify(sarifLog, null, 2);
  }

  getFileExtension(): string {
    return 'sarif';
  }

  getMimeType(): string {
    return 'application/sarif+json';
  }

  /**
   * Generate SARIF rules from all possible findings
   */
  private generateRules(): SARIFRule[] {
    const ruleDefinitions: Record<string, { name: string; description: string; severity: 'error' | 'warning' | 'note'; securitySeverity: string; tags: string[] }> = {
      lifecycle_script: {
        name: 'Risky Lifecycle Script',
        description: 'Package contains potentially dangerous install/postinstall hooks that execute arbitrary code during installation',
        severity: 'error',
        securitySeverity: '8.0',
        tags: ['security', 'supply-chain', 'lifecycle-hooks'],
      },
      c2_webhook: {
        name: 'Command & Control Communication',
        description: 'Package attempts to communicate with known C2 endpoints (Discord, Telegram, Slack webhooks)',
        severity: 'error',
        securitySeverity: '9.0',
        tags: ['security', 'exfiltration', 'c2'],
      },
      env_snoop: {
        name: 'Environment Variable Access',
        description: 'Package accesses sensitive environment variables (AWS keys, tokens, passwords)',
        severity: 'error',
        securitySeverity: '8.5',
        tags: ['security', 'credential-theft'],
      },
      writes_outside_pkg: {
        name: 'Suspicious File Write',
        description: 'Package writes to sensitive system locations (.ssh, .npmrc, system directories)',
        severity: 'error',
        securitySeverity: '7.5',
        tags: ['security', 'file-system'],
      },
      typosquat_detected: {
        name: 'Typosquatting Detected',
        description: 'Package name is suspiciously similar to a popular package (potential typosquatting attack)',
        severity: 'error',
        securitySeverity: '8.0',
        tags: ['security', 'typosquatting', 'supply-chain'],
      },
      phishing_form: {
        name: 'Phishing Form',
        description: 'Package contains forms designed to harvest credentials or sensitive information',
        severity: 'error',
        securitySeverity: '7.0',
        tags: ['security', 'phishing'],
      },
      advanced_obfuscation: {
        name: 'Advanced Obfuscation',
        description: 'Package uses advanced code obfuscation techniques (XOR, hex arrays, control flow flattening)',
        severity: 'warning',
        securitySeverity: '6.5',
        tags: ['security', 'obfuscation'],
      },
      url_outside_allowlist: {
        name: 'Non-Allowed Domain',
        description: 'Package makes network calls to domains outside the allowed list',
        severity: 'warning',
        securitySeverity: '5.0',
        tags: ['security', 'network'],
      },
      suspicious_pattern: {
        name: 'Suspicious Code Pattern',
        description: 'Package contains suspicious patterns like eval, shell execution, or dynamic code loading',
        severity: 'warning',
        securitySeverity: '5.5',
        tags: ['security', 'code-patterns'],
      },
      big_base64_blob: {
        name: 'Large Base64 Payload',
        description: 'Package contains large base64-encoded data that could hide malicious payloads',
        severity: 'warning',
        securitySeverity: '4.0',
        tags: ['security', 'obfuscation'],
      },
      native_binary_present: {
        name: 'Native Binary',
        description: 'Package includes compiled binaries (PE/ELF/Mach-O) that cannot be statically analyzed',
        severity: 'warning',
        securitySeverity: '5.0',
        tags: ['security', 'native-code'],
      },
      yara_match: {
        name: 'YARA Malware Signature',
        description: 'Package matched known malware signatures from YARA-Forge ruleset',
        severity: 'error',
        securitySeverity: '9.5',
        tags: ['security', 'malware', 'yara'],
      },
    };

    return Object.entries(ruleDefinitions).map(([id, def]) => ({
      id,
      name: def.name,
      shortDescription: { text: def.description },
      fullDescription: { text: def.description },
      defaultConfiguration: { level: def.severity },
      properties: {
        tags: def.tags,
        'security-severity': def.securitySeverity,
      },
    }));
  }

  /**
   * Convert scan results to SARIF results
   */
  private generateResults(scanResults: ScanResult[]): SARIFResult[] {
    const results: SARIFResult[] = [];

    for (const scanResult of scanResults) {
      for (const finding of scanResult.findings) {
        results.push({
          ruleId: finding.rule,
          level: this.severityToSARIFLevel(finding.severity),
          message: {
            text: this.formatFindingMessage(scanResult, finding),
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: 'package-lock.json',
                  uriBaseId: '%SRCROOT%',
                },
                region: {
                  startLine: 1,
                  snippet: {
                    text: `${scanResult.package}@${scanResult.version}`,
                  },
                },
              },
            },
          ],
          partialFingerprints: {
            packageName: scanResult.package,
            packageVersion: scanResult.version,
            rule: finding.rule,
          },
        });
      }
    }

    return results;
  }

  /**
   * Convert finding severity to SARIF level
   */
  private severityToSARIFLevel(severity: 'low' | 'medium' | 'high'): 'error' | 'warning' | 'note' {
    switch (severity) {
      case 'high':
        return 'error';
      case 'medium':
        return 'warning';
      case 'low':
        return 'note';
      default:
        const _exhaustive: never = severity;
        return 'warning';
    }
  }

  /**
   * Format finding message with context
   */
  private formatFindingMessage(scanResult: ScanResult, finding: Finding): string {
    const pkg = `${scanResult.package}@${scanResult.version}`;
    const details = JSON.stringify(finding.details);

    return `Package '${pkg}' triggered rule '${finding.rule}' (${finding.severity} severity). Details: ${details}`;
  }
}
