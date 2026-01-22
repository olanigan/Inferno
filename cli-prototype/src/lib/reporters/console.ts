/**
 * Console Reporter for human-readable terminal output
 */

import { BaseReporter } from './base.js';
import { ScanResult, Finding } from '../../types/findings.js';

// ANSI color codes
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgYellow: '\x1b[43m',
  bgGreen: '\x1b[42m',
};

/**
 * Console Reporter for beautiful terminal output
 */
export class ConsoleReporter extends BaseReporter {
  async generate(results: ScanResult[]): Promise<string> {
    const metadata = this.generateMetadata(results);
    const lines: string[] = [];

    // Header
    lines.push('');
    lines.push(this.colorize('═'.repeat(80), 'cyan'));
    lines.push(this.colorize('  📦 PackageInferno Security Scan Report', 'bright'));
    lines.push(this.colorize('═'.repeat(80), 'cyan'));
    lines.push('');

    // Summary
    lines.push(this.formatSummary(results, metadata));
    lines.push('');

    // Results by severity
    const maliciousPackages = results.filter(r => this.calculateRiskLevel(r.score) === 'malicious');
    const suspiciousPackages = results.filter(r => this.calculateRiskLevel(r.score) === 'suspicious');
    const cleanPackages = results.filter(r => this.calculateRiskLevel(r.score) === 'clean');

    if (maliciousPackages.length > 0) {
      lines.push(this.colorize('🚨 MALICIOUS PACKAGES', 'red', true));
      lines.push(this.colorize('─'.repeat(80), 'red'));
      for (const result of maliciousPackages) {
        lines.push(this.formatPackageResult(result, 'malicious'));
      }
      lines.push('');
    }

    if (suspiciousPackages.length > 0) {
      lines.push(this.colorize('⚠️  SUSPICIOUS PACKAGES', 'yellow', true));
      lines.push(this.colorize('─'.repeat(80), 'yellow'));
      for (const result of suspiciousPackages) {
        lines.push(this.formatPackageResult(result, 'suspicious'));
      }
      lines.push('');
    }

    if (cleanPackages.length > 0 && this.options.verbose) {
      lines.push(this.colorize('✅ CLEAN PACKAGES', 'green', true));
      lines.push(this.colorize('─'.repeat(80), 'green'));
      for (const result of cleanPackages) {
        lines.push(this.formatPackageResult(result, 'clean'));
      }
      lines.push('');
    }

    // Footer
    lines.push(this.colorize('═'.repeat(80), 'cyan'));
    lines.push(this.colorize(`  Scan completed at ${metadata.generatedAt}`, 'dim'));
    lines.push(this.colorize('═'.repeat(80), 'cyan'));
    lines.push('');

    return lines.join('\n');
  }

  getFileExtension(): string {
    return 'txt';
  }

  getMimeType(): string {
    return 'text/plain';
  }

  /**
   * Format summary section
   */
  private formatSummary(results: ScanResult[], metadata: any): string {
    const maliciousCount = results.filter(r => this.calculateRiskLevel(r.score) === 'malicious').length;
    const suspiciousCount = results.filter(r => this.calculateRiskLevel(r.score) === 'suspicious').length;
    const cleanCount = results.filter(r => this.calculateRiskLevel(r.score) === 'clean').length;

    const lines = [
      this.colorize('Summary:', 'bright'),
      `  Total Packages:    ${this.colorize(metadata.totalPackages.toString(), 'bright')}`,
      `  Clean:             ${this.colorize(cleanCount.toString(), 'green')}`,
      `  Suspicious:        ${this.colorize(suspiciousCount.toString(), 'yellow')}`,
      `  Malicious:         ${this.colorize(maliciousCount.toString(), 'red')}`,
      '',
      `  Total Findings:    ${metadata.totalFindings}`,
      `    High Severity:   ${this.colorize(metadata.highSeverityCount.toString(), 'red')}`,
      `    Medium Severity: ${this.colorize(metadata.mediumSeverityCount.toString(), 'yellow')}`,
      `    Low Severity:    ${this.colorize(metadata.lowSeverityCount.toString(), 'blue')}`,
    ];

    return lines.join('\n');
  }

  /**
   * Format individual package result
   */
  private formatPackageResult(result: ScanResult, riskLevel: 'clean' | 'suspicious' | 'malicious'): string {
    const packageName = `${result.package}@${result.version}`;
    const lines: string[] = [];

    // Package header
    const icon = riskLevel === 'malicious' ? '🔴' : riskLevel === 'suspicious' ? '🟡' : '🟢';
    const color = riskLevel === 'malicious' ? 'red' : riskLevel === 'suspicious' ? 'yellow' : 'green';

    lines.push('');
    lines.push(`${icon} ${this.colorize(packageName, color, true)} (Score: ${result.score})`);

    if (result.findings.length === 0) {
      lines.push(`   ${this.colorize('No security findings', 'green')}`);
      return lines.join('\n');
    }

    // Sort findings by severity
    const sortedFindings = this.sortFindingsBySeverity(result.findings);

    // Group findings by severity
    const highFindings = sortedFindings.filter(f => f.severity === 'high');
    const mediumFindings = sortedFindings.filter(f => f.severity === 'medium');
    const lowFindings = sortedFindings.filter(f => f.severity === 'low');

    if (highFindings.length > 0) {
      lines.push(`   ${this.colorize('High Severity:', 'red', true)}`);
      for (const finding of highFindings) {
        lines.push(this.formatFinding(finding, '     '));
      }
    }

    if (mediumFindings.length > 0) {
      lines.push(`   ${this.colorize('Medium Severity:', 'yellow', true)}`);
      for (const finding of mediumFindings) {
        lines.push(this.formatFinding(finding, '     '));
      }
    }

    if (lowFindings.length > 0 && this.options.verbose) {
      lines.push(`   ${this.colorize('Low Severity:', 'blue', true)}`);
      for (const finding of lowFindings) {
        lines.push(this.formatFinding(finding, '     '));
      }
    }

    return lines.join('\n');
  }

  /**
   * Format individual finding
   */
  private formatFinding(finding: Finding, indent: string): string {
    const ruleNames: Record<string, string> = {
      lifecycle_script: 'Risky Lifecycle Script',
      c2_webhook: 'C2 Communication',
      env_snoop: 'Environment Variable Access',
      writes_outside_pkg: 'Suspicious File Write',
      typosquat_detected: 'Typosquatting',
      phishing_form: 'Phishing Form',
      advanced_obfuscation: 'Advanced Obfuscation',
      url_outside_allowlist: 'Non-Allowed Domain',
      suspicious_pattern: 'Suspicious Pattern',
      big_base64_blob: 'Large Base64 Payload',
      native_binary_present: 'Native Binary',
      yara_match: 'YARA Malware Signature',
    };

    const ruleName = ruleNames[finding.rule] || finding.rule;
    const lines: string[] = [];

    lines.push(`${indent}• ${ruleName}`);

    if (this.options.verbose && finding.details) {
      const detailsStr = JSON.stringify(finding.details, null, 2);
      const detailsLines = detailsStr.split('\n');
      for (const line of detailsLines) {
        lines.push(`${indent}  ${this.colorize(line, 'dim')}`);
      }
    }

    return lines.join('\n');
  }

  /**
   * Colorize text for terminal output
   */
  private colorize(text: string, color: keyof typeof colors, bright = false): string {
    if (!this.options.colorOutput && process.env.NO_COLOR) {
      return text;
    }

    const colorCode = colors[color] || '';
    const brightCode = bright ? colors.bright : '';

    return `${brightCode}${colorCode}${text}${colors.reset}`;
  }
}
