/**
 * Base reporter interface and shared types for output formatting
 */

import { ScanResult, Finding } from '../../types/findings.js';

export type OutputFormat = 'json' | 'sarif' | 'console' | 'junit';

export interface ReportOptions {
  verbose?: boolean;
  includeMetadata?: boolean;
  colorOutput?: boolean;
}

export interface ReportMetadata {
  generatedAt: string;
  cliVersion: string;
  scannerVersion: string;
  totalPackages: number;
  totalFindings: number;
  highSeverityCount: number;
  mediumSeverityCount: number;
  lowSeverityCount: number;
}

/**
 * Abstract base class for all reporters
 */
export abstract class BaseReporter {
  constructor(protected options: ReportOptions = {}) {}

  /**
   * Generate report from scan results
   */
  abstract generate(results: ScanResult[]): Promise<string>;

  /**
   * Get file extension for this report format
   */
  abstract getFileExtension(): string;

  /**
   * Get MIME type for this report format
   */
  abstract getMimeType(): string;

  /**
   * Generate metadata from scan results
   */
  protected generateMetadata(results: ScanResult[]): ReportMetadata {
    const allFindings = results.flatMap(r => r.findings);

    return {
      generatedAt: new Date().toISOString(),
      cliVersion: '1.0.0', // TODO: Get from package.json
      scannerVersion: 'main',
      totalPackages: results.length,
      totalFindings: allFindings.length,
      highSeverityCount: allFindings.filter(f => f.severity === 'high').length,
      mediumSeverityCount: allFindings.filter(f => f.severity === 'medium').length,
      lowSeverityCount: allFindings.filter(f => f.severity === 'low').length,
    };
  }

  /**
   * Get severity level as number for sorting
   */
  protected getSeverityLevel(severity: 'low' | 'medium' | 'high'): number {
    const levels = { low: 1, medium: 2, high: 3 };
    return levels[severity];
  }

  /**
   * Sort findings by severity (high to low)
   */
  protected sortFindingsBySeverity(findings: Finding[]): Finding[] {
    return [...findings].sort((a, b) =>
      this.getSeverityLevel(b.severity) - this.getSeverityLevel(a.severity)
    );
  }

  /**
   * Calculate risk level based on score
   */
  protected calculateRiskLevel(score: number): 'clean' | 'suspicious' | 'malicious' {
    if (score === 0) return 'clean';
    if (score < 12) return 'suspicious';
    return 'malicious';
  }
}

/**
 * Reporter factory for creating reporters by format
 */
export class ReporterFactory {
  static async create(format: OutputFormat, options?: ReportOptions): Promise<BaseReporter> {
    switch (format) {
      case 'json':
        const { JSONReporter } = await import('./json.js');
        return new JSONReporter(options);

      case 'sarif':
        const { SARIFReporter } = await import('./sarif.js');
        return new SARIFReporter(options);

      case 'console':
        const { ConsoleReporter } = await import('./console.js');
        return new ConsoleReporter(options);

      case 'junit':
        const { JUnitReporter } = await import('./junit.js');
        return new JUnitReporter(options);

      default:
        // TypeScript exhaustiveness check
        const _exhaustive: never = format;
        throw new Error(`Unknown format: ${_exhaustive}`);
    }
  }

  static getAvailableFormats(): OutputFormat[] {
    return ['json', 'sarif', 'console', 'junit'];
  }
}
