/**
 * JSON Reporter for programmatic access and API integration
 */

import { BaseReporter, ReportMetadata } from './base.js';
import { ScanResult } from '../../types/findings.js';

interface JSONReport {
  metadata: ReportMetadata;
  summary: {
    totalPackages: number;
    cleanPackages: number;
    suspiciousPackages: number;
    maliciousPackages: number;
    totalScore: number;
    averageScore: number;
  };
  results: ScanResult[];
}

/**
 * JSON Reporter for structured output and API integration
 */
export class JSONReporter extends BaseReporter {
  async generate(results: ScanResult[]): Promise<string> {
    const metadata = this.generateMetadata(results);
    const summary = this.generateSummary(results);

    const report: JSONReport = {
      metadata,
      summary,
      results: this.options.verbose ? results : this.filterResults(results),
    };

    return JSON.stringify(report, null, 2);
  }

  getFileExtension(): string {
    return 'json';
  }

  getMimeType(): string {
    return 'application/json';
  }

  /**
   * Generate summary statistics
   */
  private generateSummary(results: ScanResult[]): JSONReport['summary'] {
    const totalScore = results.reduce((sum, r) => sum + r.score, 0);
    const averageScore = results.length > 0 ? totalScore / results.length : 0;

    const cleanPackages = results.filter(r => this.calculateRiskLevel(r.score) === 'clean').length;
    const suspiciousPackages = results.filter(r => this.calculateRiskLevel(r.score) === 'suspicious').length;
    const maliciousPackages = results.filter(r => this.calculateRiskLevel(r.score) === 'malicious').length;

    return {
      totalPackages: results.length,
      cleanPackages,
      suspiciousPackages,
      maliciousPackages,
      totalScore: Math.round(totalScore * 100) / 100,
      averageScore: Math.round(averageScore * 100) / 100,
    };
  }

  /**
   * Filter results based on verbosity
   */
  private filterResults(results: ScanResult[]): ScanResult[] {
    // In non-verbose mode, only include packages with findings
    return results.filter(r => r.findings.length > 0);
  }
}
