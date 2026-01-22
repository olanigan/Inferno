/**
 * JUnit XML Reporter for CI/CD systems
 * Compatible with Jenkins, GitLab CI, Azure DevOps, etc.
 */

import { BaseReporter } from './base.js';
import { ScanResult, Finding } from '../../types/findings.js';

/**
 * JUnit XML Reporter for test result visualization in CI/CD
 */
export class JUnitReporter extends BaseReporter {
  async generate(results: ScanResult[]): Promise<string> {
    const metadata = this.generateMetadata(results);

    const testsuites: string[] = [];
    let totalTests = 0;
    let totalFailures = 0;
    let totalErrors = 0;
    let totalTime = 0;

    for (const result of results) {
      const testsuite = this.generateTestSuite(result);
      testsuites.push(testsuite.xml);
      totalTests += testsuite.tests;
      totalFailures += testsuite.failures;
      totalErrors += testsuite.errors;
      totalTime += testsuite.time;
    }

    const xml = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      `<testsuites name="PackageInferno Security Scan" tests="${totalTests}" failures="${totalFailures}" errors="${totalErrors}" time="${totalTime.toFixed(3)}">`,
      ...testsuites,
      '</testsuites>',
    ].join('\n');

    return xml;
  }

  getFileExtension(): string {
    return 'xml';
  }

  getMimeType(): string {
    return 'application/xml';
  }

  /**
   * Generate a test suite for a single package
   */
  private generateTestSuite(result: ScanResult): {
    xml: string;
    tests: number;
    failures: number;
    errors: number;
    time: number;
  } {
    const packageName = `${result.package}@${result.version}`;
    const tests = result.findings.length + 1; // +1 for overall security check
    const failures = result.findings.filter(f => f.severity === 'high').length;
    const errors = result.findings.filter(f => f.severity === 'medium').length;
    const time = result.scanDuration / 1000; // Convert to seconds

    const testcases: string[] = [];

    // Overall security check test case
    const riskLevel = this.calculateRiskLevel(result.score);
    if (riskLevel === 'malicious') {
      testcases.push(
        `  <testcase name="Overall Security Score" classname="${this.escapeXml(packageName)}" time="0">`,
        `    <failure message="Package scored ${result.score} (malicious threshold)" type="SecurityViolation">`,
        `Package: ${this.escapeXml(packageName)}`,
        `Score: ${result.score}`,
        `Risk Level: ${riskLevel}`,
        `Total Findings: ${result.findings.length}`,
        `    </failure>`,
        `  </testcase>`
      );
    } else if (riskLevel === 'suspicious') {
      testcases.push(
        `  <testcase name="Overall Security Score" classname="${this.escapeXml(packageName)}" time="0">`,
        `    <error message="Package scored ${result.score} (suspicious)" type="SecurityWarning">`,
        `Package: ${this.escapeXml(packageName)}`,
        `Score: ${result.score}`,
        `Risk Level: ${riskLevel}`,
        `Total Findings: ${result.findings.length}`,
        `    </error>`,
        `  </testcase>`
      );
    } else {
      testcases.push(
        `  <testcase name="Overall Security Score" classname="${this.escapeXml(packageName)}" time="0"/>`
      );
    }

    // Individual finding test cases
    for (const finding of result.findings) {
      const testcaseName = this.formatTestCaseName(finding);
      const testcaseXml = this.generateTestCase(packageName, testcaseName, finding);
      testcases.push(testcaseXml);
    }

    const xml = [
      `<testsuite name="${this.escapeXml(packageName)}" tests="${tests}" failures="${failures}" errors="${errors}" time="${time.toFixed(3)}">`,
      ...testcases,
      '</testsuite>',
    ].join('\n');

    return { xml, tests, failures, errors, time };
  }

  /**
   * Generate a test case for a single finding
   */
  private generateTestCase(packageName: string, testName: string, finding: Finding): string {
    const escaped = {
      packageName: this.escapeXml(packageName),
      testName: this.escapeXml(testName),
      rule: this.escapeXml(finding.rule),
      severity: this.escapeXml(finding.severity),
      details: this.escapeXml(JSON.stringify(finding.details, null, 2)),
    };

    if (finding.severity === 'high') {
      return [
        `  <testcase name="${escaped.testName}" classname="${escaped.packageName}" time="0">`,
        `    <failure message="Security finding: ${escaped.rule}" type="SecurityViolation">`,
        `Rule: ${escaped.rule}`,
        `Severity: ${escaped.severity}`,
        `Details:`,
        escaped.details,
        `    </failure>`,
        `  </testcase>`,
      ].join('\n');
    } else if (finding.severity === 'medium') {
      return [
        `  <testcase name="${escaped.testName}" classname="${escaped.packageName}" time="0">`,
        `    <error message="Security warning: ${escaped.rule}" type="SecurityWarning">`,
        `Rule: ${escaped.rule}`,
        `Severity: ${escaped.severity}`,
        `Details:`,
        escaped.details,
        `    </error>`,
        `  </testcase>`,
      ].join('\n');
    } else {
      // Low severity - pass with system-out
      return [
        `  <testcase name="${escaped.testName}" classname="${escaped.packageName}" time="0">`,
        `    <system-out>`,
        `Rule: ${escaped.rule}`,
        `Severity: ${escaped.severity}`,
        `Details: ${escaped.details}`,
        `    </system-out>`,
        `  </testcase>`,
      ].join('\n');
    }
  }

  /**
   * Format finding as test case name
   */
  private formatTestCaseName(finding: Finding): string {
    const ruleNames: Record<string, string> = {
      lifecycle_script: 'Lifecycle Script Security',
      c2_webhook: 'C2 Communication Check',
      env_snoop: 'Environment Variable Access',
      writes_outside_pkg: 'File System Write Security',
      typosquat_detected: 'Typosquatting Detection',
      phishing_form: 'Phishing Form Detection',
      advanced_obfuscation: 'Obfuscation Analysis',
      url_outside_allowlist: 'Network Domain Validation',
      suspicious_pattern: 'Code Pattern Analysis',
      big_base64_blob: 'Base64 Payload Analysis',
      native_binary_present: 'Native Binary Check',
      yara_match: 'YARA Malware Signature',
    };

    return ruleNames[finding.rule] || finding.rule;
  }

  /**
   * Escape XML special characters
   */
  private escapeXml(text: string): string {
    const replacements: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&apos;',
    };

    return text.replace(/[&<>"']/g, char => replacements[char] || char);
  }
}
