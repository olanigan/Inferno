/**
 * Scan specific npm packages for malicious code
 */

import { Command, Flags, Args } from '@oclif/core';
import { DockerManager } from '../../lib/docker/manager.js';
import { SARIFReporter } from '../../lib/reporters/sarif.js';
import { JSONReporter } from '../../lib/reporters/json.js';
import { ConsoleReporter } from '../../lib/reporters/console.js';
import { JUnitReporter } from '../../lib/reporters/junit.js';
import { PolicyEngine } from '../../lib/policy/engine.js';
import { CLIConfig, Threshold, OutputFormat, CLIConfigSchema } from '../../types/config.js';
import { ScanResult, calculateRiskLevel } from '../../types/findings.js';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as yaml from 'js-yaml';

export default class ScanPackage extends Command {
  static description = 'Scan specific npm packages for malicious code';

  static examples = [
    '<%= config.bin %> <%= command.id %> lodash express',
    '<%= config.bin %> <%= command.id %> lodash@4.17.21 express@4.18.0',
    '<%= config.bin %> <%= command.id %> react --threshold malicious --output sarif',
    '<%= config.bin %> <%= command.id %> axios --fail-on suspicious --verbose',
  ];

  static flags = {
    threshold: Flags.custom<Threshold>({
      char: 't',
      description: 'Minimum severity threshold for reporting',
      options: ['suspicious', 'malicious'] as const,
      default: 'suspicious' as Threshold,
    })(),
    output: Flags.custom<OutputFormat>({
      char: 'o',
      description: 'Output format',
      options: ['json', 'sarif', 'console', 'junit'] as const,
      default: 'console' as OutputFormat,
    })(),
    'fail-on': Flags.custom<Threshold>({
      description: 'Exit with error on this severity level or higher',
      options: ['suspicious', 'malicious'] as const,
    })(),
    'max-concurrent': Flags.integer({
      description: 'Maximum number of concurrent scans',
      default: 5,
      min: 1,
      max: 50,
    }),
    config: Flags.string({
      char: 'c',
      description: 'Path to configuration file',
      default: '.inferno/config.yml',
    }),
    policy: Flags.string({
      char: 'p',
      description: 'Path to policy file',
    }),
    'output-file': Flags.string({
      char: 'f',
      description: 'Write output to file instead of stdout',
    }),
    verbose: Flags.boolean({
      char: 'v',
      description: 'Enable verbose logging',
      default: false,
    }),
    'no-cleanup': Flags.boolean({
      description: 'Keep Docker containers and work directories for debugging',
      default: false,
    }),
  };

  static args = {
    packages: Args.string({
      name: 'packages',
      required: true,
      description: 'Space-separated list of package names (e.g., lodash express)',
    }),
  };

  async run(): Promise<void> {
    const { args, flags } = await this.parse(ScanPackage);

    // Parse package list
    const packages = this.parsePackages(args.packages);

    if (packages.length === 0) {
      this.error('No packages specified', { exit: 1 });
    }

    // Load configuration
    const config = await this.loadConfig(flags.config);

    // Override config with CLI flags
    config.docker.maxConcurrent = flags['max-concurrent'];
    config.docker.cleanup = !flags['no-cleanup'];
    config.output.verbose = flags.verbose;

    // Display scan info
    this.log(`🔍 Scanning ${packages.length} package(s)...`);
    if (flags.verbose) {
      this.log(`   Packages: ${packages.join(', ')}`);
      this.log(`   Threshold: ${flags.threshold}`);
      this.log(`   Output: ${flags.output}`);
      if (flags['fail-on']) {
        this.log(`   Fail on: ${flags['fail-on']}`);
      }
    }

    try {
      // Initialize Docker manager
      const docker = new DockerManager(config.docker);

      // Ensure images are available
      this.log('📦 Checking Docker images...');
      await docker.ensureImages();

      // Run scan
      this.log('🚀 Starting scan...');
      const startTime = Date.now();

      const results = await docker.runScan(packages, {
        threshold: flags.threshold,
        timeout: config.docker.timeout,
      });

      const duration = Date.now() - startTime;
      this.log(`✅ Scan completed in ${(duration / 1000).toFixed(2)}s`);

      // Apply policy if specified
      if (flags.policy) {
        const policyEngine = new PolicyEngine(flags.policy);
        await policyEngine.load();

        for (const result of results) {
          const violations = await policyEngine.evaluate(result);
          if (violations.length > 0) {
            result.findings.push(...violations);
          }
        }
      }

      // Generate output
      const reporter = this.getReporter(flags.output);
      const output = await reporter.generate(results, {
        cliVersion: this.config.version,
        threshold: flags.threshold,
      });

      // Write output
      if (flags['output-file']) {
        await fs.writeFile(flags['output-file'], output, 'utf-8');
        this.log(`📄 Report written to: ${flags['output-file']}`);
      } else {
        this.log(output);
      }

      // Display summary
      this.displaySummary(results);

      // Determine exit code
      const exitCode = this.determineExitCode(results, flags['fail-on']);
      if (exitCode !== 0) {
        this.error(
          `Scan failed: ${this.getFailureReason(results, flags['fail-on'])}`,
          { exit: exitCode }
        );
      }
    } catch (error) {
      if (error instanceof Error) {
        this.error(`Scan error: ${error.message}`, { exit: 10 });
      }
      throw error;
    }
  }

  private parsePackages(packagesArg: string): string[] {
    return packagesArg
      .split(/\s+/)
      .map((pkg) => pkg.trim())
      .filter((pkg) => pkg.length > 0);
  }

  private async loadConfig(configPath: string): Promise<CLIConfig> {
    try {
      const content = await fs.readFile(configPath, 'utf-8');
      const data = yaml.load(content);
      return CLIConfigSchema.parse(data);
    } catch (error) {
      // Use default config if file doesn't exist
      return CLIConfigSchema.parse({
        version: '1.0.0',
      });
    }
  }

  private getReporter(format: OutputFormat) {
    const reporters = {
      json: new JSONReporter(),
      sarif: new SARIFReporter(),
      console: new ConsoleReporter(),
      junit: new JUnitReporter(),
    } as const;

    return reporters[format];
  }

  private displaySummary(results: ScanResult[]): void {
    const summary = {
      total: results.length,
      malicious: 0,
      suspicious: 0,
      clean: 0,
      totalFindings: 0,
    };

    for (const result of results) {
      const riskLevel = calculateRiskLevel(result.score);

      if (riskLevel === 'malicious') summary.malicious++;
      else if (riskLevel === 'suspicious') summary.suspicious++;
      else summary.clean++;

      summary.totalFindings += result.findings.length;
    }

    this.log('\n📊 Summary:');
    this.log(`   Total packages: ${summary.total}`);
    this.log(`   ❌ Malicious: ${summary.malicious}`);
    this.log(`   ⚠️  Suspicious: ${summary.suspicious}`);
    this.log(`   ✅ Clean: ${summary.clean}`);
    this.log(`   Total findings: ${summary.totalFindings}`);
  }

  private determineExitCode(results: ScanResult[], failOn?: Threshold): number {
    if (!failOn) return 0;

    const hasMalicious = results.some(
      (r) => calculateRiskLevel(r.score) === 'malicious'
    );
    const hasSuspicious = results.some(
      (r) => calculateRiskLevel(r.score) === 'suspicious'
    );

    if (failOn === 'malicious' && hasMalicious) return 1;
    if (failOn === 'suspicious' && (hasMalicious || hasSuspicious)) return 1;

    return 0;
  }

  private getFailureReason(results: ScanResult[], failOn?: Threshold): string {
    const maliciousCount = results.filter(
      (r) => calculateRiskLevel(r.score) === 'malicious'
    ).length;
    const suspiciousCount = results.filter(
      (r) => calculateRiskLevel(r.score) === 'suspicious'
    ).length;

    if (failOn === 'malicious' && maliciousCount > 0) {
      return `Found ${maliciousCount} malicious package(s)`;
    }

    if (failOn === 'suspicious') {
      if (maliciousCount > 0) {
        return `Found ${maliciousCount} malicious package(s)`;
      }
      if (suspiciousCount > 0) {
        return `Found ${suspiciousCount} suspicious package(s)`;
      }
    }

    return 'Unknown failure';
  }
}
