/**
 * Scan lockfile command - scans dependencies from package-lock.json
 */

import { Command, Flags, Args } from '@oclif/core';
import { DockerManager } from '../../lib/docker/manager.js';
import { LockfileParser, PackageInfo } from '../../lib/parsers/lockfile.js';
import { ReporterFactory, OutputFormat } from '../../lib/reporters/base.js';
import { CLIConfig } from '../../types/config.js';
import { ScanResult } from '../../types/findings.js';
import * as fs from 'fs/promises';
import * as path from 'path';

export default class ScanLockfile extends Command {
  static description = 'Scan dependencies from package-lock.json';

  static examples = [
    '<%= config.bin %> <%= command.id %> package-lock.json',
    '<%= config.bin %> <%= command.id %> package-lock.json --threshold malicious',
    '<%= config.bin %> <%= command.id %> package-lock.json --compare old-package-lock.json',
    '<%= config.bin %> <%= command.id %> package-lock.json --output sarif --fail-on suspicious',
    '<%= config.bin %> <%= command.id %> package-lock.json --exclude-dev',
  ];

  static flags = {
    threshold: Flags.string({
      char: 't',
      description: 'Minimum severity threshold',
      options: ['suspicious', 'malicious'] as const,
      default: 'suspicious',
    }),
    output: Flags.string({
      char: 'o',
      description: 'Output format',
      options: ['json', 'sarif', 'console', 'junit'] as const,
      default: 'console',
    }),
    'fail-on': Flags.string({
      description: 'Exit with error on severity level',
      options: ['suspicious', 'malicious'] as const,
    }),
    'max-concurrent': Flags.integer({
      description: 'Maximum concurrent scans',
      default: 5,
    }),
    config: Flags.string({
      char: 'c',
      description: 'Path to config file',
      default: '.inferno/config.yml',
    }),
    compare: Flags.string({
      description: 'Compare with previous lockfile (scan only new/updated packages)',
    }),
    'exclude-dev': Flags.boolean({
      description: 'Exclude dev dependencies from scan',
      default: false,
    }),
    'exclude-optional': Flags.boolean({
      description: 'Exclude optional dependencies from scan',
      default: false,
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
  };

  static args = {
    lockfile: Args.string({
      name: 'lockfile',
      required: true,
      description: 'Path to package-lock.json',
    }),
  };

  async run(): Promise<void> {
    const { args, flags } = await this.parse(ScanLockfile);

    // Validate lockfile exists
    const parser = new LockfileParser();
    const validation = await parser.validate(args.lockfile);

    if (!validation.valid) {
      this.error(`Invalid lockfile: ${validation.error}`, { exit: 11 });
    }

    // Get lockfile stats
    const stats = await parser.getStats(args.lockfile);
    this.log(`📋 Lockfile version: ${stats.version}`);
    this.log(`📦 Total packages: ${stats.totalPackages}`);
    this.log(`   Production: ${stats.productionPackages}`);
    this.log(`   Dev: ${stats.devPackages}`);
    this.log(`   Optional: ${stats.optionalPackages}`);
    this.log('');

    // Parse packages
    let packages: PackageInfo[];

    if (flags.compare) {
      this.log(`🔍 Comparing with ${flags.compare}...`);
      const compareValidation = await parser.validate(flags.compare);

      if (!compareValidation.valid) {
        this.error(`Invalid comparison lockfile: ${compareValidation.error}`, {
          exit: 11,
        });
      }

      const newPackages = await parser.extractNewPackages(
        flags.compare,
        args.lockfile
      );

      this.log(`   Found ${newPackages.length} new/updated packages`);
      packages = newPackages;
    } else {
      packages = await parser.parse(args.lockfile);
    }

    // Filter packages
    packages = parser.filterPackages(packages, {
      includeDev: !flags['exclude-dev'],
      includeOptional: !flags['exclude-optional'],
    });

    if (packages.length === 0) {
      this.log('✅ No packages to scan');
      return;
    }

    this.log(`🔍 Scanning ${packages.length} packages...`);
    this.log(`   Threshold: ${flags.threshold}`);
    this.log(`   Output: ${flags.output}`);
    this.log('');

    // Initialize Docker manager
    const docker = new DockerManager({
      maxConcurrent: flags['max-concurrent'],
      configPath: flags.config,
      pullPolicy: 'missing',
      cleanup: true,
      network: {
        isolated: true,
        name: undefined,
      },
    });

    try {
      // Ensure Docker images are available
      if (flags.verbose) {
        this.log('📥 Ensuring Docker images are available...');
      }
      await docker.ensureImages();

      // Format packages for scanning
      const packagesToScan = packages.map(pkg => parser.formatForScan(pkg));

      // Run scan
      const results = await docker.runScan(packagesToScan, {
        threshold: flags.threshold,
      });

      // Generate report
      const reporter = await ReporterFactory.create(flags.output as OutputFormat, {
        verbose: flags.verbose,
        colorOutput: !flags['output-file'],
      });

      const output = await reporter.generate(results);

      // Output results
      if (flags['output-file']) {
        await fs.writeFile(flags['output-file'], output, 'utf-8');
        this.log(`✅ Report written to ${flags['output-file']}`);

        // Also save with correct extension
        const ext = reporter.getFileExtension();
        if (!flags['output-file'].endsWith(`.${ext}`)) {
          const extendedPath = `${flags['output-file']}.${ext}`;
          await fs.writeFile(extendedPath, output, 'utf-8');
          this.log(`   Also saved as ${extendedPath}`);
        }
      } else {
        this.log(output);
      }

      // Determine exit code
      const exitCode = this.determineExitCode(results, flags['fail-on']);

      if (exitCode !== 0) {
        const summary = this.generateExitSummary(results, flags['fail-on']);
        this.error(summary, { exit: exitCode });
      }
    } catch (error) {
      this.error(error as Error, { exit: 10 });
    }
  }

  /**
   * Determine exit code based on findings and fail-on threshold
   */
  private determineExitCode(
    results: ScanResult[],
    failOn?: 'suspicious' | 'malicious'
  ): number {
    if (!failOn) return 0;

    const hasMalicious = results.some(r => r.score >= 12);
    const hasSuspicious = results.some(r => r.score >= 7);

    if (failOn === 'malicious' && hasMalicious) return 1;
    if (failOn === 'suspicious' && (hasMalicious || hasSuspicious)) return 1;

    return 0;
  }

  /**
   * Generate summary message for exit
   */
  private generateExitSummary(
    results: ScanResult[],
    failOn?: 'suspicious' | 'malicious'
  ): string {
    const maliciousCount = results.filter(r => r.score >= 12).length;
    const suspiciousCount = results.filter(r => r.score >= 7 && r.score < 12)
      .length;

    const messages: string[] = ['Scan failed:'];

    if (maliciousCount > 0) {
      messages.push(`  - ${maliciousCount} malicious package(s) detected`);
    }

    if (suspiciousCount > 0) {
      messages.push(`  - ${suspiciousCount} suspicious package(s) detected`);
    }

    messages.push(`  - Threshold: ${failOn}`);

    return messages.join('\n');
  }
}
