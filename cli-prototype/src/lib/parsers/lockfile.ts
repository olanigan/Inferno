/**
 * package-lock.json parser with support for v1, v2, and v3 formats
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { z } from 'zod';

// Type definitions for package-lock.json formats

interface PackageLockV1 {
  name: string;
  version: string;
  lockfileVersion: 1;
  dependencies?: Record<string, {
    version: string;
    resolved?: string;
    integrity?: string;
    dev?: boolean;
    optional?: boolean;
  }>;
}

interface PackageLockV2V3 {
  name: string;
  version: string;
  lockfileVersion: 2 | 3;
  packages?: Record<string, {
    version?: string;
    resolved?: string;
    integrity?: string;
    dev?: boolean;
    optional?: boolean;
    dependencies?: Record<string, string>;
  }>;
  dependencies?: Record<string, {
    version: string;
    resolved?: string;
    integrity?: string;
  }>;
}

type PackageLock = PackageLockV1 | PackageLockV2V3;

export interface PackageInfo {
  name: string;
  version: string;
  resolved?: string;
  integrity?: string;
  isDev: boolean;
  isOptional: boolean;
}

/**
 * Parser for package-lock.json with support for all versions
 */
export class LockfileParser {
  /**
   * Parse package-lock.json and extract all packages
   */
  async parse(lockfilePath: string): Promise<PackageInfo[]> {
    const content = await fs.readFile(lockfilePath, 'utf-8');
    const lockfile = JSON.parse(content) as PackageLock;

    if (!lockfile.lockfileVersion) {
      throw new Error('Invalid package-lock.json: missing lockfileVersion');
    }

    switch (lockfile.lockfileVersion) {
      case 1:
        return this.parseV1(lockfile as PackageLockV1);

      case 2:
      case 3:
        return this.parseV2V3(lockfile as PackageLockV2V3);

      default:
        throw new Error(
          `Unsupported lockfile version: ${lockfile.lockfileVersion}`
        );
    }
  }

  /**
   * Parse v1 format (npm 5.x - 6.x)
   */
  private parseV1(lockfile: PackageLockV1): PackageInfo[] {
    const packages: PackageInfo[] = [];

    if (!lockfile.dependencies) {
      return packages;
    }

    for (const [name, details] of Object.entries(lockfile.dependencies)) {
      packages.push({
        name,
        version: details.version,
        resolved: details.resolved,
        integrity: details.integrity,
        isDev: details.dev || false,
        isOptional: details.optional || false,
      });
    }

    return packages;
  }

  /**
   * Parse v2/v3 format (npm 7.x+)
   */
  private parseV2V3(lockfile: PackageLockV2V3): PackageInfo[] {
    const packages: PackageInfo[] = [];

    if (!lockfile.packages) {
      return packages;
    }

    for (const [pkgPath, details] of Object.entries(lockfile.packages)) {
      // Skip the root package (empty string or "")
      if (!pkgPath || pkgPath === '') {
        continue;
      }

      // Extract package name from path
      // Format: "node_modules/package-name" or "node_modules/@scope/package-name"
      const name = this.extractPackageName(pkgPath);

      if (!name || !details.version) {
        continue;
      }

      packages.push({
        name,
        version: details.version,
        resolved: details.resolved,
        integrity: details.integrity,
        isDev: details.dev || false,
        isOptional: details.optional || false,
      });
    }

    return packages;
  }

  /**
   * Extract package name from node_modules path
   */
  private extractPackageName(pkgPath: string): string {
    // Remove "node_modules/" prefix
    const withoutPrefix = pkgPath.replace(/^node_modules\//, '');

    // Handle scoped packages (@scope/name)
    if (withoutPrefix.startsWith('@')) {
      const parts = withoutPrefix.split('/');
      if (parts.length >= 2) {
        return `${parts[0]}/${parts[1]}`;
      }
    }

    // Handle regular packages
    const parts = withoutPrefix.split('/');
    return parts[0];
  }

  /**
   * Compare two lockfiles and return new/changed packages
   */
  async diff(
    oldLockfilePath: string,
    newLockfilePath: string
  ): Promise<{
    added: PackageInfo[];
    removed: PackageInfo[];
    updated: PackageInfo[];
  }> {
    const oldPackages = await this.parse(oldLockfilePath);
    const newPackages = await this.parse(newLockfilePath);

    const oldMap = new Map(
      oldPackages.map(pkg => [`${pkg.name}@${pkg.version}`, pkg])
    );
    const newMap = new Map(
      newPackages.map(pkg => [`${pkg.name}@${pkg.version}`, pkg])
    );

    const added: PackageInfo[] = [];
    const removed: PackageInfo[] = [];
    const updated: PackageInfo[] = [];

    // Find added and updated packages
    for (const [key, newPkg] of newMap.entries()) {
      if (!oldMap.has(key)) {
        // Check if package name exists but with different version
        const oldVersion = oldPackages.find(p => p.name === newPkg.name);
        if (oldVersion) {
          updated.push(newPkg);
        } else {
          added.push(newPkg);
        }
      }
    }

    // Find removed packages
    for (const [key, oldPkg] of oldMap.entries()) {
      if (!newMap.has(key)) {
        const newVersion = newPackages.find(p => p.name === oldPkg.name);
        if (!newVersion) {
          removed.push(oldPkg);
        }
      }
    }

    return { added, removed, updated };
  }

  /**
   * Extract only new packages from lockfile comparison
   */
  async extractNewPackages(
    oldLockfilePath: string,
    newLockfilePath: string
  ): Promise<PackageInfo[]> {
    const { added, updated } = await this.diff(oldLockfilePath, newLockfilePath);
    return [...added, ...updated];
  }

  /**
   * Format package for scanning (name@version)
   */
  formatForScan(pkg: PackageInfo): string {
    return `${pkg.name}@${pkg.version}`;
  }

  /**
   * Filter packages by type
   */
  filterPackages(
    packages: PackageInfo[],
    options: {
      includeDev?: boolean;
      includeOptional?: boolean;
    } = {}
  ): PackageInfo[] {
    const { includeDev = true, includeOptional = true } = options;

    return packages.filter(pkg => {
      if (!includeDev && pkg.isDev) return false;
      if (!includeOptional && pkg.isOptional) return false;
      return true;
    });
  }

  /**
   * Validate lockfile exists and is readable
   */
  async validate(lockfilePath: string): Promise<{
    valid: boolean;
    error?: string;
  }> {
    try {
      const stats = await fs.stat(lockfilePath);

      if (!stats.isFile()) {
        return {
          valid: false,
          error: 'Path is not a file',
        };
      }

      const content = await fs.readFile(lockfilePath, 'utf-8');
      const lockfile = JSON.parse(content);

      if (!lockfile.lockfileVersion) {
        return {
          valid: false,
          error: 'Missing lockfileVersion field',
        };
      }

      if (![1, 2, 3].includes(lockfile.lockfileVersion)) {
        return {
          valid: false,
          error: `Unsupported lockfileVersion: ${lockfile.lockfileVersion}`,
        };
      }

      return { valid: true };
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Get lockfile version
   */
  async getVersion(lockfilePath: string): Promise<1 | 2 | 3 | null> {
    try {
      const content = await fs.readFile(lockfilePath, 'utf-8');
      const lockfile = JSON.parse(content);
      return lockfile.lockfileVersion || null;
    } catch {
      return null;
    }
  }

  /**
   * Get statistics about lockfile
   */
  async getStats(lockfilePath: string): Promise<{
    version: number;
    totalPackages: number;
    devPackages: number;
    optionalPackages: number;
    productionPackages: number;
  }> {
    const packages = await this.parse(lockfilePath);
    const version = await this.getVersion(lockfilePath);

    return {
      version: version || 0,
      totalPackages: packages.length,
      devPackages: packages.filter(p => p.isDev).length,
      optionalPackages: packages.filter(p => p.isOptional).length,
      productionPackages: packages.filter(p => !p.isDev && !p.isOptional).length,
    };
  }
}
