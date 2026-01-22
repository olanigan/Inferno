#!/usr/bin/env tsx
/**
 * Simple test script to demonstrate lockfile parsing
 */

import { LockfileParser } from './src/lib/parsers/lockfile.js';
import * as path from 'path';

async function main() {
  const lockfilePath = path.join(process.cwd(), '../enumerator/package-lock.json');

  console.log('🔍 PackageInferno Lockfile Parser Test\n');
  console.log(`Parsing: ${lockfilePath}\n`);

  const parser = new LockfileParser();

  // Validate lockfile
  console.log('📋 Validating lockfile...');
  const validation = await parser.validate(lockfilePath);

  if (!validation.valid) {
    console.error(`❌ Invalid lockfile: ${validation.error}`);
    process.exit(1);
  }

  console.log('✅ Lockfile is valid\n');

  // Get statistics
  console.log('📊 Lockfile Statistics:');
  const stats = await parser.getStats(lockfilePath);
  console.log(`   Version: ${stats.version}`);
  console.log(`   Total packages: ${stats.totalPackages}`);
  console.log(`   Production: ${stats.productionPackages}`);
  console.log(`   Dev: ${stats.devPackages}`);
  console.log(`   Optional: ${stats.optionalPackages}\n`);

  // Parse all packages
  console.log('📦 Parsing packages...');
  const packages = await parser.parse(lockfilePath);

  console.log(`   Found ${packages.length} packages\n`);

  // Show first 10 packages
  console.log('📋 Sample packages (first 10):');
  for (const pkg of packages.slice(0, 10)) {
    const type = pkg.isDev ? '[dev]' : pkg.isOptional ? '[opt]' : '[prod]';
    console.log(`   ${type} ${pkg.name}@${pkg.version}`);
  }

  if (packages.length > 10) {
    console.log(`   ... and ${packages.length - 10} more\n`);
  }

  // Show packages formatted for scanning
  console.log('\n🔍 Packages ready for scanning:');
  const scanPackages = packages.slice(0, 5).map(pkg => parser.formatForScan(pkg));
  for (const scanPkg of scanPackages) {
    console.log(`   ${scanPkg}`);
  }
  console.log(`   ... and ${packages.length - 5} more\n`);

  console.log('✅ Lockfile parsing test completed successfully!\n');
  console.log('💡 To scan these packages with PackageInferno:');
  console.log('   inferno scan lockfile ../enumerator/package-lock.json\n');
}

main().catch(error => {
  console.error('❌ Error:', error);
  process.exit(1);
});
