/**
 * Type-safe Docker container management
 */

import Docker, { Container, Network } from 'dockerode';
import { DockerConfig } from '../../types/config.js';
import { ScanResult, Finding } from '../../types/findings.js';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

export interface ScanOptions {
  threshold?: 'suspicious' | 'malicious';
  maxExtractBytes?: number;
  timeout?: number;
}

export class DockerManager {
  private docker: Docker;
  private config: DockerConfig;
  private currentNetwork?: Network;
  private containers: Container[] = [];

  constructor(config: DockerConfig) {
    this.docker = new Docker();
    this.config = config;
  }

  /**
   * Ensure all required images are available
   */
  async ensureImages(): Promise<void> {
    const requiredImages = [
      'ghcr.io/mhaggis/package-inferno/enumerator:main',
      'ghcr.io/mhaggis/package-inferno/fetcher:main',
      'ghcr.io/mhaggis/package-inferno/analyzer:main',
      'postgres:15-alpine',
    ];

    for (const imageName of requiredImages) {
      await this.ensureImage(imageName);
    }
  }

  private async ensureImage(imageName: string): Promise<void> {
    const images = await this.docker.listImages();
    const exists = images.some((img) =>
      img.RepoTags?.includes(imageName)
    );

    if (!exists || this.config.pullPolicy === 'always') {
      console.log(`📥 Pulling image: ${imageName}`);
      await this.pullImage(imageName);
    }
  }

  private async pullImage(imageName: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this.docker.pull(imageName, (err: Error | null, stream: NodeJS.ReadableStream) => {
        if (err) return reject(err);

        this.docker.modem.followProgress(
          stream,
          (err: Error | null) => {
            if (err) return reject(err);
            resolve();
          },
          (event: { status: string; progress?: string }) => {
            if (event.progress) {
              console.log(`   ${event.status}: ${event.progress}`);
            }
          }
        );
      });
    });
  }

  /**
   * Run a complete scan of packages
   */
  async runScan(packages: string[], options: ScanOptions = {}): Promise<ScanResult[]> {
    const scanId = uuidv4();
    const workDir = await this.createWorkDirectory(scanId);

    try {
      // Create isolated network
      this.currentNetwork = await this.createNetwork(scanId);

      // Start database
      const dbContainer = await this.startDatabase(scanId);
      await this.waitForDatabase(dbContainer);

      // Initialize schema
      await this.initializeSchema(dbContainer);

      // Run pipeline
      await this.runEnumerator(packages, workDir);
      await this.runFetcher(workDir);
      await this.runAnalyzer(workDir, options);

      // Read results
      const results = await this.readFindings(workDir, packages);

      return results;
    } finally {
      // Cleanup
      if (this.config.cleanup) {
        await this.cleanup();
        await fs.rm(workDir, { recursive: true, force: true });
      }
    }
  }

  private async createWorkDirectory(scanId: string): Promise<string> {
    const workDir = path.join('/tmp', `inferno-${scanId}`);
    await fs.mkdir(workDir, { recursive: true });
    await fs.mkdir(path.join(workDir, 'out'), { recursive: true });
    await fs.mkdir(path.join(workDir, 'downloads'), { recursive: true });
    await fs.mkdir(path.join(workDir, 'findings'), { recursive: true });
    return workDir;
  }

  private async createNetwork(scanId: string): Promise<Network> {
    const networkName = this.config.network.name || `inferno-${scanId}`;

    const network = await this.docker.createNetwork({
      Name: networkName,
      Driver: 'bridge',
      Internal: this.config.network.isolated,
      Labels: {
        'inferno.scan-id': scanId,
        'inferno.managed': 'true',
      },
    });

    return network;
  }

  private async startDatabase(scanId: string): Promise<Container> {
    const container = await this.docker.createContainer({
      Image: 'postgres:15-alpine',
      name: `inferno-db-${scanId}`,
      Env: [
        'POSTGRES_USER=piuser',
        'POSTGRES_PASSWORD=pipass',
        'POSTGRES_DB=packageinferno',
      ],
      HostConfig: {
        NetworkMode: this.currentNetwork!.id,
        AutoRemove: true,
        Memory: 512 * 1024 * 1024, // 512MB
        Tmpfs: {
          '/var/lib/postgresql/data': 'rw,size=256m', // In-memory for speed
        },
      },
      Cmd: [
        'postgres',
        '-c', 'shared_buffers=128MB',
        '-c', 'fsync=off',
        '-c', 'synchronous_commit=off',
      ],
      Labels: {
        'inferno.scan-id': scanId,
        'inferno.role': 'database',
      },
    });

    await container.start();
    this.containers.push(container);

    return container;
  }

  private async waitForDatabase(container: Container, maxRetries = 30): Promise<void> {
    for (let i = 0; i < maxRetries; i++) {
      try {
        const exec = await container.exec({
          Cmd: ['pg_isready', '-U', 'piuser', '-d', 'packageinferno'],
          AttachStdout: true,
          AttachStderr: true,
        });

        const stream = await exec.start({ Detach: false });
        const output = await this.streamToString(stream);

        if (output.includes('accepting connections')) {
          return;
        }
      } catch (err) {
        // Ignore errors during retries
      }

      await this.sleep(1000);
    }

    throw new Error('Database failed to become ready');
  }

  private async initializeSchema(dbContainer: Container): Promise<void> {
    // Read schema files
    const schemaSQL = await fs.readFile(
      path.join(__dirname, '../../../infra/migrations.sql'),
      'utf-8'
    );

    const scanRunsSQL = await fs.readFile(
      path.join(__dirname, '../../../infra/20251106_scan_runs.sql'),
      'utf-8'
    );

    // Execute schema creation
    await this.execSQL(dbContainer, schemaSQL);
    await this.execSQL(dbContainer, scanRunsSQL);
  }

  private async execSQL(container: Container, sql: string): Promise<void> {
    const exec = await container.exec({
      Cmd: ['psql', '-U', 'piuser', '-d', 'packageinferno', '-c', sql],
      Env: ['PGPASSWORD=pipass'],
      AttachStdout: true,
      AttachStderr: true,
    });

    const stream = await exec.start({ Detach: false });
    await this.streamToString(stream);
  }

  private async runEnumerator(packages: string[], workDir: string): Promise<void> {
    const container = await this.docker.createContainer({
      Image: 'ghcr.io/mhaggis/package-inferno/enumerator:main',
      Env: [
        `SEEDS=${packages.join(',')}`,
        'LOCAL_ONLY=true',
        'OUT_FILE=/out/fetch_queue.ndjson',
        'DB_URL=postgres://piuser:pipass@inferno-db:5432/packageinferno',
      ],
      HostConfig: {
        NetworkMode: this.currentNetwork!.id,
        AutoRemove: true,
        Binds: [
          `${path.join(workDir, 'out')}:/out`,
        ],
      },
    });

    await container.start();
    this.containers.push(container);

    const result = await container.wait();
    if (result.StatusCode !== 0) {
      throw new Error(`Enumerator failed with exit code ${result.StatusCode}`);
    }
  }

  private async runFetcher(workDir: string): Promise<void> {
    const container = await this.docker.createContainer({
      Image: 'ghcr.io/mhaggis/package-inferno/fetcher:main',
      Env: [
        'LOCAL_ONLY=true',
        'IN_FILE=/out/fetch_queue.ndjson',
        'DOWNLOAD_DIR=/downloads',
      ],
      HostConfig: {
        NetworkMode: this.currentNetwork!.id,
        AutoRemove: true,
        Binds: [
          `${path.join(workDir, 'out')}:/out`,
          `${path.join(workDir, 'downloads')}:/downloads`,
        ],
      },
    });

    await container.start();
    this.containers.push(container);

    const result = await container.wait();
    if (result.StatusCode !== 0) {
      throw new Error(`Fetcher failed with exit code ${result.StatusCode}`);
    }
  }

  private async runAnalyzer(workDir: string, options: ScanOptions): Promise<void> {
    const container = await this.docker.createContainer({
      Image: 'ghcr.io/mhaggis/package-inferno/analyzer:main',
      Env: [
        'DOWNLOADS_DIR=/downloads',
        'FINDINGS_DIR=/out/findings',
        `MAX_EXTRACT_BYTES=${options.maxExtractBytes || 0}`,
        'DB_URL=postgres://piuser:pipass@inferno-db:5432/packageinferno',
      ],
      HostConfig: {
        NetworkMode: this.currentNetwork!.id,
        AutoRemove: true,
        Binds: [
          `${path.join(workDir, 'out')}:/out`,
          `${path.join(workDir, 'downloads')}:/downloads`,
        ],
      },
    });

    await container.start();
    this.containers.push(container);

    const result = await container.wait();
    if (result.StatusCode !== 0) {
      throw new Error(`Analyzer failed with exit code ${result.StatusCode}`);
    }
  }

  private async readFindings(workDir: string, packages: string[]): Promise<ScanResult[]> {
    const findingsDir = path.join(workDir, 'findings');
    const results: ScanResult[] = [];

    for (const pkg of packages) {
      const findingFile = path.join(findingsDir, `${pkg}.findings.json`);

      try {
        const content = await fs.readFile(findingFile, 'utf-8');
        const data = JSON.parse(content) as { findings: Finding[] };

        const [name, version] = pkg.split('@');
        const score = this.calculateScore(data.findings);

        results.push({
          package: name,
          version,
          score,
          findings: data.findings,
          timestamp: new Date().toISOString(),
          scanDuration: 0, // TODO: Track duration
        });
      } catch (err) {
        // Package may have no findings file (clean)
        const [name, version] = pkg.split('@');
        results.push({
          package: name,
          version,
          score: 0,
          findings: [],
          timestamp: new Date().toISOString(),
          scanDuration: 0,
        });
      }
    }

    return results;
  }

  private calculateScore(findings: Finding[]): number {
    const weights: Record<string, number> = {
      low: 1,
      medium: 3,
      high: 5,
    };

    return findings.reduce((sum, finding) => sum + (weights[finding.severity] || 0), 0);
  }

  private async cleanup(): Promise<void> {
    // Stop all containers
    for (const container of this.containers) {
      try {
        await container.stop();
        await container.remove();
      } catch (err) {
        // Ignore cleanup errors
      }
    }

    // Remove network
    if (this.currentNetwork) {
      try {
        await this.currentNetwork.remove();
      } catch (err) {
        // Ignore cleanup errors
      }
    }

    this.containers = [];
    this.currentNetwork = undefined;
  }

  private streamToString(stream: NodeJS.ReadableStream): Promise<string> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      stream.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
      stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
      stream.on('error', reject);
    });
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
