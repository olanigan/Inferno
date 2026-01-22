/**
 * Type definitions for PackageInferno findings and scanner results
 */

export type SeverityLevel = 'low' | 'medium' | 'high';

export type RuleId =
  | 'lifecycle_script'
  | 'c2_webhook'
  | 'env_snoop'
  | 'writes_outside_pkg'
  | 'typosquat_detected'
  | 'phishing_form'
  | 'advanced_obfuscation'
  | 'url_outside_allowlist'
  | 'suspicious_pattern'
  | 'big_base64_blob'
  | 'native_binary_present'
  | 'yara_match';

export interface Finding {
  rule: RuleId;
  severity: SeverityLevel;
  file: string;
  details: {
    explanation: string;
    evidence?: string;
    location?: {
      line?: number;
      column?: number;
    };
  };
}

export interface ScanResult {
  package: string;
  version: string;
  score: number;
  findings: Finding[];
  timestamp: string;
  scanDuration: number; // milliseconds
}

export interface ScanReport {
  results: ScanResult[];
  summary: {
    totalPackages: number;
    maliciousCount: number;
    suspiciousCount: number;
    cleanCount: number;
    totalFindings: number;
  };
  metadata: {
    scanId: string;
    startTime: string;
    endTime: string;
    duration: number;
    cliVersion: string;
  };
}

export const SEVERITY_WEIGHTS: Record<SeverityLevel, number> = {
  low: 1,
  medium: 3,
  high: 5,
};

export const MALICIOUS_THRESHOLD = 12;
export const SUSPICIOUS_THRESHOLD = 7;

export function calculateRiskLevel(score: number): 'clean' | 'suspicious' | 'malicious' {
  if (score >= MALICIOUS_THRESHOLD) return 'malicious';
  if (score >= SUSPICIOUS_THRESHOLD) return 'suspicious';
  return 'clean';
}
