/**
 * Type-safe configuration schemas
 */

import { z } from 'zod';

export const ThresholdSchema = z.enum(['suspicious', 'malicious']);
export const OutputFormatSchema = z.enum(['json', 'sarif', 'console', 'junit']);
export const SeveritySchema = z.enum(['low', 'medium', 'high']);

export const PolicyRuleSchema = z.object({
  id: z.string(),
  severity: SeveritySchema.optional(),
  finding: z.string().optional(),
  action: z.enum(['block', 'warn', 'allow']),
  message: z.string().optional(),
  conditions: z.array(z.string()).optional(),
});

export const AllowlistEntrySchema = z.object({
  name: z.string(),
  reason: z.string(),
  expires: z.string().optional(),
  approvedBy: z.string().optional(),
});

export const NotificationsSchema = z.object({
  slack: z
    .object({
      webhook: z.string().url(),
      channel: z.string(),
    })
    .optional(),
  email: z
    .object({
      recipients: z.array(z.string().email()),
      onSeverity: SeveritySchema,
    })
    .optional(),
});

export const PolicyConfigSchema = z.object({
  version: z.number(),
  name: z.string(),
  rules: z.array(PolicyRuleSchema),
  allowlist: z
    .object({
      packages: z.array(AllowlistEntrySchema),
    })
    .optional(),
  thresholds: z
    .object({
      suspicious: z.number().min(0),
      malicious: z.number().min(0),
    })
    .optional(),
  notifications: NotificationsSchema.optional(),
});

export const DockerConfigSchema = z.object({
  maxConcurrent: z.number().min(1).max(50).default(5),
  timeout: z.number().min(0).default(300000), // 5 minutes
  pullPolicy: z.enum(['always', 'missing', 'never']).default('missing'),
  cleanup: z.boolean().default(true),
  network: z
    .object({
      isolated: z.boolean().default(true),
      name: z.string().optional(),
    })
    .default({ isolated: true }),
});

export const CLIConfigSchema = z.object({
  version: z.string(),
  docker: DockerConfigSchema.default({}),
  policy: z.string().optional(), // Path to policy file
  output: z
    .object({
      format: OutputFormatSchema.default('console'),
      directory: z.string().default('./inferno-reports'),
      verbose: z.boolean().default(false),
    })
    .default({}),
  cache: z
    .object({
      enabled: z.boolean().default(true),
      directory: z.string().default('~/.inferno/cache'),
      ttl: z.number().default(86400), // 24 hours
    })
    .default({}),
});

// Infer TypeScript types from Zod schemas
export type Threshold = z.infer<typeof ThresholdSchema>;
export type OutputFormat = z.infer<typeof OutputFormatSchema>;
export type Severity = z.infer<typeof SeveritySchema>;
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;
export type AllowlistEntry = z.infer<typeof AllowlistEntrySchema>;
export type PolicyConfig = z.infer<typeof PolicyConfigSchema>;
export type DockerConfig = z.infer<typeof DockerConfigSchema>;
export type CLIConfig = z.infer<typeof CLIConfigSchema>;
