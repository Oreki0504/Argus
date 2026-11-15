import { z } from 'zod'

// Session-authenticated Console DTOs; never use the CLI Bearer API.
export const objectId = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/)
const timestamp = z.number().int().nonnegative()
const resourceId = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/)
export const taskTypes = [
  'system.info',
  'system.metrics',
  'service.status',
  'ssh.audit',
  'process.list',
  'network.listeners',
] as const
export const taskStates = [
  'PENDING',
  'ACCEPTED',
  'RUNNING',
  'SUCCEEDED',
  'FAILED',
  'UNKNOWN',
] as const
export const taskTypeSchema = z.enum(taskTypes)
const parameterSchema = z.union([
  z.strictObject({}),
  z.strictObject({ service_id: resourceId }),
  z.strictObject({ profile_id: resourceId }),
])
function parametersMatch(value: { task_type: string; parameters: Record<string, unknown> }) {
  const expected =
    value.task_type === 'service.status'
      ? 'service_id'
      : value.task_type === 'ssh.audit'
        ? 'profile_id'
        : null
  const keys = Object.keys(value.parameters)
  return expected ? keys.length === 1 && keys[0] === expected : keys.length === 0
}
export const createTaskSchema = z
  .strictObject({
    node_id: objectId,
    task_type: taskTypeSchema,
    parameters: parameterSchema,
    ttl_seconds: z.number().int().min(10).max(3600),
    execution_timeout_ms: z.number().int().min(1).max(30000),
  })
  .refine(parametersMatch, { message: 'Invalid task parameters', path: ['parameters'] })
export type CreateTask = z.infer<typeof createTaskSchema>
export const managedAgentSchema = z.strictObject({
  node_id: objectId,
  public_id: objectId,
  display_name: z.string(),
  hostname: z.string(),
  tags: z.array(z.string().max(32)).max(16),
  authorization: z.enum(['ACTIVE', 'DISABLED', 'REVOKED']),
  status: z.enum(['active', 'disabled']),
  last_seen_at: timestamp,
  created_at: timestamp,
  agent_version: z.string(),
  protocol_version: z.number().int().positive(),
  certificate_expires_at: timestamp,
})
export type ManagedAgent = z.infer<typeof managedAgentSchema>
export const managedTaskSchema = z
  .strictObject({
    id: objectId,
    node_id: objectId,
    agent_name: z.string(),
    task_type: taskTypeSchema,
    parameters: parameterSchema,
    status: z.enum(taskStates),
    created_at: timestamp,
    dispatch_expires_at: timestamp,
    execution_timeout_ms: z.number().int().min(1).max(30000),
    result_due_at: timestamp,
    execution_authorized_at: timestamp.nullable(),
    result_received_at: timestamp.nullable(),
  })
  .refine(parametersMatch, { message: 'Invalid task parameters' })
export type ManagedTask = z.infer<typeof managedTaskSchema>
export const diagnosticEvidenceSchema = z.strictObject({
  coverage: z.enum(['complete', 'partial', 'unavailable']),
  resources_total: z.number().int().min(0).max(32),
  resources_available: z.number().int().min(0).max(32),
  truncated: z.boolean(),
})
export const diagnosticCollectionSchema = diagnosticEvidenceSchema.extend({
  id: objectId,
  boot_id: objectId,
  collector_version: z.string(),
  started_at: timestamp,
  completed_at: timestamp,
  duration_ms: z.number().int().nonnegative(),
  listener_processes: z
    .strictObject({
      coverage: z.enum(['complete', 'partial', 'unavailable']),
      scanned_processes: z.number().int().nonnegative(),
      scanned_fds: z.number().int().nonnegative(),
      items: z
        .array(
          z.strictObject({
            protocol: z.string(),
            address: z.string(),
            port: z.number().int().min(0).max(65535),
            pid: z.number().int().positive(),
            process_name: z.string(),
            process_start_ticks: z.string().regex(/^[0-9]+$/),
            socket_inode: z.string().regex(/^[0-9]+$/),
          }),
        )
        .max(128),
    })
    .optional(),
})
export const taskDetailSchema = z.strictObject({
  task: managedTaskSchema,
  result: z
    .strictObject({
      status: z.enum(['SUCCEEDED', 'FAILED', 'UNKNOWN']),
      error: z.string().max(128),
      completed_at: timestamp,
      payload: z.record(z.string(), z.json()),
      evidence: diagnosticEvidenceSchema,
      collection: diagnosticCollectionSchema.optional(),
    })
    .nullable(),
})
export type TaskDetail = z.infer<typeof taskDetailSchema>
export const auditEventSchema = z.strictObject({
  id: z.number().int().positive(),
  timestamp,
  actor: z.string(),
  action: z.string(),
  node_id: objectId.nullable(),
  task_id: objectId.nullable(),
  subject_id: objectId.nullable(),
  status: z.string(),
})
export type AuditEvent = z.infer<typeof auditEventSchema>
export const managedUserSchema = z.strictObject({
  id: objectId,
  name: z.string(),
  issuer: z.string(),
  subject: z.string(),
  role: z.enum(['Admin', 'User']),
  status: z.enum(['pending', 'active', 'disabled']),
  created_at: timestamp,
  last_login_at: timestamp.nullable(),
  version: z.number().int().positive(),
})
export type ManagedUser = z.infer<typeof managedUserSchema>
export const updateUserSchema = z.strictObject({
  role: z.enum(['Admin', 'User']),
  status: z.enum(['active', 'disabled']),
  expected_version: z.number().int().positive(),
  confirm_subject: z.string().min(1),
})
export type UpdateUser = z.infer<typeof updateUserSchema>
export const enrollmentRequestSchema = z.strictObject({
  ttl_seconds: z.number().int().min(60).max(3600),
})
export const enrollmentSchema = z.strictObject({
  token: z.string().min(1).max(512),
  expires_at: timestamp,
})
export type Enrollment = z.infer<typeof enrollmentSchema>
export const installerStatusSchema = z.strictObject({
  enabled: z.boolean(),
  platforms: z.array(z.enum(['linux/amd64', 'linux/arm64'])).max(2),
  fleet_origin: z.string(),
})
export const installationSchema = z.strictObject({
  installation_id: objectId,
  url: z
    .string()
    .max(2048)
    .regex(/^https:\/\/[a-z0-9.[\]:-]+\/v1\/console\/install\/[A-Za-z0-9_-]{1,64}$/),
  expires_at: timestamp,
})
export const disableAgentSchema = z.strictObject({ confirm_node_id: objectId })
const page = <T extends z.ZodType>(item: T) =>
  z.strictObject({
    items: z.array(item).max(200),
    total: z.number().int().nonnegative(),
    next_cursor: z.string().max(2048).nullable(),
  })
export const agentsPageSchema = page(managedAgentSchema)
export const tasksPageSchema = page(managedTaskSchema)
export const auditPageSchema = page(auditEventSchema)
export const usersPageSchema = page(managedUserSchema)

export const diagnosticProfileSchema = z.strictObject({
  id: z.enum(['overview', 'system', 'service', 'security']),
  name: z.string(),
  collectors: z.array(taskTypeSchema).min(1).max(6),
  requires_resource: z.boolean(),
})
export const diagnosticProfilesSchema = z.array(diagnosticProfileSchema).max(16)
export const diagnosticRequestSchema = z.strictObject({
  node_ids: z
    .array(objectId)
    .min(1)
    .max(50)
    .refine((ids) => new Set(ids).size === ids.length),
  profile_id: diagnosticProfileSchema.shape.id,
  resource_id: z.string().max(32),
  ttl_seconds: z.number().int().min(10).max(3600),
  execution_timeout_ms: z.number().int().min(1).max(30000),
})
export type DiagnosticRequest = z.infer<typeof diagnosticRequestSchema>
export const diagnosticBatchSchema = z.strictObject({
  id: objectId,
  profile_id: diagnosticProfileSchema.shape.id,
  created_at: timestamp,
  tasks: z
    .array(
      z.strictObject({
        id: objectId,
        node_id: objectId,
        task_type: taskTypeSchema,
        parameters: parameterSchema,
        status: z.enum(taskStates),
        created_at: timestamp,
        dispatch_expires_at: timestamp,
        execution_timeout_ms: z.number().int().positive(),
        result_due_at: timestamp,
      }),
    )
    .max(200),
})
export const alertRuleSchema = z.strictObject({
  id: objectId,
  metric: z.enum(['cpu_percent', 'memory_percent', 'disk_percent', 'telemetry_missing']),
  severity: z.enum(['WARNING', 'CRITICAL']),
  threshold: z.number().nonnegative(),
  for_seconds: z.number().int().nonnegative(),
  recovery_seconds: z.number().int().nonnegative(),
  enabled: z.boolean(),
})
export type AlertRule = z.infer<typeof alertRuleSchema>
export const alertRulesSchema = z.array(alertRuleSchema).max(32)
export const alertSchema = z.strictObject({
  id: objectId,
  node_id: objectId,
  rule_id: objectId,
  severity: z.enum(['WARNING', 'CRITICAL']),
  status: z.enum(['FIRING', 'RESOLVED']),
  opened_at: timestamp,
  last_observed_at: timestamp,
  resolved_at: timestamp,
  reason: z.string(),
})
export const alertsPageSchema = z.strictObject({
  items: z.array(alertSchema).max(200),
  next_cursor: z.string().optional(),
})
export const alertEventSchema = z.strictObject({
  id: z.number().int().positive(),
  alert_id: objectId,
  node_id: objectId,
  rule_id: objectId,
  state: z.enum(['FIRING', 'RESOLVED']),
  timestamp,
  reason: z.string(),
})
export const alertEventsSchema = z.array(alertEventSchema).max(200)

export const agentCapabilitiesSchema = z
  .strictObject({
    agent_version: z.string(),
    protocol_version: z.number().int().positive(),
    policy_version: z.number().int().positive(),
    policy_hash: z.string(),
    supported_collectors: z.array(taskTypeSchema).max(6),
    allowed_collectors: z.array(taskTypeSchema).max(6),
    reported_at: timestamp,
  })
  .nullable()
