import { http, HttpResponse } from 'msw'
import type { Identity, Summary } from '../api/contracts'
import {
  createTaskSchema,
  diagnosticRequestSchema,
  diagnosticProfilesSchema,
  diagnosticBatchSchema,
  alertRuleSchema,
  type AlertRule,
  disableAgentSchema,
  enrollmentRequestSchema,
  updateUserSchema,
  type ManagedAgent,
  type ManagedTask,
  type ManagedUser,
  type AuditEvent,
  type TaskDetail,
} from '../api/management-contracts'

// Development-only state. No real task dispatch, credentials, identities or enrollment.
export function managementFixture(summary: Summary) {
  const now = summary.generated_at
  const agents: ManagedAgent[] = summary.nodes.map((node, i) => ({
    node_id: `node-${String(i + 1).padStart(4, '0')}`,
    public_id: node.public_id,
    display_name: node.display_name,
    hostname: `preview-linux-${i + 1}`,
    tags: node.tags,
    authorization: node.status.authorization,
    status: 'active',
    last_seen_at: node.last_seen_at,
    created_at: now - 86400 * 28,
    agent_version: '0.1.0-preview',
    protocol_version: 1,
    certificate_expires_at: now + 86400 * (i === 3 ? 3 : 24),
  }))
  const tasks: TaskDetail[] = agents.slice(0, 6).map((agent, i): TaskDetail => {
    const status = (['SUCCEEDED', 'RUNNING', 'FAILED', 'UNKNOWN', 'PENDING', 'ACCEPTED'] as const)[
      i
    ]
    const task: ManagedTask = {
      id: `task-preview-${i + 1}`,
      node_id: agent.node_id,
      agent_name: agent.display_name,
      task_type: (
        [
          'system.info',
          'system.metrics',
          'service.status',
          'ssh.audit',
          'process.list',
          'network.listeners',
        ] as const
      )[i],
      parameters: i === 2 ? { service_id: 'journal' } : i === 3 ? { profile_id: 'host' } : {},
      status,
      created_at: now - (i + 1) * 120,
      dispatch_expires_at: now + 300,
      execution_timeout_ms: 10000,
      result_due_at: now + 370,
      execution_authorized_at: ['PENDING', 'ACCEPTED'].includes(status)
        ? null
        : now - (i + 1) * 120 + 2,
      result_received_at: status === 'SUCCEEDED' || status === 'FAILED' ? now - i * 120 - 80 : null,
    }
    return {
      task,
      result:
        status === 'SUCCEEDED'
          ? {
              status,
              error: '',
              evidence: {
                coverage: 'complete',
                resources_total: 1,
                resources_available: 1,
                truncated: false,
              },
              completed_at: now - 80,
              payload: { os: 'Linux', architecture: 'x86_64', kernel: '6.8.0' },
            }
          : status === 'FAILED'
            ? {
                status,
                error: 'local_policy_denied',
                evidence: {
                  coverage: 'unavailable',
                  resources_total: 0,
                  resources_available: 0,
                  truncated: false,
                },
                completed_at: now - i * 120 - 80,
                payload: {},
              }
            : null,
    }
  })
  const users: ManagedUser[] = [
    {
      id: 'preview-admin',
      name: 'Alex Morgan',
      role: 'Admin',
      status: 'active',
      subject: 'alex-preview',
      last_login_at: now - 60,
    },
    {
      id: 'preview-user',
      name: 'Sam Taylor',
      role: 'User',
      status: 'active',
      subject: 'sam-preview',
      last_login_at: now - 3600,
    },
    {
      id: 'preview-pending',
      name: 'Jamie Chen',
      role: 'User',
      status: 'pending',
      subject: 'jamie-preview',
      last_login_at: null,
    },
    {
      id: 'preview-disabled',
      name: 'Robin Lee',
      role: 'User',
      status: 'disabled',
      subject: 'robin-preview',
      last_login_at: now - 86400 * 4,
    },
  ].map(
    (user) =>
      ({
        ...user,
        issuer: 'https://identity.example.test',
        created_at: now - 86400 * 20,
        version: 1,
      }) as ManagedUser,
  )
  const audit: AuditEvent[] = [...tasks].reverse().map(({ task }, i) => ({
    id: i + 1,
    timestamp: task.created_at,
    actor: 'Alex Morgan',
    action: 'task.create',
    node_id: task.node_id,
    task_id: task.id,
    subject_id: null,
    status: 'accepted',
  }))
  let sequence = audit.length
  const addAudit = (action: string, fields: Partial<AuditEvent> = {}) => {
    audit.unshift({
      id: ++sequence,
      timestamp: Math.floor(Date.now() / 1000),
      actor: 'Alex Morgan',
      action,
      node_id: null,
      task_id: null,
      subject_id: null,
      status: 'accepted',
      ...fields,
    })
  }
  return { agents, tasks, users, audit, addAudit }
}

export function managementHandlers(
  state: ReturnType<typeof managementFixture>,
  viewer: () => Identity | null,
  csrf: string,
) {
  const root = '/v1/console/admin'
  const json = (body: unknown, status = 200) =>
    HttpResponse.json(body as never, { status, headers: { 'Cache-Control': 'no-store' } })
  const problem = (code: string, status = 400) => json({ code }, status)
  function authorize(
    request: Request,
    capability: Identity['capabilities'][number],
    write = false,
  ) {
    const user = viewer()
    if (!user) return problem('session_expired', 401)
    if (user.role !== 'Admin' || !user.capabilities.includes(capability))
      return problem('forbidden', 403)
    if (write && request.headers.get('X-CSRF-Token') !== csrf) return problem('csrf_invalid', 403)
    return null
  }
  const readBody = async (request: Request): Promise<unknown> => {
    try {
      return await request.json()
    } catch {
      return null
    }
  }
  function page<T>(items: T[], params: URLSearchParams) {
    const limit = Math.min(200, Math.max(1, Number(params.get('limit')) || 8))
    const offset = Number(params.get('cursor')?.replace(/^offset-/, '') ?? 0)
    if (!Number.isSafeInteger(offset) || offset < 0) return problem('invalid_request')
    return json({
      items: items.slice(offset, offset + limit),
      total: items.length,
      next_cursor: offset + limit < items.length ? `offset-${offset + limit}` : null,
    })
  }
  const textMatch = (value: string, query: string | null) =>
    !query || value.toLowerCase().includes(query.toLowerCase())
  const randomId = () =>
    Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) =>
      byte.toString(16).padStart(2, '0'),
    ).join('')
  const newlyCreated = new Set<string>()
  function advance() {
    const now = Math.floor(Date.now() / 1000)
    for (const entry of state.tasks) {
      if (!newlyCreated.has(entry.task.id) || entry.result) continue
      const elapsed = now - entry.task.created_at
      entry.task.status =
        elapsed < 2 ? 'PENDING' : elapsed < 5 ? 'ACCEPTED' : elapsed < 9 ? 'RUNNING' : 'SUCCEEDED'
      if (elapsed >= 5) entry.task.execution_authorized_at = entry.task.created_at + 5
      if (elapsed >= 9) {
        entry.task.result_received_at = now
        entry.result = {
          status: 'SUCCEEDED',
          error: '',
          evidence: {
            coverage: 'complete',
            resources_total: 1,
            resources_available: 1,
            truncated: false,
          },
          completed_at: now,
          payload: {
            preview: true,
            collector: entry.task.task_type,
            observation: 'Simulated diagnostic completed; no agent was contacted.',
          },
        }
        state.addAudit('task.complete', {
          node_id: entry.task.node_id,
          task_id: entry.task.id,
          status: 'SUCCEEDED',
        })
      }
    }
  }
  const profiles = diagnosticProfilesSchema.parse([
    {
      id: 'overview',
      name: 'System investigation',
      collectors: ['system.info', 'system.metrics', 'process.list', 'network.listeners'],
      requires_resource: false,
    },
    {
      id: 'system',
      name: 'System snapshot',
      collectors: ['system.info', 'system.metrics'],
      requires_resource: false,
    },
    {
      id: 'service',
      name: 'Service status',
      collectors: ['service.status'],
      requires_resource: true,
    },
    {
      id: 'security',
      name: 'SSH configuration audit',
      collectors: ['ssh.audit'],
      requires_resource: true,
    },
  ])
  const batches = new Map<
    string,
    { id: string; profile_id: string; created_at: number; taskIds: string[] }
  >()
  const rules: AlertRule[] = [
    {
      id: 'cpu-critical',
      metric: 'cpu_percent',
      severity: 'CRITICAL',
      threshold: 90,
      for_seconds: 120,
      recovery_seconds: 120,
      enabled: true,
    },
    {
      id: 'telemetry-missing',
      metric: 'telemetry_missing',
      severity: 'WARNING',
      threshold: 180,
      for_seconds: 0,
      recovery_seconds: 120,
      enabled: true,
    },
  ]
  const batchResponse = (batch: {
    id: string
    profile_id: string
    created_at: number
    taskIds: string[]
  }) =>
    diagnosticBatchSchema.parse({
      id: batch.id,
      profile_id: batch.profile_id,
      created_at: batch.created_at,
      tasks: batch.taskIds.map((taskId) => {
        const task = state.tasks.find((entry) => entry.task.id === taskId)!.task
        return {
          id: task.id,
          node_id: task.node_id,
          task_type: task.task_type,
          parameters: task.parameters,
          status: task.status,
          created_at: task.created_at,
          dispatch_expires_at: task.dispatch_expires_at,
          execution_timeout_ms: task.execution_timeout_ms,
          result_due_at: task.result_due_at,
        }
      }),
    })
  return [
    http.get(
      `${root}/diagnostic-profiles`,
      ({ request }) => authorize(request, 'tasks:read') ?? json(profiles),
    ),
    http.post(`${root}/diagnostics`, async ({ request }) => {
      const denied = authorize(request, 'tasks:write', true)
      if (denied) return denied
      const parsed = diagnosticRequestSchema.safeParse(await readBody(request))
      if (!parsed.success) return problem('invalid_request')
      const value = parsed.data
      const profile = profiles.find((entry) => entry.id === value.profile_id)!
      const agents = value.node_ids.map((id) => state.agents.find((agent) => agent.node_id === id))
      if (agents.some((agent) => !agent || agent.status !== 'active'))
        return problem('node_disabled', 409)
      const now = Math.floor(Date.now() / 1000)
      const taskIds: string[] = []
      for (const agent of agents)
        for (const task_type of profile.collectors) {
          const id = randomId()
          taskIds.push(id)
          newlyCreated.add(id)
          state.tasks.unshift({
            task: {
              id,
              node_id: agent!.node_id,
              agent_name: agent!.display_name,
              task_type,
              parameters:
                task_type === 'service.status'
                  ? { service_id: value.resource_id }
                  : task_type === 'ssh.audit'
                    ? { profile_id: value.resource_id }
                    : {},
              status: 'PENDING',
              created_at: now,
              dispatch_expires_at: now + value.ttl_seconds,
              execution_timeout_ms: value.execution_timeout_ms,
              result_due_at: now + value.ttl_seconds + 60,
              execution_authorized_at: null,
              result_received_at: null,
            },
            result: null,
          })
        }
      const batch = { id: randomId(), profile_id: value.profile_id, created_at: now, taskIds }
      batches.set(batch.id, batch)
      return json(batchResponse(batch))
    }),
    http.get(`${root}/diagnostics/:id`, ({ request, params }) => {
      const denied = authorize(request, 'tasks:read')
      if (denied) return denied
      advance()
      const batch = batches.get(String(params.id))
      return batch ? json(batchResponse(batch)) : problem('not_found', 404)
    }),
    http.post(`${root}/tasks/:id/cancel`, ({ request, params }) => {
      const denied = authorize(request, 'tasks:write', true)
      if (denied) return denied
      const entry = state.tasks.find((item) => item.task.id === params.id)
      if (!entry) return problem('not_found', 404)
      if (entry.task.status !== 'PENDING') return problem('state_conflict', 409)
      entry.task.status = 'FAILED'
      entry.result = {
        status: 'FAILED',
        error: 'cancelled_before_dispatch',
        completed_at: Math.floor(Date.now() / 1000),
        payload: {},
        evidence: {
          coverage: 'unavailable',
          resources_total: 0,
          resources_available: 0,
          truncated: false,
        },
      }
      return json({})
    }),
    http.get(
      `${root}/alert-rules`,
      ({ request }) => authorize(request, 'audit:read') ?? json(rules),
    ),
    http.post(`${root}/alert-rules`, async ({ request }) => {
      const denied = authorize(request, 'audit:read', true)
      if (denied) return denied
      const rule = alertRuleSchema.safeParse(await readBody(request))
      if (!rule.success) return problem('invalid_request')
      const at = rules.findIndex((value) => value.id === rule.data.id)
      if (at < 0) rules.push(rule.data)
      else rules[at] = rule.data
      return json({})
    }),
    http.get(
      `${root}/alerts`,
      ({ request }) => authorize(request, 'audit:read') ?? json({ items: [], next_cursor: '' }),
    ),
    http.get(`${root}/alert-events`, ({ request }) => authorize(request, 'audit:read') ?? json([])),
    http.get(`${root}/agents`, ({ request }) => {
      const denied = authorize(request, 'agents:read')
      if (denied) return denied
      const p = new URL(request.url).searchParams
      return page(
        state.agents.filter(
          (agent) =>
            (!p.get('status') || agent.status === p.get('status')) &&
            (!p.get('public_id') || agent.public_id === p.get('public_id')) &&
            textMatch(`${agent.display_name} ${agent.hostname} ${agent.node_id}`, p.get('q')),
        ),
        p,
      )
    }),
    http.get(`${root}/installer`, ({ request }) => {
      const denied = authorize(request, 'agents:read')
      if (denied) return denied
      return json({
        enabled: true,
        platforms: ['linux/amd64', 'linux/arm64'],
        fleet_origin: 'https://fleet.example.invalid:8443',
      })
    }),
    http.post(`${root}/installations`, async ({ request }) => {
      const denied = authorize(request, 'agents:write', true)
      if (denied) return denied
      const parsed = enrollmentRequestSchema.safeParse(await readBody(request))
      if (!parsed.success) return problem('invalid_request')
      const id = `preview-${randomId()}`
      state.addAudit('console.installation.create', { subject_id: id })
      return json({
        installation_id: id,
        url: `https://console.example.invalid/v1/console/install/${id}`,
        expires_at: Math.floor(Date.now() / 1000) + parsed.data.ttl_seconds,
      })
    }),
    http.post(`${root}/enrollment-tokens`, async ({ request }) => {
      const denied = authorize(request, 'agents:write', true)
      if (denied) return denied
      const parsed = enrollmentRequestSchema.safeParse(await readBody(request))
      if (!parsed.success) return problem('invalid_request')
      state.addAudit('enrollment.create')
      return json({
        token: `preview-enrollment-${randomId()}`,
        expires_at: Math.floor(Date.now() / 1000) + parsed.data.ttl_seconds,
      })
    }),
    http.get(
      `${root}/agents/:id/capabilities`,
      ({ request }) => authorize(request, 'agents:read') ?? json(null),
    ),
    http.post(`${root}/agents/:id/tags`, async ({ request, params }) => {
      const denied = authorize(request, 'agents:write', true)
      if (denied) return denied
      const body = (await readBody(request)) as { tags: string[] }
      const agent = state.agents.find((value) => value.node_id === params.id)
      if (!agent) return problem('not_found', 404)
      agent.tags = body.tags
      return json({})
    }),
    http.post(`${root}/agents/:id/revoke`, async ({ request, params }) => {
      const denied = authorize(request, 'agents:write', true)
      if (denied) return denied
      const body = (await readBody(request)) as { confirm_node_id: string }
      const agent = state.agents.find((value) => value.node_id === params.id)
      if (!agent) return problem('not_found', 404)
      if (body.confirm_node_id !== agent.node_id) return problem('invalid_request')
      agent.authorization = 'REVOKED'
      agent.status = 'disabled'
      return json({})
    }),
    http.post(`${root}/agents/:id/rename`, async ({ request, params }) => {
      const denied = authorize(request, 'agents:write', true)
      if (denied) return denied
      const body = (await readBody(request)) as { display_name?: string }
      if (
        typeof body.display_name !== 'string' ||
        !body.display_name.trim() ||
        body.display_name.trim().length > 64
      )
        return problem('invalid_request')
      const agent = state.agents.find((a) => a.node_id === params.id)
      if (!agent) return problem('not_found', 404)
      agent.display_name = body.display_name.trim()
      for (const entry of state.tasks)
        if (entry.task.node_id === agent.node_id) entry.task.agent_name = agent.display_name
      state.addAudit('node.rename', { node_id: agent.node_id })
      return json({})
    }),
    http.post(`${root}/agents/:id/delete`, async ({ request, params }) => {
      const denied = authorize(request, 'agents:write', true)
      if (denied) return denied
      const body = disableAgentSchema.safeParse(await readBody(request))
      if (!body.success || body.data.confirm_node_id !== params.id)
        return problem('invalid_request')
      const index = state.agents.findIndex((a) => a.node_id === params.id)
      if (index < 0) return problem('not_found', 404)
      state.agents.splice(index, 1)
      for (let i = state.tasks.length - 1; i >= 0; i--)
        if (state.tasks[i].task.node_id === params.id) state.tasks.splice(i, 1)
      state.addAudit('node.delete', { node_id: String(params.id) })
      return json({})
    }),
    http.post(`${root}/agents/:id/disable`, async ({ request, params }) => {
      const denied = authorize(request, 'agents:write', true)
      if (denied) return denied
      const body = disableAgentSchema.safeParse(await readBody(request))
      if (!body.success || body.data.confirm_node_id !== params.id)
        return problem('invalid_request')
      const agent = state.agents.find((item) => item.node_id === params.id)
      if (!agent) return problem('not_found', 404)
      if (agent.status === 'active') {
        agent.status = 'disabled'
        agent.authorization = 'DISABLED'
        for (const entry of state.tasks.filter(
          (entry) =>
            entry.task.node_id === agent.node_id &&
            ['PENDING', 'ACCEPTED', 'RUNNING'].includes(entry.task.status),
        )) {
          const status = entry.task.status === 'PENDING' ? 'FAILED' : 'UNKNOWN'
          entry.task.status = status
          entry.task.result_received_at = Math.floor(Date.now() / 1000)
          entry.result = {
            status,
            error: 'node_disabled',
            evidence: {
              coverage: 'unavailable',
              resources_total: 0,
              resources_available: 0,
              truncated: false,
            },
            completed_at: entry.task.result_received_at,
            payload: {},
          }
        }
        state.addAudit('node.disable', { node_id: agent.node_id })
      }
      return json(agent)
    }),
    http.get(`${root}/tasks`, ({ request }) => {
      const denied = authorize(request, 'tasks:read')
      if (denied) return denied
      advance()
      const p = new URL(request.url).searchParams
      return page(
        state.tasks
          .map((entry) => entry.task)
          .filter(
            (task) =>
              (!p.get('node_id') || task.node_id === p.get('node_id')) &&
              (!p.get('status') || task.status === p.get('status')) &&
              (!p.get('task_type') || task.task_type === p.get('task_type')),
          )
          .sort((a, b) => b.created_at - a.created_at || b.id.localeCompare(a.id)),
        p,
      )
    }),
    http.get(`${root}/tasks/:id`, ({ request, params }) => {
      const denied = authorize(request, 'tasks:read')
      if (denied) return denied
      advance()
      const task = state.tasks.find((entry) => entry.task.id === params.id)
      return task ? json(task) : problem('not_found', 404)
    }),
    http.post(`${root}/tasks`, async ({ request }) => {
      const denied = authorize(request, 'tasks:write', true)
      if (denied) return denied
      const body = createTaskSchema.safeParse(await readBody(request))
      if (!body.success) return problem('invalid_request')
      const agent = state.agents.find((agent) => agent.node_id === body.data.node_id)
      if (!agent) return problem('not_found', 404)
      if (agent.status === 'disabled') return problem('node_disabled', 409)
      const now = Math.floor(Date.now() / 1000)
      const task: ManagedTask = {
        id: `task-${randomId()}`,
        node_id: agent.node_id,
        agent_name: agent.display_name,
        task_type: body.data.task_type,
        parameters: body.data.parameters,
        status: 'PENDING',
        created_at: now,
        dispatch_expires_at: now + body.data.ttl_seconds,
        execution_timeout_ms: body.data.execution_timeout_ms,
        result_due_at: now + body.data.ttl_seconds + 90,
        execution_authorized_at: null,
        result_received_at: null,
      }
      state.tasks.unshift({ task, result: null })
      newlyCreated.add(task.id)
      state.addAudit('task.create', { node_id: task.node_id, task_id: task.id })
      return json(task)
    }),
    http.get(`${root}/audit`, ({ request }) => {
      const denied = authorize(request, 'audit:read')
      if (denied) return denied
      const p = new URL(request.url).searchParams
      return page(
        state.audit
          .filter(
            (event) =>
              (!p.get('node_id') || event.node_id === p.get('node_id')) &&
              (!p.get('task_id') || event.task_id === p.get('task_id')) &&
              (!p.get('subject_id') || event.subject_id === p.get('subject_id')) &&
              textMatch(event.action, p.get('action')),
          )
          .sort((a, b) => b.id - a.id),
        p,
      )
    }),
    http.get(`${root}/users`, ({ request }) => {
      const denied = authorize(request, 'users:read')
      if (denied) return denied
      const p = new URL(request.url).searchParams
      return page(
        state.users.filter(
          (user) =>
            (!p.get('status') || user.status === p.get('status')) &&
            textMatch(`${user.name} ${user.subject}`, p.get('q')),
        ),
        p,
      )
    }),
    http.post(`${root}/users/:id`, async ({ request, params }) => {
      const denied = authorize(request, 'users:write', true)
      if (denied) return denied
      const body = updateUserSchema.safeParse(await readBody(request))
      if (!body.success) return problem('invalid_request')
      const user = state.users.find((user) => user.id === params.id)
      if (!user) return problem('not_found', 404)
      if (user.version !== body.data.expected_version) return problem('user_conflict', 409)
      if (body.data.confirm_subject !== user.subject) return problem('invalid_request')
      if (
        user.role === 'Admin' &&
        user.status === 'active' &&
        (body.data.role !== 'Admin' || body.data.status !== 'active') &&
        state.users.filter((u) => u.role === 'Admin' && u.status === 'active').length <= 1
      )
        return problem('last_admin', 409)
      if (user.id === viewer()?.principal_id) return problem('self_change', 409)
      const action =
        user.status === 'pending'
          ? 'user.approve'
          : body.data.status === 'disabled'
            ? 'user.disable'
            : 'user.update'
      Object.assign(user, {
        role: body.data.role,
        status: body.data.status,
        version: user.version + 1,
      })
      state.addAudit(action, { subject_id: user.id })
      state.addAudit('user.sessions.revoke', { subject_id: user.id })
      return json(user)
    }),
    http.post(`${root}/users/:id/revoke-sessions`, ({ request, params }) => {
      const denied = authorize(request, 'users:write', true)
      if (denied) return denied
      const user = state.users.find((user) => user.id === params.id)
      if (!user) return problem('not_found', 404)
      if (user.id === viewer()?.principal_id) return problem('self_change', 409)
      state.addAudit('user.sessions.revoke', { subject_id: user.id })
      return json({})
    }),
  ]
}
