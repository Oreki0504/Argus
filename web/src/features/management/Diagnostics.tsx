import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { management } from '../../api/management'
import type { DiagnosticRequest } from '../../api/management-contracts'
import { ErrorState, Loading, Notice, Status } from '../../components/ui'
import { usePreferences } from '../../preferences/context'
import { uncertainWrite, useManagement } from './hooks'
import { Dialog, MutationError } from './shared'

export function DiagnosticsPanel() {
  const { t } = usePreferences()
  const { identity, key, refresh } = useManagement()
  const [open, setOpen] = useState(false)
  const [profile, setProfile] = useState<DiagnosticRequest['profile_id']>('overview')
  const [nodes, setNodes] = useState<string[]>([])
  const [search, setSearch] = useState('')
  const profiles = useQuery({
    queryKey: [...key, 'diagnostic-profiles'],
    queryFn: ({ signal }) => management.profiles(signal),
    enabled: open,
  })
  const agents = useQuery({
    queryKey: [...key, 'diagnostic-agents', search],
    queryFn: ({ signal }) => management.agents({ status: 'active', q: search, limit: 200 }, signal),
    enabled: open,
  })
  const create = useMutation({
    mutationFn: (body: DiagnosticRequest) => management.diagnose(body, identity.csrf_token),
    onSuccess: () => {
      void refresh()
    },
  })
  const batch = useQuery({
    queryKey: [...key, 'diagnostic-batch', create.data?.id],
    queryFn: ({ signal }) => management.diagnosticBatch(create.data!.id, signal),
    enabled: !!create.data,
    refetchInterval: 5000,
  })
  const selectedProfile = profiles.data?.find((value) => value.id === profile)
  return (
    <>
      <div className="diagnostic-profile-action">
        <button
          className="button secondary"
          onClick={() => {
            setOpen(true)
            create.reset()
            setNodes([])
          }}
        >
          {t('Run diagnostic profile')}
        </button>
        <span className="muted">{t('Run fixed read-only collectors across up to 50 nodes.')}</span>
      </div>
      {open && (
        <Dialog
          title={t('Run diagnostic profile')}
          onClose={() => setOpen(false)}
          busy={create.isPending}
          wide
        >
          {create.data ? (
            <>
              <p>
                {t('Diagnostic batch created')}: <code>{create.data.id}</code>
              </p>
              {batch.isError && (
                <ErrorState error={batch.error} retry={() => void batch.refetch()} />
              )}
              <table>
                <thead>
                  <tr>
                    <th>{t('Agent')}</th>
                    <th>{t('Collector')}</th>
                    <th>{t('Status')}</th>
                  </tr>
                </thead>
                <tbody>
                  {(batch.data ?? create.data).tasks.map((task) => (
                    <tr key={task.id}>
                      <td>{task.node_id}</td>
                      <td>
                        <Link className="text-link" to={`/manage/tasks/${task.id}`}>
                          {task.task_type}
                        </Link>
                      </td>
                      <td>
                        <Status>{task.status}</Status>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          ) : profiles.isPending || agents.isPending ? (
            <Loading />
          ) : profiles.isError || agents.isError ? (
            <ErrorState error={profiles.error ?? agents.error} />
          ) : (
            <form
              className="management-form"
              onSubmit={(event) => {
                event.preventDefault()
                const form = new FormData(event.currentTarget)
                create.mutate({
                  node_ids: nodes,
                  profile_id: profile,
                  resource_id: selectedProfile?.requires_resource
                    ? String(form.get('resource_id'))
                    : '',
                  ttl_seconds: 300,
                  execution_timeout_ms: 10000,
                })
              }}
            >
              <label>
                {t('Diagnostic profile')}
                <select
                  value={profile}
                  onChange={(event) =>
                    setProfile(event.target.value as DiagnosticRequest['profile_id'])
                  }
                >
                  {profiles.data.map((value) => (
                    <option value={value.id} key={value.id}>
                      {t(value.name)}
                    </option>
                  ))}
                </select>
              </label>
              <p className="muted">{selectedProfile?.collectors.join(' · ')}</p>
              {selectedProfile?.requires_resource && (
                <label>
                  {t(profile === 'service' ? 'Service ID' : 'SSH profile ID')}
                  <input
                    name="resource_id"
                    required
                    maxLength={32}
                    pattern="[A-Za-z0-9][A-Za-z0-9_-]{0,31}"
                  />
                </label>
              )}
              <label>
                {t('Find agent')}
                <input value={search} onChange={(event) => setSearch(event.target.value)} />
              </label>
              <fieldset className="diagnostic-node-options">
                <legend>
                  {t('Select nodes')} ({nodes.length}/50)
                </legend>
                {agents.data.items.map((agent) => (
                  <label key={agent.node_id}>
                    <input
                      type="checkbox"
                      checked={nodes.includes(agent.node_id)}
                      disabled={nodes.length >= 50 && !nodes.includes(agent.node_id)}
                      onChange={(event) =>
                        setNodes(
                          event.target.checked
                            ? [...nodes, agent.node_id]
                            : nodes.filter((id) => id !== agent.node_id),
                        )
                      }
                    />
                    {agent.display_name} <small>{agent.node_id}</small>
                  </label>
                ))}
              </fieldset>
              {agents.data.next_cursor && (
                <Notice>
                  {t('More nodes match. Refine the search to select additional nodes.')}
                </Notice>
              )}
              <Notice>
                {t(
                  'Every node is checked before the batch is created. Each Agent applies its local policy independently.',
                )}
              </Notice>
              <MutationError error={create.error} />
              <div className="dialog-actions">
                <button type="button" className="button secondary" onClick={() => setOpen(false)}>
                  {t('Cancel')}
                </button>
                <button
                  className="button primary"
                  disabled={!nodes.length || create.isPending || uncertainWrite(create.error)}
                >
                  {t(create.isPending ? 'Submitting…' : 'Run diagnostic profile')}
                </button>
              </div>
            </form>
          )}
        </Dialog>
      )}
    </>
  )
}
