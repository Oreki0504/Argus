import { useNow } from '../fleet/useSummary'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { management } from '../../api/management'
import { useManagement } from '../management/hooks'
import { usePreferences } from '../../preferences/context'
import { useFormat } from '../../lib/useFormat'
import { ErrorState, Loading, Notice, Status } from '../../components/ui'

export function NodeDiagnostics({ publicId }: { publicId: string }) {
  const { key } = useManagement()
  const now = useNow()
  const { t } = usePreferences()
  const { timestampLabel } = useFormat()
  const agent = useQuery({
    queryKey: [...key, 'node-diagnostics-agent', publicId],
    queryFn: ({ signal }) => management.agents({ public_id: publicId, limit: 1 }, signal),
  })
  const node = agent.data?.items[0]
  const tasks = useQuery({
    queryKey: [...key, 'node-diagnostics', node?.node_id],
    queryFn: ({ signal }) => management.tasks({ node_id: node!.node_id, limit: 8 }, signal),
    enabled: !!node,
  })
  const capabilities = useQuery({
    queryKey: [...key, 'node-capabilities', node?.node_id],
    queryFn: ({ signal }) => management.capabilities(node!.node_id, signal),
    enabled: !!node,
  })
  if (agent.isError || tasks.isError) return <ErrorState error={agent.error ?? tasks.error} />
  if (!node || tasks.isPending) return <Loading label="Loading diagnostics" />
  return (
    <section className="panel node-diagnostics">
      <h2>{t('Diagnostics and events')}</h2>
      {capabilities.isError ? (
        <ErrorState error={capabilities.error} />
      ) : capabilities.data ? (
        <>
          <p>
            {t('Agent version')}: {capabilities.data.agent_version} · {t('Policy version')}:{' '}
            {capabilities.data.policy_version} · {t('Reported')}:{' '}
            {timestampLabel(capabilities.data.reported_at)}
          </p>
          <dl className="result-evidence">
            {capabilities.data.supported_collectors.map((collector) => (
              <div key={collector}>
                <dt>{collector}</dt>
                <dd>
                  {t(
                    node.authorization !== 'ACTIVE' ||
                      now - node.last_seen_at > 90 ||
                      !capabilities.data!.allowed_collectors.includes(collector)
                      ? 'Unavailable'
                      : 'Available',
                  )}
                </dd>
              </div>
            ))}
          </dl>
          <details>
            <summary>{t('Reported policy hash')}</summary>
            <code>{capabilities.data.policy_hash}</code>
          </details>
          <Notice>
            {t(
              'Reported capabilities describe the last known configuration. The Agent local policy remains authoritative at execution time.',
            )}
          </Notice>
        </>
      ) : (
        <p>{t('Diagnostic availability is unknown until the Agent reports its capabilities.')}</p>
      )}
      <div className="management-actions">
        <Link className="text-link" to={`/manage/tasks?node_id=${node.node_id}`}>
          {t('Diagnostic history')}
        </Link>
        <Link className="text-link" to={`/manage/alerts?node_id=${node.node_id}`}>
          {t('Alerts and events')}
        </Link>
        <Link className="text-link" to={`/manage/audit?node_id=${node.node_id}`}>
          {t('Audit')}
        </Link>
      </div>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>{t('Collector')}</th>
              <th>{t('Created')}</th>
              <th>{t('Status')}</th>
            </tr>
          </thead>
          <tbody>
            {tasks.data.items.map((task) => (
              <tr key={task.id}>
                <td>
                  <Link className="text-link" to={`/manage/tasks/${task.id}`}>
                    {task.task_type}
                  </Link>
                </td>
                <td>{timestampLabel(task.created_at)}</td>
                <td>
                  <Status>{task.status}</Status>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!tasks.data.items.length && <p>{t('No diagnostic tasks yet.')}</p>}
    </section>
  )
}
