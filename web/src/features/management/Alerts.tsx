import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { management } from '../../api/management'
import type { AlertRule } from '../../api/management-contracts'
import { ErrorState, Loading, Notice, Status } from '../../components/ui'
import { useFormat } from '../../lib/useFormat'
import { usePreferences } from '../../preferences/context'
import { useListNavigation, useManagement } from './hooks'
import { Dialog, MutationError, SectionHeading } from './shared'

export function AlertsPage() {
  const { t } = usePreferences()
  const { timestampLabel } = useFormat()
  const { identity, key, refresh } = useManagement()
  const nav = useListNavigation(['node_id', 'status'])
  const [params] = useSearchParams()
  const [editing, setEditing] = useState<AlertRule | null>(null)
  const eventFilter = `${nav.filters.node_id}:${params.get('alert_id') ?? ''}`
  const [eventPage, setEventPage] = useState({ filter: '', after: 0, back: [] as number[] })
  const eventsAfter = eventPage.filter === eventFilter ? eventPage.after : 0
  const eventsBack = eventPage.filter === eventFilter ? eventPage.back : []
  const filters = { ...nav.filters, cursor: nav.cursor, limit: 25 }
  const query = useQuery({
    queryKey: [...key, 'alerts', filters],
    queryFn: ({ signal }) => management.alerts(filters, signal),
    refetchInterval: 30000,
  })
  const rules = useQuery({
    queryKey: [...key, 'alert-rules'],
    queryFn: ({ signal }) => management.alertRules(signal),
  })
  const events = useQuery({
    queryKey: [...key, 'alert-events', nav.filters.node_id, params.get('alert_id'), eventsAfter],
    queryFn: ({ signal }) =>
      management.alertEvents(
        {
          node_id: nav.filters.node_id,
          alert_id: params.get('alert_id') ?? '',
          after: eventsAfter,
          limit: 25,
        },
        signal,
      ),
  })
  const update = useMutation({
    mutationFn: (rule: AlertRule) => management.putAlertRule(rule, identity.csrf_token),
    onSuccess: () => {
      setEditing(null)
      void refresh()
      void rules.refetch()
      void query.refetch()
      void events.refetch()
    },
  })
  return (
    <>
      <SectionHeading
        title="Alerts"
        description="Sustained resource anomalies and missing telemetry, with recovery evidence."
        busy={query.isFetching}
        refresh={() => {
          void query.refetch()
          void events.refetch()
        }}
      >
        <button
          className="button secondary"
          onClick={() =>
            setEditing({
              id: '',
              metric: 'cpu_percent',
              severity: 'WARNING',
              threshold: 80,
              for_seconds: 120,
              recovery_seconds: 120,
              enabled: true,
            })
          }
        >
          {t('New alert rule')}
        </button>
      </SectionHeading>
      <div className="management-filters">
        <input
          aria-label={t('Filter by agent ID')}
          placeholder={t('Agent ID')}
          value={nav.filters.node_id}
          onChange={(event) => {
            nav.change('node_id', event.target.value)
            setEventPage({ filter: '', after: 0, back: [] })
          }}
        />
        <select
          aria-label={t('Alert state')}
          value={nav.filters.status}
          onChange={(event) => nav.change('status', event.target.value)}
        >
          <option value="">{t('All alert states')}</option>
          <option value="FIRING">{t('FIRING')}</option>
          <option value="RESOLVED">{t('RESOLVED')}</option>
        </select>
      </div>
      {query.isPending ? (
        <Loading />
      ) : query.isError ? (
        <ErrorState error={query.error} retry={() => void query.refetch()} />
      ) : (
        <section className="panel management-table-panel">
          <div className="table-scroll" tabIndex={0} role="region" aria-label={t('Alerts')}>
            <table>
              <thead>
                <tr>
                  <th>{t('Agent')}</th>
                  <th>{t('Rule')}</th>
                  <th>{t('Severity')}</th>
                  <th>{t('Status')}</th>
                  <th>{t('Opened')}</th>
                  <th>{t('Resolved')}</th>
                  <th>{t('Evidence')}</th>
                </tr>
              </thead>
              <tbody>
                {query.data.items.map((alert) => (
                  <tr key={alert.id}>
                    <td>
                      <Link className="text-link" to={`/manage/tasks?node_id=${alert.node_id}`}>
                        {alert.node_id}
                      </Link>
                    </td>
                    <td>{alert.rule_id}</td>
                    <td>
                      <Status>{alert.severity}</Status>
                    </td>
                    <td>
                      <Status>{alert.status}</Status>
                    </td>
                    <td>{timestampLabel(alert.opened_at)}</td>
                    <td>{timestampLabel(alert.resolved_at || null)}</td>
                    <td>
                      {t(alert.reason)}
                      <small>
                        {t('Last observed')}: {timestampLabel(alert.last_observed_at)}
                      </small>
                      <Link
                        className="text-link"
                        to={`/manage/alerts?node_id=${alert.node_id}&alert_id=${alert.id}`}
                      >
                        {t('View events')}
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!query.data.items.length && (
            <p className="management-note">{t('No alerts match this filter.')}</p>
          )}
          <div className="pagination">
            <button className="button secondary" disabled={!nav.cursor} onClick={nav.back}>
              {t('Previous')}
            </button>
            <button
              className="button secondary"
              disabled={!query.data.next_cursor}
              onClick={() => query.data.next_cursor && nav.advance(query.data.next_cursor)}
            >
              {t('Next')}
            </button>
          </div>
        </section>
      )}
      <section className="panel management-table-panel">
        <h3>{t('Alert events')}</h3>
        {events.isPending ? (
          <Loading />
        ) : events.isError ? (
          <ErrorState error={events.error} />
        ) : (
          <>
            <div className="table-scroll" tabIndex={0} role="region" aria-label={t('Alert events')}>
              <table>
                <thead>
                  <tr>
                    <th>{t('Time')}</th>
                    <th>{t('Agent')}</th>
                    <th>{t('Rule')}</th>
                    <th>{t('State')}</th>
                    <th>{t('Reason')}</th>
                  </tr>
                </thead>
                <tbody>
                  {events.data.map((event) => (
                    <tr key={event.id}>
                      <td>{timestampLabel(event.timestamp)}</td>
                      <td>{event.node_id}</td>
                      <td>{event.rule_id}</td>
                      <td>
                        <Status>{event.state}</Status>
                      </td>
                      <td>{t(event.reason)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="pagination">
              <button
                className="button secondary"
                disabled={!eventsBack.length}
                onClick={() => {
                  setEventPage({
                    filter: eventFilter,
                    after: eventsBack[eventsBack.length - 1] ?? 0,
                    back: eventsBack.slice(0, -1),
                  })
                }}
              >
                {t('Previous')}
              </button>
              <button
                className="button secondary"
                disabled={events.data.length < 25}
                onClick={() => {
                  setEventPage({
                    filter: eventFilter,
                    after: events.data[events.data.length - 1].id,
                    back: [...eventsBack, eventsAfter],
                  })
                }}
              >
                {t('Next')}
              </button>
            </div>
          </>
        )}
      </section>
      <section className="panel management-table-panel">
        <h3>{t('Alert rules')}</h3>
        {rules.isPending ? (
          <Loading />
        ) : rules.isError ? (
          <ErrorState error={rules.error} />
        ) : (
          <div className="table-scroll" tabIndex={0} role="region" aria-label={t('Alert rules')}>
            <table>
              <thead>
                <tr>
                  <th>{t('Rule')}</th>
                  <th>{t('Metric')}</th>
                  <th>{t('Threshold')}</th>
                  <th>{t('Sustain / recovery')}</th>
                  <th>{t('Status')}</th>
                  <th>{t('Actions')}</th>
                </tr>
              </thead>
              <tbody>
                {rules.data.map((rule) => (
                  <tr key={rule.id}>
                    <td>{rule.id}</td>
                    <td>{rule.metric}</td>
                    <td>
                      {rule.threshold}
                      {rule.metric === 'telemetry_missing' ? 's' : '%'}
                    </td>
                    <td>
                      {rule.for_seconds}s / {rule.recovery_seconds}s
                    </td>
                    <td>{t(rule.enabled ? 'Enabled' : 'Disabled')}</td>
                    <td>
                      <button
                        className="text-action"
                        onClick={() => {
                          update.reset()
                          setEditing(rule)
                        }}
                      >
                        {t('Edit rule')}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {editing && (
        <Dialog title={t('Alert rule')} onClose={() => setEditing(null)} busy={update.isPending}>
          <form
            className="management-form"
            onSubmit={(event) => {
              event.preventDefault()
              update.mutate(editing)
            }}
          >
            <label>
              {t('Rule ID')}
              <input
                required
                maxLength={64}
                pattern="[A-Za-z0-9_-]+"
                value={editing.id}
                onChange={(event) => setEditing({ ...editing, id: event.target.value })}
              />
            </label>
            <label>
              {t('Metric')}
              <select
                value={editing.metric}
                onChange={(event) => {
                  const metric = event.target.value as AlertRule['metric']
                  setEditing({
                    ...editing,
                    metric,
                    threshold: metric === 'telemetry_missing' ? 180 : 80,
                  })
                }}
              >
                {['cpu_percent', 'memory_percent', 'disk_percent', 'telemetry_missing'].map(
                  (metric) => (
                    <option key={metric}>{metric}</option>
                  ),
                )}
              </select>
            </label>
            <label>
              {t('Severity')}
              <select
                value={editing.severity}
                onChange={(event) =>
                  setEditing({ ...editing, severity: event.target.value as AlertRule['severity'] })
                }
              >
                <option>WARNING</option>
                <option>CRITICAL</option>
              </select>
            </label>
            <label>
              {t('Threshold')} ({editing.metric === 'telemetry_missing' ? 's' : '%'})
              <input
                required
                type="number"
                min={editing.metric === 'telemetry_missing' ? 180 : 0.1}
                max={editing.metric === 'telemetry_missing' ? 86400 : 100}
                step={editing.metric === 'telemetry_missing' ? 1 : 0.1}
                value={editing.threshold}
                onChange={(event) =>
                  setEditing({ ...editing, threshold: Number(event.target.value) })
                }
              />
            </label>
            <label>
              {t('Sustain seconds')}
              <input
                required
                type="number"
                min={0}
                max={3600}
                value={editing.for_seconds}
                onChange={(event) =>
                  setEditing({ ...editing, for_seconds: Number(event.target.value) })
                }
              />
            </label>
            <label>
              {t('Recovery seconds')}
              <input
                required
                type="number"
                min={30}
                max={3600}
                value={editing.recovery_seconds}
                onChange={(event) =>
                  setEditing({ ...editing, recovery_seconds: Number(event.target.value) })
                }
              />
            </label>
            <label>
              <input
                type="checkbox"
                checked={editing.enabled}
                onChange={(event) => setEditing({ ...editing, enabled: event.target.checked })}
              />
              {t('Enabled')}
            </label>
            <Notice>
              {t(
                'Changing a rule resolves its active alerts with an administrative reason. Missing observations never count as healthy recovery.',
              )}
            </Notice>
            <MutationError error={update.error} />
            <div className="dialog-actions">
              <button className="button primary" disabled={update.isPending}>
                {t('Save rule')}
              </button>
            </div>
          </form>
        </Dialog>
      )}
    </>
  )
}
