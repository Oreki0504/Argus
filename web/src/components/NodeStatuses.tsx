import type { PublicNode } from '../api/contracts'
import { observationStatus, statusLabel } from '../lib/status'
import { usePreferences } from '../preferences/context'
import { Status } from './ui'

export function NodeStatuses({ node, now }: { node: PublicNode; now: number }) {
  const { t } = usePreferences()
  const status = observationStatus(node, now)
  return (
    <div className="node-status-dimensions" aria-label={t('Node status')}>
      {(['connectivity', 'authorization', 'telemetry', 'health'] as const).map((dimension) => (
        <span key={dimension} className="node-status-dimension">
          <small>{t(statusLabel(dimension))}</small>
          <Status>{statusLabel(status[dimension])}</Status>
        </span>
      ))}
    </div>
  )
}
