import { describe, expect, it } from 'vitest'
import { fleetFixture, historyFixture } from '../mocks/fixtures'
import { nodeHistorySchema } from '../api/contracts'
import { observationStatus, sumObserved } from './status'
import { seriesSegments } from './utilization'

describe('independent node status and telemetry evidence', () => {
  it('keeps authorization, connectivity and telemetry health independent', () => {
    const now = 1800000000
    const node = fleetFixture(1, now).nodes[0]
    node.status.authorization = 'DISABLED'
    expect(observationStatus(node, now)).toEqual({
      connectivity: 'ONLINE',
      authorization: 'DISABLED',
      telemetry: 'FRESH',
      health: 'HEALTHY',
    })
    node.telemetry.observed_at = now - 1000
    node.telemetry.received_at = now
    expect(observationStatus(node, now)).toMatchObject({
      connectivity: 'ONLINE',
      telemetry: 'STALE',
      health: 'UNKNOWN',
    })
    node.telemetry.observed_at = null
    expect(observationStatus(node, now)).toMatchObject({ telemetry: 'MISSING', health: 'UNKNOWN' })
    node.telemetry.observed_at = now + 30
    expect(observationStatus(node, now).health).toBe('UNKNOWN')
  })
  it('does not turn a missing fleet throughput into zero', () => {
    expect(sumObserved([null, null])).toBeNull()
    expect(sumObserved([null, 0])).toBe(0)
    expect(sumObserved([null, 10, 20])).toBe(30)
  })
  it('shows throughput without configured bandwidth and never bridges a boot gap', () => {
    const node = fleetFixture().nodes[3]
    node.traffic.inbound_capacity_bps = null
    const h = historyFixture(node, '30d')
    expect(nodeHistorySchema.safeParse(h).success).toBe(true)
    expect(h.points.length).toBeLessThanOrEqual(1441)
    expect(h.points[0].inbound_bps).toBeGreaterThan(0)
    expect(h.points[0].inbound_percent).toBeNull()
    const points = h.points
      .slice(0, 3)
      .map((point, index) => ({ ...point, gap_before: index === 2 }))
    expect(
      seriesSegments({ ...h, points }, 'inbound_bps').map((segment) => segment.length),
    ).toEqual([2, 1])
  })
})
