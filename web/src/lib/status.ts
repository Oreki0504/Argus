import type { PublicNode } from '../api/contracts'

// Re-evaluate freshness while a cached response is visible. Neither a heartbeat
// nor a delayed upload makes an old observation healthy.
export function observationStatus(node: PublicNode, now: number): PublicNode['status'] {
  const connectivity =
    !node.last_seen_at || node.last_seen_at > now
      ? 'UNKNOWN'
      : now - node.last_seen_at <= 90
        ? 'ONLINE'
        : 'OFFLINE'
  const observed = node.telemetry.observed_at
  const telemetry =
    observed === null
      ? 'MISSING'
      : node.telemetry.clock_skew ||
          observed > now ||
          now - observed > Math.max(180, 3 * node.telemetry.interval_seconds)
        ? 'STALE'
        : 'FRESH'
  return {
    ...node.status,
    connectivity,
    telemetry,
    health: telemetry === 'FRESH' ? node.status.health : 'UNKNOWN',
  }
}
export function statusLabel(value: string) {
  return value[0] + value.slice(1).toLowerCase()
}
export function sumObserved(values: (number | null)[]): number | null {
  const available = values.filter((value): value is number => value !== null)
  return available.length ? available.reduce((sum, value) => sum + value, 0) : null
}
