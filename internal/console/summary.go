package console

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

// These DTOs intentionally cannot hold hostnames, addresses, paths, interfaces,
// task identifiers or nested raw collector reports. Both User and anonymous
// responses are constructed here before JSON serialization.
type publicSystem struct {
	OS            *string `json:"os"`
	Architecture  *string `json:"architecture"`
	Kernel        *string `json:"kernel"`
	UptimeSeconds *int64  `json:"uptime_seconds"`
}
type publicResources struct {
	AsOf   *int64   `json:"as_of"`
	CPU    *float64 `json:"cpu_percent"`
	Memory *float64 `json:"memory_percent"`
	Disk   *float64 `json:"disk_percent"`
}
type publicTraffic struct {
	AsOf             *int64   `json:"as_of"`
	Inbound          *float64 `json:"inbound_bps"`
	Outbound         *float64 `json:"outbound_bps"`
	InboundCapacity  *float64 `json:"inbound_capacity_bps"`
	OutboundCapacity *float64 `json:"outbound_capacity_bps"`
	InboundBytes     *float64 `json:"sampled_inbound_bytes"`
	OutboundBytes    *float64 `json:"sampled_outbound_bytes"`
	Coverage         *float64 `json:"coverage_percent"`
}
type publicNode struct {
	Tags        []string                `json:"tags"`
	PublicID    string                  `json:"public_id"`
	DisplayName string                  `json:"display_name"`
	LastSeenAt  int64                   `json:"last_seen_at"`
	System      publicSystem            `json:"system"`
	Resources   publicResources         `json:"resources"`
	Traffic     publicTraffic           `json:"traffic"`
	Status      publicNodeStatus        `json:"status"`
	Telemetry   publicTelemetryEvidence `json:"telemetry"`
}
type publicNodeStatus struct {
	Connectivity  string `json:"connectivity"`
	Authorization string `json:"authorization"`
	Telemetry     string `json:"telemetry"`
	Health        string `json:"health"`
}
type publicTelemetryEvidence struct {
	ObservedAt       *int64 `json:"observed_at"`
	ReceivedAt       *int64 `json:"received_at"`
	IntervalSeconds  int    `json:"interval_seconds"`
	ClockSkew        bool   `json:"clock_skew"`
	CollectionErrors int    `json:"collection_errors"`
}
type publicSummary struct {
	GeneratedAt           int64        `json:"generated_at"`
	WindowStart           int64        `json:"window_start"`
	WindowEnd             int64        `json:"window_end"`
	SampleIntervalSeconds int64        `json:"sample_interval_seconds"`
	Nodes                 []publicNode `json:"nodes"`
}
type historyPoint struct {
	ReceivedAt                int64    `json:"received_at"`
	CollectionIntervalSeconds int      `json:"collection_interval_seconds"`
	CollectionErrors          int      `json:"collection_errors"`
	ClockSkew                 bool     `json:"clock_skew"`
	GapBefore                 bool     `json:"gap_before"`
	InboundBPS                *float64 `json:"inbound_bps"`
	OutboundBPS               *float64 `json:"outbound_bps"`
	Timestamp                 int64    `json:"timestamp"`
	CPU                       *float64 `json:"cpu_percent"`
	Memory                    *float64 `json:"memory_percent"`
	Disk                      *float64 `json:"disk_percent"`
	Inbound                   *float64 `json:"inbound_percent"`
	Outbound                  *float64 `json:"outbound_percent"`
}
type publicHistory struct {
	Source                string         `json:"source"`
	Aggregation           string         `json:"aggregation"`
	SampleCount           int            `json:"sample_count"`
	PublicID              string         `json:"public_id"`
	Range                 string         `json:"range"`
	WindowStart           int64          `json:"window_start"`
	WindowEnd             int64          `json:"window_end"`
	SampleIntervalSeconds int64          `json:"sample_interval_seconds"`
	Points                []historyPoint `json:"points"`
}

func ptr[T any](v T) *T { return &v }

var kernelVersion = regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3})(?:[-+].*)?$`)
var osVersion = regexp.MustCompile(`^[0-9]{1,4}(?:\.[0-9]{1,4}){0,2}$`)

func projectSystem(raw string, completed int64) publicSystem {
	var out publicSystem
	i, err := protocol.DecodeInformation([]byte(raw))
	if err != nil || i.Validate(completed) != nil || !i.Available {
		return out
	}
	// Return a small vocabulary, never arbitrary Agent-supplied system text.
	for _, family := range []string{"linux", "Ubuntu", "Debian", "Fedora", "Alpine", "Arch", "Rocky", "AlmaLinux", "CentOS", "Red Hat", "openSUSE", "SUSE", "Amazon Linux", "Oracle Linux", "NixOS"} {
		if i.OS == family || strings.HasPrefix(i.OS, family+" ") {
			name := family
			for _, word := range strings.Fields(strings.TrimPrefix(i.OS, family)) {
				if osVersion.MatchString(word) {
					name += " " + word
					break
				}
			}
			out.OS = &name
			break
		}
	}
	switch i.Architecture {
	case "x86_64", "amd64", "aarch64", "arm64", "armv7l", "armv6l", "i386", "i686", "riscv64", "ppc64le", "s390x":
		out.Architecture = ptr(i.Architecture)
	}
	if match := kernelVersion.FindStringSubmatch(i.Kernel); len(match) > 1 {
		out.Kernel = &match[1]
	}
	if completed >= i.BootTime && i.BootTime > 0 {
		out.UptimeSeconds = ptr(completed - i.BootTime)
	}
	return out
}
func projectResources(raw string, received int64) publicResources {
	var out publicResources
	m, err := protocol.DecodeMeasurements([]byte(raw))
	if err != nil {
		return out
	}
	out.AsOf = ptr(received)
	if m.CPU.Available {
		out.CPU = ptr(m.CPU.BusyPercent)
	}
	if m.Memory.Available && m.Memory.TotalBytes > 0 {
		out.Memory = ptr(100 * float64(m.Memory.TotalBytes-m.Memory.AvailableBytes) / float64(m.Memory.TotalBytes))
	}
	complete := len(m.Disks) > 0
	var total, available float64
	for _, d := range m.Disks {
		if !d.Available {
			complete = false
		}
		total += float64(d.TotalBytes)
		available += float64(d.AvailableBytes)
	}
	if complete && total > 0 {
		out.Disk = ptr(100 * (total - available) / total)
	}
	return out
}

// decodeObservation reads persisted, validated telemetry. Public responses are
// always explicitly projected; raw sample identifiers and resource names stay private.
func decodeObservation(raw string, received int64, skew bool) (*database.TelemetryObservation, error) {
	if raw == "" {
		return nil, nil
	}
	var sample protocol.TelemetrySample
	if err := json.Unmarshal([]byte(raw), &sample); err != nil {
		return nil, err
	}
	return &database.TelemetryObservation{TelemetrySample: sample, ReceivedAt: received, ClockSkew: skew}, nil
}

func projectObservation(sample *database.TelemetryObservation, now int64) (publicSystem, publicResources, publicTelemetryEvidence, database.TelemetryStatus) {
	status := database.ProjectTelemetryStatus(sample, now)
	evidence := publicTelemetryEvidence{IntervalSeconds: 60}
	if sample == nil {
		return publicSystem{}, publicResources{}, evidence, status
	}
	evidence = publicTelemetryEvidence{ptr(sample.ObservedAt), ptr(sample.ReceivedAt), sample.IntervalSeconds, sample.ClockSkew, len(sample.Errors)}
	info, _ := json.Marshal(sample.System)
	metrics, _ := json.Marshal(sample.Metrics)
	return projectSystem(string(info), sample.ObservedAt), projectResources(string(metrics), sample.ObservedAt), evidence, status
}

func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		problem(w, 400, "invalid_request")
		return
	}
	now := s.now().Unix()
	out := publicSummary{now, now - 3600, now, 60, []publicNode{}}
	// Two indexed lookups per visible node, independent of the diagnostic queue.
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT p.public_id,p.display_name,n.last_seen_at,
 CASE WHEN EXISTS(SELECT 1 FROM node_revocations WHERE node_id=n.id) THEN 'REVOKED' WHEN n.status='disabled' THEN 'DISABLED' ELSE 'ACTIVE' END,
 (SELECT json_group_array(tag) FROM (SELECT tag FROM node_tags WHERE node_id=n.id ORDER BY tag)),
 COALESCE((SELECT max(CASE WHEN severity='CRITICAL' THEN 2 ELSE 1 END) FROM alerts WHERE node_id=n.id AND status='FIRING'),0),
 COALESCE(m.payload_json,''),COALESCE(m.received_at,0),COALESCE(m.clock_skew,0),
 COALESCE(b.payload_json,''),COALESCE(b.received_at,0),COALESCE(b.clock_skew,0)
 FROM nodes n JOIN console_nodes p ON p.node_id=n.id
 LEFT JOIN telemetry_samples m ON m.id=(SELECT id FROM telemetry_samples WHERE node_id=n.id ORDER BY observed_at DESC,sample_id DESC LIMIT 1)
 LEFT JOIN telemetry_samples b ON b.id=(SELECT id FROM telemetry_samples WHERE node_id=n.id AND (observed_at,sample_id)<(m.observed_at,m.sample_id) ORDER BY observed_at DESC,sample_id DESC LIMIT 1)
 WHERE n.last_seen_at>0 ORDER BY p.public_id LIMIT 1001`)
	if err != nil {
		storeProblem(w, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var n publicNode
		var authorization, raw, beforeRaw, tags string
		var alertSeverity int
		var received, beforeReceived int64
		var skew, beforeSkew bool
		if err = rows.Scan(&n.PublicID, &n.DisplayName, &n.LastSeenAt, &authorization, &tags, &alertSeverity, &raw, &received, &skew, &beforeRaw, &beforeReceived, &beforeSkew); err != nil {
			storeProblem(w, err)
			return
		}
		if !database.ValidNodeName(n.DisplayName) {
			n.DisplayName = ""
		}
		n.DisplayName = publicName(n.DisplayName, n.PublicID)
		if err = json.Unmarshal([]byte(tags), &n.Tags); err != nil {
			storeProblem(w, err)
			return
		}
		current, e := decodeObservation(raw, received, skew)
		if e != nil {
			storeProblem(w, e)
			return
		}
		previous, e := decodeObservation(beforeRaw, beforeReceived, beforeSkew)
		if e != nil {
			storeProblem(w, e)
			return
		}
		var status database.TelemetryStatus
		n.System, n.Resources, n.Telemetry, status = projectObservation(current, now)
		n.Status = publicNodeStatus{Connectivity: "UNKNOWN", Authorization: strings.ToUpper(authorization), Telemetry: status.Telemetry, Health: status.Health}
		if status.Telemetry == "FRESH" && status.Health != "UNKNOWN" {
			if alertSeverity == 2 {
				n.Status.Health = "CRITICAL"
			} else if alertSeverity == 1 && status.Health == "HEALTHY" {
				n.Status.Health = "WARNING"
			}
		}
		if n.LastSeenAt > 0 {
			n.Status.Connectivity = "OFFLINE"
			if now-n.LastSeenAt <= 90 && n.LastSeenAt <= now {
				n.Status.Connectivity = "ONLINE"
			}
		}
		if status.Telemetry == "FRESH" {
			n.Traffic = projectTelemetryTraffic(previous, current)
		}
		out.Nodes = append(out.Nodes, n)
	}
	if err = rows.Err(); err != nil {
		storeProblem(w, err)
		return
	}
	if len(out.Nodes) > 1000 {
		problem(w, 503, "service_unavailable")
		return
	}
	reply(w, out)
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	if !listParams(w, r, "range") {
		return
	}
	if len(r.URL.Query()) != 1 {
		problem(w, 400, "invalid_request")
		return
	}
	id := r.PathValue("id")
	if !identity.Valid(id) {
		problem(w, 404, "not_found")
		return
	}
	window, interval := int64(3600), int64(60)
	span := r.URL.Query().Get("range")
	switch span {
	case "1h":
	case "24h":
		window = 86400
		interval = 300
	case "7d":
		window = 7 * 86400
		interval = 900
	case "30d":
		window = 30 * 86400
		interval = 1800
	default:
		problem(w, 400, "invalid_request")
		return
	}
	var node string
	err := s.store.DB.QueryRowContext(r.Context(), "SELECT p.node_id FROM console_nodes p JOIN nodes n ON n.id=p.node_id WHERE p.public_id=? AND n.last_seen_at>0", id).Scan(&node)
	if err == sql.ErrNoRows {
		problem(w, 404, "not_found")
		return
	}
	if err != nil {
		storeProblem(w, err)
		return
	}
	now := s.now().Unix()
	out := publicHistory{Source: "telemetry", Aggregation: "latest_per_bucket", PublicID: id, Range: span, WindowStart: now - window, WindowEnd: now, SampleIntervalSeconds: interval, Points: []historyPoint{}}
	// Scan only the indexed, bounded node/time window. Rank identifiers rather
	// than payloads; the response retains the latest real observation per bucket.
	// The count exposes aggregation explicitly, including all 30 days of data.
	rows, err := s.store.DB.QueryContext(r.Context(), `WITH ordered AS (
 SELECT id,observed_at,sample_id,boot_id,interval_seconds,
 lag(observed_at) OVER (ORDER BY observed_at,sample_id) AS prior_at,
 lag(boot_id) OVER (ORDER BY observed_at,sample_id) AS prior_boot,
 lag(interval_seconds) OVER (ORDER BY observed_at,sample_id) AS prior_interval
 FROM telemetry_samples WHERE node_id=? AND observed_at>=? AND observed_at<=?
 ), ranked AS (
 SELECT id,count(*) OVER (PARTITION BY observed_at/?) AS samples,
 max(CASE WHEN prior_at IS NOT NULL AND (prior_boot!=boot_id OR observed_at-prior_at>max(180,3*max(interval_seconds,prior_interval))) THEN 1 ELSE 0 END) OVER (PARTITION BY observed_at/?) AS bucket_gap,
 row_number() OVER (PARTITION BY observed_at/? ORDER BY observed_at DESC,sample_id DESC) AS pos
 FROM ordered
 ) SELECT m.payload_json,m.received_at,m.clock_skew,ranked.samples,ranked.bucket_gap,
 COALESCE(b.payload_json,''),COALESCE(b.received_at,0),COALESCE(b.clock_skew,0)
 FROM ranked JOIN telemetry_samples m ON m.id=ranked.id
 LEFT JOIN telemetry_samples b ON b.id=(SELECT id FROM telemetry_samples WHERE node_id=m.node_id AND (observed_at,sample_id)<(m.observed_at,m.sample_id) ORDER BY observed_at DESC,sample_id DESC LIMIT 1)
 WHERE ranked.pos=1 ORDER BY m.observed_at,m.sample_id LIMIT 2000`, node, out.WindowStart, now, interval, interval, interval)
	if err != nil {
		storeProblem(w, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var raw, beforeRaw string
		var received, beforeReceived int64
		var skew, beforeSkew, bucketGap bool
		var count int
		if err = rows.Scan(&raw, &received, &skew, &count, &bucketGap, &beforeRaw, &beforeReceived, &beforeSkew); err != nil {
			storeProblem(w, err)
			return
		}
		current, e := decodeObservation(raw, received, skew)
		if e != nil {
			storeProblem(w, e)
			return
		}
		previous, e := decodeObservation(beforeRaw, beforeReceived, beforeSkew)
		if e != nil {
			storeProblem(w, e)
			return
		}
		_, resources, _, _ := projectObservation(current, now)
		traffic := projectTelemetryTraffic(previous, current)
		gap := bucketGap || previous == nil || current.BootID != previous.BootID || current.ObservedAt-previous.ObservedAt > int64(max(180, 3*max(current.IntervalSeconds, previous.IntervalSeconds)))
		point := historyPoint{Timestamp: current.ObservedAt, ReceivedAt: current.ReceivedAt, CollectionIntervalSeconds: current.IntervalSeconds, CollectionErrors: len(current.Errors), ClockSkew: current.ClockSkew, GapBefore: gap, CPU: resources.CPU, Memory: resources.Memory, Disk: resources.Disk, InboundBPS: traffic.Inbound, OutboundBPS: traffic.Outbound}
		if current.ClockSkew {
			point.CPU = nil
			point.Memory = nil
			point.Disk = nil
		}
		out.SampleCount += count
		out.Points = append(out.Points, point)
	}
	if err = rows.Err(); err != nil {
		storeProblem(w, err)
		return
	}
	reply(w, out)
}
