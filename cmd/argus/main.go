package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/auth"
	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/transport"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "argus:", e)
		os.Exit(1)
	}
}
func run() error {
	f := flag.NewFlagSet("argus", flag.ContinueOnError)
	server := f.String("server", "https://localhost:8443", "server HTTPS origin")
	ca := f.String("ca", "", "CA certificate")
	tokenFile := f.String("token-file", "", "private administrator token file")
	if e := f.Parse(os.Args[1:]); e != nil {
		return e
	}
	args := f.Args()
	if len(args) == 0 {
		return errors.New("usage: argus [connection flags] nodes|telemetry|capabilities|tags|revoke|profiles|diagnose|diagnostic|cancel|alerts|alert-rules|alert-events|tasks|create|result|wait|disable|enrollment-token|audit|health|new-user [flags]")
	}
	sub := flag.NewFlagSet(args[0], flag.ContinueOnError)
	node := sub.String("node", "", "node ID")
	task := sub.String("task", "", "task ID")
	kind := sub.String("type", "system.info", "collector type")
	resource := sub.String("resource", "", "local service/profile ID")
	profile := sub.String("profile", "overview", "fixed diagnostic profile: overview, system, service, security")
	nodes := sub.String("nodes", "", "comma-separated node IDs for a diagnostic profile (maximum 50)")
	batch := sub.String("batch", "", "diagnostic batch ID")
	ttl := sub.Int("ttl", 300, "dispatch validity in seconds")
	executionTimeout := sub.Duration("execution-timeout", 10*time.Second, "collector budget, 1ms to 30s; also bounded by agent policy")
	after := sub.String("after", "", "legacy pagination cursor")
	order := sub.String("order", "id", "task listing: id or newest")
	cursor := sub.String("cursor", "", "newest task page cursor")
	status := sub.String("status", "", "task status filter with -order newest")
	alertID := sub.String("alert", "", "alert ID for event filtering")
	tags := sub.String("tags", "", "comma-separated administrator labels; empty removes all tags")
	limit := sub.Int("limit", 20, "newest task page size, 1-200")
	createdAfter := sub.Int64("created-after", 0, "inclusive task creation lower bound, Unix seconds")
	createdBefore := sub.Int64("created-before", 0, "inclusive task creation upper bound, Unix seconds")
	from := sub.Int64("from", 0, "telemetry observation lower bound, Unix seconds (default: 24 hours ago)")
	to := sub.Int64("to", 0, "telemetry observation upper bound, Unix seconds (default: now)")
	timeout := sub.Duration("timeout", 5*time.Minute, "wait deadline")
	out := sub.String("out", "", "new private token file")
	name := sub.String("name", "", "administrator name")
	role := sub.String("role", "ReadOnly", "Admin or ReadOnly")
	expiresIn := sub.Duration("expires-in", 0, "new-user token lifetime, 1 minute to 365 days; zero preserves legacy no-expiry behavior")
	if e := sub.Parse(args[1:]); e != nil {
		return e
	}
	if sub.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if args[0] == "new-user" {
		if *expiresIn != 0 && (*expiresIn < time.Minute || *expiresIn > 365*24*time.Hour) {
			return errors.New("expires-in must be zero or between 1 minute and 365 days")
		}
		u, token, e := auth.NewUser(*name, *role)
		if e != nil {
			return e
		}
		if *expiresIn > 0 {
			u.ExpiresAt = time.Now().Add(*expiresIn).Unix()
		}
		if e = writeToken(*out, token); e != nil {
			return e
		}
		return printJSON(u)
	}
	b, e := localfile.Read(*tokenFile, 1024, true)
	if e != nil {
		return e
	}
	token := strings.TrimSpace(string(b))
	client, e := transport.Client(*ca, "", "")
	if e != nil {
		return e
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	method, path := "GET", ""
	var input any
	switch args[0] {
	case "capabilities":
		if *node == "" {
			return errors.New("-node is required")
		}
		path = "/v1/nodes/" + url.PathEscape(*node) + "/capabilities"
	case "tags":
		if *node == "" {
			return errors.New("-node is required")
		}
		labels := []string{}
		if *tags != "" {
			labels = strings.Split(*tags, ",")
		}
		method, path, input = "PUT", "/v1/nodes/"+url.PathEscape(*node)+"/tags", map[string]any{"tags": labels}
	case "revoke":
		if *node == "" {
			return errors.New("-node is required")
		}
		method, path, input = "POST", "/v1/nodes/"+url.PathEscape(*node)+"/revoke", struct{}{}
	case "alert-rules":
		path = "/v1/alert-rules"
	case "alerts":
		query := database.AlertQuery{NodeID: *node, Status: *status, Cursor: *cursor, Limit: *limit}
		if err := query.Validate(); err != nil {
			return err
		}
		values := url.Values{"node_id": {*node}, "status": {*status}, "cursor": {*cursor}, "limit": {fmt.Sprint(*limit)}}
		path = "/v1/alerts?" + values.Encode()
	case "alert-events":
		sequence := int64(0)
		if *after != "" {
			var err error
			sequence, err = strconv.ParseInt(*after, 10, 64)
			if err != nil {
				return err
			}
		}
		query := database.AlertEventQuery{NodeID: *node, AlertID: *alertID, After: sequence, Limit: *limit}
		if err := query.Validate(); err != nil {
			return err
		}
		values := url.Values{"node_id": {*node}, "alert_id": {*alertID}, "after": {fmt.Sprint(sequence)}, "limit": {fmt.Sprint(*limit)}}
		path = "/v1/alert-events?" + values.Encode()
	case "profiles":
		path = "/v1/diagnostic-profiles"
	case "diagnostic":
		if *batch == "" {
			return errors.New("-batch is required")
		}
		path = "/v1/diagnostics/" + url.PathEscape(*batch)
	case "diagnose":
		if *node != "" && *nodes != "" || *node == "" && *nodes == "" {
			return errors.New("specify -node or -nodes for diagnostics")
		}
		selected := []string{*node}
		if *nodes != "" {
			selected = strings.Split(*nodes, ",")
		}
		if *executionTimeout < time.Millisecond || *executionTimeout > 30*time.Second || *executionTimeout%time.Millisecond != 0 {
			return errors.New("execution-timeout must be whole milliseconds from 1ms to 30s")
		}
		request := protocol.DiagnosticRequest{NodeIDs: selected, ProfileID: *profile, ResourceID: *resource, TTLSeconds: *ttl, ExecutionTimeoutMS: int(executionTimeout.Milliseconds())}
		if _, err := request.Tasks(); err != nil {
			return err
		}
		method, path, input = "POST", "/v1/diagnostics", request
	case "cancel":
		if *task == "" {
			return errors.New("-task is required")
		}
		method, path, input = "POST", "/v1/tasks/"+url.PathEscape(*task)+"/cancel", struct{}{}
	case "telemetry":
		if *cursor != "" && (*from == 0 || *to == 0) {
			return errors.New("telemetry pagination requires the original -from and -to bounds")
		}
		now := time.Now().Unix()
		if *from == 0 {
			*from = now - 86400
		}
		if *to == 0 {
			*to = now
		}
		query := database.TelemetryQuery{From: *from, To: *to, Limit: *limit, Cursor: *cursor}
		if err := query.Validate(*node); err != nil {
			return err
		}
		values := url.Values{"from": {fmt.Sprint(*from)}, "to": {fmt.Sprint(*to)}, "limit": {fmt.Sprint(*limit)}, "cursor": {*cursor}}
		path = "/v1/nodes/" + url.PathEscape(*node) + "/telemetry?" + values.Encode()
	case "nodes":
		path = "/v1/nodes?after=" + url.QueryEscape(*after)
	case "tasks":
		if *order == "id" {
			if *node != "" || *status != "" || *cursor != "" || *createdAfter != 0 || *createdBefore != 0 || *limit != 20 {
				return errors.New("task filters require -order newest")
			}
			path = "/v1/tasks?after=" + url.QueryEscape(*after)
		} else if *order == "newest" && *after == "" {
			q := database.TaskQuery{NodeID: *node, Status: protocol.TaskStatus(*status), CreatedAfter: *createdAfter, CreatedBefore: *createdBefore, Limit: *limit, Cursor: *cursor}
			if e = q.Validate(); e != nil {
				return e
			}
			values := url.Values{"order": {"newest"}, "node_id": {*node}, "status": {*status}, "cursor": {*cursor}, "limit": {fmt.Sprint(*limit)}, "created_after": {fmt.Sprint(*createdAfter)}, "created_before": {fmt.Sprint(*createdBefore)}}
			path = "/v1/tasks?" + values.Encode()
		} else {
			return errors.New("invalid task order or mixed cursors")
		}
	case "health":
		path = "/v1/health"
	case "audit":
		path = "/v1/audit?after=" + url.QueryEscape(*after)
	case "disable":
		if *node == "" {
			return errors.New("-node is required")
		}
		method = "POST"
		path = "/v1/nodes/" + url.PathEscape(*node) + "/disable"
		input = struct{}{}
	case "enrollment-token":
		method = "POST"
		path = "/v1/enrollment-tokens"
		input = map[string]int{"ttl_seconds": *ttl}
		if *out == "" {
			return errors.New("-out private token file is required")
		}
	case "create":
		if *executionTimeout < time.Millisecond || *executionTimeout > 30*time.Second || *executionTimeout%time.Millisecond != 0 {
			return errors.New("execution-timeout must be a whole number of milliseconds from 1ms to 30s")
		}
		params := json.RawMessage(`{}`)
		if *resource != "" {
			field := "service_id"
			if *kind == string(protocol.SSHAudit) {
				field = "profile_id"
			}
			params, e = json.Marshal(map[string]string{field: *resource})
			if e != nil {
				return e
			}
		}
		request := protocol.TaskRequest{NodeID: *node, Type: protocol.TaskType(*kind), Params: params, TTLSeconds: *ttl, ExecutionTimeoutMS: int(executionTimeout.Milliseconds())}
		raw, _ := json.Marshal(request)
		if _, e = protocol.DecodeTaskRequest(raw); e != nil {
			return e
		}
		method = "POST"
		path = "/v1/tasks"
		input = request
	case "result", "wait":
		if *task == "" {
			return errors.New("-task is required")
		}
		path = "/v1/tasks/" + url.PathEscape(*task)
	default:
		return errors.New("unknown command")
	}
	for {
		b, e = transport.Request(ctx, client, *server, token, method, path, input)
		if e != nil {
			return e
		}
		if args[0] == "enrollment-token" {
			var v struct {
				Token string `json:"token"`
			}
			if e = json.Unmarshal(b, &v); e != nil {
				return e
			}
			if e = writeToken(*out, v.Token); e != nil {
				return e
			}
			fmt.Println("Enrollment token saved to", *out)
			return nil
		}
		if args[0] != "wait" {
			var v any
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.UseNumber() // Preserve exact uint64 telemetry counters in CLI output.
			if e = decoder.Decode(&v); e != nil {
				return e
			}
			return printJSON(v)
		}
		var view database.TaskView
		if e = json.Unmarshal(b, &view); e != nil {
			return e
		}
		if protocol.Terminal(view.Task.Status) {
			if e = printJSON(view); e != nil {
				return e
			}
			if view.Task.Status != protocol.Succeeded {
				if view.Task.Status == protocol.Unknown && view.Result == nil {
					return errors.New("task outcome overdue; no result stored, a late result may still resolve it")
				}
				return errors.New("task completed with " + string(view.Task.Status))
			}
			return nil
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func printJSON(v any) error {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	return e.Encode(v)
}
func writeToken(path, token string) error {
	if path == "" {
		return errors.New("-out is required")
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.WriteString(token + "\n")
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}
