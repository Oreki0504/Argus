package agent

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/collectors"
	"github.com/Oreki0504/Argus-C2/internal/collectors/network"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/transport"
)

type Engine struct {
	now            func() time.Time
	State          *State
	Policy         policy.Policy
	Execute        func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error)
	BootID         string
	ReportMetadata bool
	associate      func(context.Context, protocol.Listeners) protocol.ListenerProcesses
}

func (e *Engine) Process(ctx context.Context, t protocol.Task, running func(context.Context, string) error) (protocol.Result, error) {
	e.State.mu.Lock()
	defer e.State.mu.Unlock()
	if err := t.Validate(); err != nil {
		return protocol.Result{}, err
	}
	if t.NodeID != e.State.NodeID {
		return protocol.Result{}, errors.New("task belongs to another node")
	}
	if err := e.Policy.Validate(); err != nil {
		return protocol.Result{}, err
	}
	old, err := e.State.prepare(ctx, t)
	if err != nil {
		return protocol.Result{}, err
	}
	if old != nil {
		return *old, nil
	}
	r := protocol.NewResult(t, protocol.Failed, "collector_failed")
	var collection *protocol.DiagnosticCollection
	now := time.Now()
	if e.now != nil {
		now = e.now()
	}
	switch {
	case t.DispatchExpiresAt <= now.Unix():
		r.Error = "task_expired"
	case t.CreatedAt > now.Unix()+protocol.MaxClockSkew:
		r.Error = "task_from_future"
	case !e.Policy.Allows(t):
		r.Error = "local_policy_denied"
	default:
		if err = running(ctx, t.ID); err != nil {
			// The server may never redeliver this assignment. Reconcile locally
			// now, without depending on another poll or a process restart.
			r = protocol.NewResult(t, protocol.Unknown, "execution_authorization_uncertain")
			var rejection *transport.APIError
			if errors.As(err, &rejection) && rejection.ExecutionRejection() {
				r = protocol.NewResult(t, protocol.Failed, "execution_authorization_rejected")
			}
			e.State.interrupted[t.ID] = r
			finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return r, errors.Join(err, e.State.recover(finishCtx))
		}
		if err = e.State.markRunning(ctx, t.ID); err != nil {
			e.State.interruption(t, "running_persistence_interrupted")
			finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return protocol.Result{}, errors.Join(err, e.State.recover(finishCtx))
		}
		// The collector gets its full bounded duration after authorization and
		// durable intent. Dispatch expiry never truncates an authorized execution.
		budget := min(time.Duration(t.ExecutionTimeoutMS)*time.Millisecond, time.Duration(e.Policy.TimeoutSeconds)*time.Second)
		taskCtx, cancel := context.WithTimeout(ctx, budget)
		execute := e.Execute
		if execute == nil {
			execute = collectors.Execute
		}
		started := time.Now()
		if e.ReportMetadata {
			if e.BootID == "" {
				e.BootID = identity.RandomID()
			}
			collection = &protocol.DiagnosticCollection{ID: identity.RandomID(), BootID: e.BootID, CollectorVersion: protocol.BuildVersion(), StartedAt: started.Unix()}
		}
		payload, collectErr := execute(taskCtx, t, e.Policy)
		contextErr := taskCtx.Err()
		if collection != nil && collectErr == nil && contextErr == nil && t.Type == protocol.NetworkListeners && protocol.ValidateListeners(payload) == nil {
			var listeners protocol.Listeners
			json.Unmarshal(payload, &listeners)
			associationCtx, associationCancel := context.WithTimeout(taskCtx, 500*time.Millisecond)
			associate := e.associate
			if associate == nil {
				associate = network.AssociateProcesses
			}
			associations := associate(associationCtx, listeners)
			associationCancel()
			collection.ListenerProcesses = &associations
		}
		if collection != nil {
			collection.DurationMS = time.Since(started).Milliseconds()
		}
		// Association is optional evidence enrichment. Its timeout cannot erase
		// a primary listener report already collected within its own deadline.
		cancel()
		if collectErr == nil && contextErr == nil {
			r.Status = protocol.Succeeded
			r.Error = ""
			r.Payload = payload
		} else if contextErr != nil {
			r.Error = "collector_timeout"
		}
	}
	r.CompletedAt = time.Now().Unix()
	if err = errors.Join(r.Validate(), r.CheckAssignment(t)); err != nil {
		r = protocol.NewResult(t, protocol.Failed, "invalid_collector_output")
	}
	attachCollection := func() {
		if collection == nil {
			return
		}
		collection.CompletedAt = r.CompletedAt
		collection.DiagnosticEvidence, _ = protocol.DiagnosticEvidenceFor(t, r)
		if r.Status != protocol.Succeeded {
			collection.ListenerProcesses = nil
		}
		r.Collection = collection
	}
	attachCollection()
	b, _ := json.Marshal(r)
	if len(b) > e.Policy.MaxResultBytes && collection != nil && collection.ListenerProcesses != nil {
		// Preserve the primary listener evidence when the optional bounded
		// association sidecar would exceed a locally configured result limit.
		collection.ListenerProcesses.Items = []protocol.ListenerProcess{}
		if collection.ListenerProcesses.Coverage != "unavailable" {
			collection.ListenerProcesses.Coverage = "partial"
		}
		b, _ = json.Marshal(r)
	}
	if len(b) > e.Policy.MaxResultBytes {
		r = protocol.NewResult(t, protocol.Failed, "result_too_large")
		attachCollection()
	}
	finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = e.State.finish(finishCtx, r)
	if err != nil {
		e.State.interruption(t, "result_persistence_interrupted")
	}
	return r, err
}
