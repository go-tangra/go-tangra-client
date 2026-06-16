package executor

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/go-tangra/go-tangra-actions/action"
	"github.com/go-tangra/go-tangra-actions/engine"
	"github.com/go-tangra/go-tangra-actions/workflow"
)

// maxRestrictedDepth bounds composite-action nesting during validation, matching
// the engine's own composite depth guard.
const maxRestrictedDepth = 16

// ActionsPolicy controls whether and how this host runs go-tangra-actions
// workflows pushed by the executor.
type ActionsPolicy struct {
	// Enabled gates workflow execution entirely (ACTIONS_ENABLED). When false the
	// host refuses to run any pushed workflow.
	Enabled bool
	// Restricted limits execution to predefined, code-free actions: native
	// built-in actions and composite actions that (recursively) use only those.
	// No `run:` shell steps and no scripted (JS/Lua) actions are permitted at any
	// depth — not at the workflow level, not inside a composite action. Default true.
	Restricted bool
}

// newRestrictedRegistry returns a registry holding only the native built-in
// structured actions — the no-shell, no-script actions from go-tangra-actions'
// `action` package. The `run` action (arbitrary shell) is deliberately excluded,
// so even if validation were bypassed the engine could never dispatch bash.
// Adding a new builtin here is an explicit, deliberate decision: an allowlist.
func newRestrictedRegistry() *action.Registry {
	r := action.NewRegistry()
	r.Register(&action.Package{})
	r.Register(&action.File{})
	r.Register(&action.FileLine{})
	r.Register(&action.Service{})
	r.Register(&action.ServiceStatus{})
	r.Register(&action.Log{})
	r.Register(&action.Hostname{})
	r.Register(&action.Timezone{})
	return r
}

// validateRestricted refuses a workflow that would execute any code in restricted
// mode. Permitted: native built-in actions, and composite actions that
// (recursively) reference only permitted actions. Rejected anywhere — workflow
// step or composite step, at any nesting depth: `run:` shell steps and scripted
// (JS/Lua) actions. Composite actions are resolved via resolver so their
// internals can be inspected; an action that cannot be resolved is rejected
// (fail closed). The first offending step is named.
func validateRestricted(ctx context.Context, wf *workflow.Workflow, reg *action.Registry, resolver engine.Resolver) error {
	for jobID, job := range wf.Jobs {
		for i, step := range job.Steps {
			loc := fmt.Sprintf("job %q step %d", jobID, i+1)
			if id := stepIdentity(step); id != "" {
				loc = fmt.Sprintf("job %q step %q", jobID, id)
			}
			if err := validateStep(ctx, step, reg, resolver, nil); err != nil {
				return fmt.Errorf("%s: %w", loc, err)
			}
		}
	}
	return nil
}

// validateStep checks a single step (workflow- or composite-level).
func validateStep(ctx context.Context, step workflow.Step, reg *action.Registry, resolver engine.Resolver, stack []string) error {
	switch {
	case step.IsRun():
		return fmt.Errorf("shell (`run:`) steps are not permitted by ACTIONS_RESTRICTED")
	case step.Uses == "":
		return fmt.Errorf("step is neither a permitted `uses:` action nor runnable in restricted mode")
	default:
		return validateActionRef(ctx, step.Uses, reg, resolver, stack)
	}
}

// validateActionRef permits a native builtin or a composite action whose steps
// (recursively) are all permitted. Scripted (JS/Lua) actions are rejected.
func validateActionRef(ctx context.Context, name string, reg *action.Registry, resolver engine.Resolver, stack []string) error {
	if _, ok := reg.Get(name); ok {
		return nil // native builtin — code-free, allowed
	}
	if resolver == nil {
		return fmt.Errorf("action %q is not a native action and cannot be resolved; only native actions are allowed: %s",
			name, strings.Join(reg.Names(), ", "))
	}
	if len(stack) >= maxRestrictedDepth {
		return fmt.Errorf("action %q exceeds max composite nesting depth %d", name, maxRestrictedDepth)
	}
	if slices.Contains(stack, name) {
		return fmt.Errorf("action %q forms a composite cycle (%s)", name, strings.Join(append(stack, name), " -> "))
	}

	resolved, err := resolver.Resolve(ctx, name)
	if err != nil {
		return fmt.Errorf("action %q could not be resolved for inspection: %w", name, err)
	}
	if !resolved.Def.Runs.IsComposite() {
		return fmt.Errorf("action %q is a %q script, which is not permitted by ACTIONS_RESTRICTED",
			name, resolved.Def.Runs.Using)
	}

	next := append(append([]string{}, stack...), name)
	for i, cstep := range resolved.Def.Runs.Steps {
		if err := validateStep(ctx, cstep, reg, resolver, next); err != nil {
			where := fmt.Sprintf("step %d", i+1)
			if id := stepIdentity(cstep); id != "" {
				where = fmt.Sprintf("step %q", id)
			}
			return fmt.Errorf("action %q → %s: %w", name, where, err)
		}
	}
	return nil
}

// stepIdentity is the display identifier for a workflow step (id, else name).
func stepIdentity(s workflow.Step) string {
	if s.ID != "" {
		return s.ID
	}
	return s.Name
}
