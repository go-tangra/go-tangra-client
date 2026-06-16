package executor

import (
	"fmt"
	"strings"

	"github.com/go-tangra/go-tangra-actions/action"
	"github.com/go-tangra/go-tangra-actions/workflow"
)

// ActionsPolicy controls whether and how this host runs go-tangra-actions
// workflows pushed by the executor.
type ActionsPolicy struct {
	// Enabled gates workflow execution entirely (ACTIONS_ENABLED). When false the
	// host refuses to run any pushed workflow.
	Enabled bool
	// Restricted limits execution to the native built-in structured actions only:
	// no bash/`run:` steps, no scripted (JS/Lua) actions, and no external or
	// composite actions resolved from the executor. Default true.
	Restricted bool
}

// newRestrictedRegistry returns a registry holding only the native built-in
// structured actions permitted in restricted mode — the no-shell, no-script
// actions from go-tangra-actions' `action` package. The `run` action (arbitrary
// shell) is deliberately excluded. Adding a new builtin to this list is an
// explicit, deliberate decision: an allowlist, not a denylist.
func newRestrictedRegistry() *action.Registry {
	r := action.NewRegistry()
	r.Register(&action.Package{})
	r.Register(&action.File{})
	r.Register(&action.FileLine{})
	r.Register(&action.Service{})
	r.Register(&action.ServiceStatus{})
	r.Register(&action.Hostname{})
	r.Register(&action.Timezone{})
	return r
}

// validateRestricted rejects a workflow that would run anything other than the
// allowlisted native actions: bash/`run:` steps and any `uses:` not registered
// in reg (scripted, composite, or other external actions). It returns a
// human-readable error naming the first offending step, so a workflow is refused
// up front rather than failing midway with a generic unknown-action error.
func validateRestricted(wf *workflow.Workflow, reg *action.Registry) error {
	for jobID, job := range wf.Jobs {
		for i, step := range job.Steps {
			where := fmt.Sprintf("job %q step %d", jobID, i+1)
			if id := stepIdentity(step); id != "" {
				where = fmt.Sprintf("job %q step %q", jobID, id)
			}
			switch {
			case step.IsRun():
				return fmt.Errorf("%s: shell (`run:`) execution is disabled by ACTIONS_RESTRICTED", where)
			case step.Uses == "":
				return fmt.Errorf("%s: step is neither a permitted `uses:` action nor runnable in restricted mode", where)
			default:
				if _, ok := reg.Get(step.Uses); !ok {
					return fmt.Errorf(
						"%s: action %q is not permitted by ACTIONS_RESTRICTED; only native actions are allowed: %s",
						where, step.Uses, strings.Join(reg.Names(), ", "),
					)
				}
			}
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
