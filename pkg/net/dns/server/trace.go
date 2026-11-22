package server

import "github.com/Asutorufa/yuhaiin/pkg/net/netapi"

// traceFailure names where the server refused or lost a request. Call sites
// pass a one-byte code instead of the full classification so the frames of
// the DNS path (which run on fresh goroutines) stay small when history is off.
type traceFailure uint8

const (
	failContextDone traceFailure = iota
	failShutdown
	failParse
	failEmptyQuestion
	failReadTCP
	failBeforeWrite
	failPack
	failCanceledInQueue
	failExpired
	failBudgetFull
	failQueueFull
)

var traceFailures = [...]struct {
	outcome, stage, reason string
}{
	failContextDone:     {"", netapi.DNSStageAdmission, "context_done"},
	failShutdown:        {netapi.DNSOutcomeDropped, netapi.DNSStageAdmission, "shutdown"},
	failParse:           {netapi.DNSOutcomeMalformed, netapi.DNSStageIngress, "parse_failed"},
	failEmptyQuestion:   {netapi.DNSOutcomeMalformed, netapi.DNSStageIngress, "empty_question"},
	failReadTCP:         {netapi.DNSOutcomeMalformed, netapi.DNSStageIngress, "read_failed"},
	failBeforeWrite:     {"", netapi.DNSStageDelivery, "context_done_before_write"},
	failPack:            {netapi.DNSOutcomeInternal, netapi.DNSStagePack, "pack_failed"},
	failCanceledInQueue: {"", netapi.DNSStageAdmission, "canceled_in_queue"},
	failExpired:         {netapi.DNSOutcomeDropped, netapi.DNSStageAdmission, "expired"},
	failBudgetFull:      {netapi.DNSOutcomeDropped, netapi.DNSStageAdmission, "budget_full"},
	failQueueFull:       {netapi.DNSOutcomeDropped, netapi.DNSStageAdmission, "queue_full"},
}

// traceFail records a failure; an empty table outcome is derived from err
// (timeout or canceled). A request that times out while still queued was
// dropped by admission, not by an upstream.
//
//go:noinline
func traceFail(t *netapi.DNSTrace, code traceFailure, err error) {
	if t == nil {
		return
	}
	f := traceFailures[code]
	outcome := f.outcome
	if outcome == "" {
		outcome = netapi.ClassifyDNSError(err)
		if code == failCanceledInQueue && outcome == netapi.DNSOutcomeTimeout {
			outcome = netapi.DNSOutcomeDropped
		}
	}
	t.Fail(outcome, f.stage, f.reason, err)
}
