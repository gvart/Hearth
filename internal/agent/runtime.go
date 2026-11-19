// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"os"
	"runtime"
	"runtime/debug"
	"time"
)

// collectionDelay is how long after start, and after each connection to a hub,
// the agent collects garbage: long enough for that burst of work to finish.
const collectionDelay = 30 * time.Second

// failureGap is the least time between two collections after failed attempts
// to reach a hub. Retries back off to about one a minute, so during a long
// outage the agent collects after nearly every attempt, and the quick retries
// at the start of an outage share one collection.
const failureGap = 30 * time.Second

// TuneRuntime keeps the long-running agent under its 20 MB idle limit. Only
// `hearth agent run` calls it, as it changes the whole process. Pass connected
// as Config.Connected and failed as Config.Failed; stop cancels a collection
// that has not run yet.
//
// The agent is nearly always idle, so one P is enough; each further P costs
// memory for its caches and GC worker. An explicit GOMAXPROCS is respected.
//
// The runtime's periodic GC only starts after a first cycle, and an idle agent
// takes most of an hour to allocate its way to the first one, so until then
// its garbage keeps growing RSS. Collecting early bounds that from the start.
// A reconnect's TLS handshake leaves free heap behind in the same way, so the
// agent collects after each one too and returns that memory to the OS. While
// the hub is unreachable, each failed attempt leaves the same kind of garbage
// (facts, a dial, perhaps a TLS handshake) and no connection comes to collect
// it, so the agent also collects after failed attempts, at most once per
// failureGap.
func TuneRuntime() (connected, failed, stop func()) {
	return tuneRuntime(collectionDelay, failureGap, time.Now, debug.FreeOSMemory)
}

// LimitProcs limits the process to one P unless GOMAXPROCS is set. main calls
// it first thing for `hearth agent run`: the earlier, the fewer threads the
// runtime has started by then.
func LimitProcs() {
	if os.Getenv("GOMAXPROCS") == "" {
		runtime.GOMAXPROCS(1)
	}
}

// tuneRuntime is TuneRuntime with its delays, clock and collection injected.
// failed collects at once when the last collection it ran is at least gap
// old; Run calls it from one goroutine only.
func tuneRuntime(delay, gap time.Duration, now func() time.Time, collect func()) (connected, failed, stop func()) {
	LimitProcs()
	t := time.AfterFunc(delay, collect)
	var last time.Time
	failed = func() {
		if n := now(); last.IsZero() || n.Sub(last) >= gap {
			last = n
			collect()
		}
	}
	return func() { t.Reset(delay) }, failed, func() { t.Stop() }
}
