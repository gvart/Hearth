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

// TuneRuntime keeps the long-running agent under its 20 MB idle limit. Only
// `hearth agent run` calls it, as it changes the whole process. Pass connected
// as Config.Connected; stop cancels a collection that has not run yet.
//
// The agent is nearly always idle, so one P is enough; each further P costs
// memory for its caches and GC worker. An explicit GOMAXPROCS is respected.
//
// The runtime's periodic GC only starts after a first cycle, and an idle agent
// takes most of an hour to allocate its way to the first one, so until then
// its garbage keeps growing RSS. Collecting early bounds that from the start.
// A reconnect's TLS handshake leaves free heap behind in the same way, so the
// agent collects after each one too and returns that memory to the OS.
func TuneRuntime() (connected, stop func()) {
	return tuneRuntime(collectionDelay, debug.FreeOSMemory)
}

// LimitProcs limits the process to one P unless GOMAXPROCS is set. main calls
// it first thing for `hearth agent run`: the earlier, the fewer threads the
// runtime has started by then.
func LimitProcs() {
	if os.Getenv("GOMAXPROCS") == "" {
		runtime.GOMAXPROCS(1)
	}
}

func tuneRuntime(delay time.Duration, collect func()) (connected, stop func()) {
	LimitProcs()
	t := time.AfterFunc(delay, collect)
	return func() { t.Reset(delay) }, func() { t.Stop() }
}
