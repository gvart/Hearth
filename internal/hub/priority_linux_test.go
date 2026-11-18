// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// niceCheck, run in a child test binary, lowers its priority, starts new
// threads, and exits 0 only if every thread has nice 19.
func niceCheck() int {
	if err := lowerPriority(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	var wg sync.WaitGroup
	hold := make(chan struct{})
	defer close(hold)
	for range 4 {
		wg.Add(1)
		go func() {
			runtime.LockOSThread() // forces a fresh thread, kept until the check is done
			wg.Done()
			<-hold
		}()
	}
	wg.Wait()
	ents, err := os.ReadDir("/proc/self/task")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	for _, e := range ents {
		b, err := os.ReadFile("/proc/self/task/" + e.Name() + "/stat")
		if err != nil {
			continue // the thread exited
		}
		// The fields after the ")" that ends the command name; nice is the 17th.
		f := strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+1:]))
		if f[16] != "19" {
			fmt.Fprintf(os.Stderr, "thread %s has nice %s\n", e.Name(), f[16])
			return 1
		}
	}
	return 0
}

func TestLowerPriorityAllThreads(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(t.Context(), exe, niceCheckArg).CombinedOutput()
	if err != nil {
		t.Fatalf("nice check: %v: %s", err, out)
	}
}
