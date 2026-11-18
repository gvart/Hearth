// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"testing"

	"github.com/gvart/hearth/internal/store"
)

func TestLocalWrites(t *testing.T) {
	data := []byte("cmd")
	res := store.Result{Count: 7}

	t.Run("an entry nobody waits for is not local", func(t *testing.T) {
		var w localWrites
		if w.claim(data, res) {
			t.Error("claimed without a caller")
		}
	})
	t.Run("an entry applied after its caller gave up is not local", func(t *testing.T) {
		var w localWrites
		w.begin(data)
		if _, claimed := w.end(data); claimed {
			t.Error("end reported a claim before any apply")
		}
		if w.claim(data, res) {
			t.Error("claimed after the caller left")
		}
	})
	t.Run("a claimed entry hands its result to the caller", func(t *testing.T) {
		var w localWrites
		w.begin(data)
		if !w.claim(data, res) {
			t.Fatal("not claimed while the caller waits")
		}
		if got, claimed := w.end(data); !claimed || got.Count != res.Count {
			t.Errorf("end = %+v, %v; want the claimed result", got, claimed)
		}
		if len(w.waiting) != 0 {
			t.Errorf("%d writes left behind", len(w.waiting))
		}
	})
	t.Run("one caller claims one entry", func(t *testing.T) {
		var w localWrites
		w.begin(data)
		if !w.claim(data, res) {
			t.Fatal("first entry not claimed")
		}
		if w.claim(data, res) {
			t.Error("a second identical entry was claimed for the same caller")
		}
	})
	t.Run("identical writes are counted apart", func(t *testing.T) {
		var w localWrites
		w.begin(data)
		w.begin(data)
		for range 2 {
			if !w.claim(data, res) {
				t.Fatal("both entries should be claimed")
			}
		}
		for range 2 {
			if _, claimed := w.end(data); !claimed {
				t.Error("a caller lost its claim")
			}
		}
	})
}
