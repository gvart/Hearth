// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"sync"
	"time"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// ReauthTTL is how long entering the admin password again lets a session
// take sensitive actions of the web UI.
const ReauthTTL = 5 * time.Minute

// errReauthRequired refuses a sensitive action whose session did not enter
// the admin password again within ReauthTTL. Policy audits it as a denial.
var errReauthRequired = fmt.Errorf("the admin password was not entered again in the last %s: %w", ReauthTTL, policy.ErrDenied)

// reauths remembers, by the SHA-256 of each session secret, when the session
// last entered the admin password: in memory, on this hub only. A restart
// forgets them, which only asks for the password again.
type reauths struct {
	mu sync.Mutex
	at map[[sha256.Size]byte]time.Time
}

func sessionKey(secret string) [sha256.Size]byte { return sha256.Sum256([]byte(secret)) }

// mark records that the session secret entered the password at now, and
// forgets the marks that expired.
func (s *reauths) mark(secret string, now time.Time) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.at == nil {
		s.at = map[[sha256.Size]byte]time.Time{}
	}
	maps.DeleteFunc(s.at, func(_ [sha256.Size]byte, at time.Time) bool { return !now.Before(at.Add(ReauthTTL)) })
	s.at[sessionKey(secret)] = now
	return now.Add(ReauthTTL)
}

// until is when the session secret's re-authentication ends; zero if it has
// none in force at now.
func (s *reauths) until(secret string, now time.Time) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	at, ok := s.at[sessionKey(secret)]
	if !ok || !now.Before(at.Add(ReauthTTL)) {
		return time.Time{}
	}
	return at.Add(ReauthTTL)
}

// forget drops the session secret's mark, as its session ends.
func (s *reauths) forget(secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.at, sessionKey(secret))
}

// forgetAll drops every mark, as a password change ends every session.
func (s *reauths) forgetAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.at)
}

// sessionSecret is the request's session secret; auth admitted it.
func sessionSecret(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName(r))
	if err != nil {
		return ""
	}
	return c.Value
}

// reauthUntil is when the request's session's re-authentication ends; zero
// for none.
func (a *api) reauthUntil(r *http.Request) time.Time {
	secret := sessionSecret(r)
	if secret == "" {
		return time.Time{}
	}
	return a.reauths.until(secret, a.now())
}

// recentAuth is the Precheck of a sensitive web action: it refuses, as an
// audited denial, unless the session entered the admin password again within
// ReauthTTL. It runs before a hold, so a refused request is never held.
func (a *api) recentAuth(r *http.Request) func(context.Context) error {
	return func(context.Context) error {
		if a.reauthUntil(r).IsZero() {
			return errReauthRequired
		}
		return nil
	}
}

// ReauthJSON answers a re-authentication: sensitive actions need no
// password again until Until.
type ReauthJSON struct {
	Until time.Time `json:"reauth_until"`
}

// reauth checks the admin password again for the signed-in session, as login
// checks it and under login's rate limit, through policy (admin.reauth) and
// audited, wrong passwords too. The password is never logged.
func (a *api) reauth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	password, ok := approvePassword(w, r)
	if !ok {
		return
	}
	// As approving: only a request with a password costs a verification and
	// a token, which a password that is not wrong gives back.
	wrong := false
	if password != "" {
		if ok, wait := a.logins.allow(remoteHost(r)); !ok {
			writeRetry(w, http.StatusTooManyRequests, wait, "rate_limited", "too many password attempts; try again later")
			return
		}
		defer func() {
			if !wrong {
				a.logins.refund(remoteHost(r))
			}
		}()
	}
	var until time.Time
	err := a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.AdminReauth, Target: adminUser,
	}, func(ctx context.Context) error {
		if password == "" {
			return errNoPassword
		}
		err := a.checkAdminPassword(ctx, password)
		wrong = errors.Is(err, errWrongPassword)
		if err != nil {
			return err
		}
		until = a.reauths.mark(sessionSecret(r), a.now())
		return nil
	})
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, ReauthJSON{Until: until.UTC()})
	case errors.Is(err, errWrongPassword), errors.Is(err, errNoPassword):
		a.log.WarnContext(ctx, "re-authentication failed: wrong or missing password", "remote", remoteHost(r))
		writeError(w, http.StatusForbidden, "reauth_failed", "the password was missing or wrong")
	case errors.Is(err, errVerifyBusy):
		writeRetry(w, http.StatusServiceUnavailable, a.verifyWait, "busy", "the hub is busy checking other passwords; try again shortly")
	case ctx.Err() != nil:
		// The client went away.
	default:
		a.writeActionError(w, r, "re-authenticate", err)
	}
}

// writeActionError answers a web action that policy refused or that failed:
// a missing re-authentication, a denial, a cluster without a leader, or an
// internal error, logged without the request's body.
func (a *api) writeActionError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, errReauthRequired):
		writeError(w, http.StatusForbidden, "reauth_required", "enter the admin password again to do this")
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
	case r.Context().Err() != nil:
		// The client went away.
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	default:
		a.log.ErrorContext(r.Context(), op, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot "+op)
	}
}
