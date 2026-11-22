package chserver

import (
	"runtime"

	"github.com/jpillora/chisel/share/settings"
)

// authGate serializes the expensive part of password verification.
//
// Bcrypt deliberately burns CPU (tens to hundreds of milliseconds per
// comparison at production costs). Without a cap, a flood of login attempts
// would occupy every core and starve the rest of the server. The gate is a
// weighted semaphore sized from GOMAXPROCS (overridable via
// CHISEL_AUTH_CONCURRENCY), so verification scales on big machines while
// staying bounded on small ones.
type authGate struct {
	slots chan struct{}
	// dummyHash is a valid bcrypt hash used to spend real bcrypt time on
	// the "user does not exist" path, keeping its latency indistinguishable
	// from a wrong-password attempt against a hashed account.
	dummyHash string
}

func newAuthGate() (*authGate, error) {
	max := settings.EnvInt("AUTH_CONCURRENCY", 0)
	if max <= 0 {
		if max = runtime.GOMAXPROCS(0); max < 1 {
			max = 1
		}
	}
	dummy, err := settings.HashPassword("chisel-dummy-credential", settings.DefaultBcryptCost)
	if err != nil {
		return nil, err
	}
	return &authGate{
		slots:     make(chan struct{}, max),
		dummyHash: dummy,
	}, nil
}

// verify runs the credential check under the concurrency cap. It takes the
// lock regardless of whether the user exists, so even unknown-user attempts
// count against the same budget and cannot be used to bypass the limit.
//
// Every failure path spends one bcrypt-strength comparison:
//   - unknown user: a throwaway dummy hash, result discarded;
//   - hashed account, wrong password: the real bcrypt comparison;
//   - plaintext (legacy) account, wrong password: the fast constant-time
//     compare fails, then a dummy bcrypt round is added so this response is
//     not faster than the other two — otherwise timing would reveal both
//     account existence and the legacy storage form.
//
// Successful authentications return as soon as the credential matches.
func (g *authGate) verify(user *settings.User, found bool, presented string) bool {
	g.slots <- struct{}{}
	defer func() { <-g.slots }()

	if !found || user == nil {
		_ = settings.CompareBcrypt(g.dummyHash, presented)
		return false
	}
	ok := user.VerifyPassword(presented)
	if !ok && !user.HasHash() {
		_ = settings.CompareBcrypt(g.dummyHash, presented)
	}
	return ok
}
