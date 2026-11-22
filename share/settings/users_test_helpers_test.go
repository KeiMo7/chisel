package settings

// reloadForTest triggers one synchronous config reload; test-only access to
// the unexported loadUserIndex.
func (u *UserIndex) reloadForTest() error {
	return u.loadUserIndex()
}
