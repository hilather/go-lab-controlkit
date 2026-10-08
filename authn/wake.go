package authn

import "sync"

// Wake is a broadcast. Subscribe returns the current channel. Signal closes
// that channel and installs a fresh one. Signal never blocks and never calls
// back. A subscriber that arrives after Signal receives the fresh channel.
type Wake struct {
	mu sync.Mutex
	ch chan struct{}
}

// NewWake returns a wake with an open channel.
func NewWake() *Wake {
	return &Wake{ch: make(chan struct{})}
}

// Subscribe returns the current channel.
func (w *Wake) Subscribe() <-chan struct{} {
	if w == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ch
}

// Signal closes the current channel and replaces it. It does not block.
func (w *Wake) Signal() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	close(w.ch)
	w.ch = make(chan struct{})
}
