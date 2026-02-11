package backoff

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"
)

// Backoff implements exponential backoff with jitter.
type Backoff struct {
	InitialInterval time.Duration
	MaxInterval     time.Duration
	Multiplier      float64
	attempt         int
}

// New creates a Backoff with sensible defaults:
// starts at 2s, doubles each attempt, caps at 2 minutes.
func New() *Backoff {
	return &Backoff{
		InitialInterval: 2 * time.Second,
		MaxInterval:     2 * time.Minute,
		Multiplier:      2.0,
	}
}

// NextDuration returns the next backoff duration and increments the attempt counter.
func (b *Backoff) NextDuration() time.Duration {
	d := float64(b.InitialInterval) * math.Pow(b.Multiplier, float64(b.attempt))
	if d > float64(b.MaxInterval) {
		d = float64(b.MaxInterval)
	}
	// Add jitter: +/- 20%
	jitter := d * 0.2 * (rand.Float64()*2 - 1)
	d += jitter
	b.attempt++
	return time.Duration(d)
}

// Reset resets the attempt counter (call after a successful connection).
func (b *Backoff) Reset() {
	b.attempt = 0
}

// Wait blocks until the backoff duration elapses or the context is cancelled.
// Returns the duration waited and whether the context was cancelled.
func (b *Backoff) Wait(ctx context.Context) (time.Duration, bool) {
	d := b.NextDuration()
	fmt.Printf("  Reconnecting in %s (attempt %d)...\n", d.Round(time.Millisecond), b.attempt)
	select {
	case <-ctx.Done():
		return d, true
	case <-time.After(d):
		return d, false
	}
}
