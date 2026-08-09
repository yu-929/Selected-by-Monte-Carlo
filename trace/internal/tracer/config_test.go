package tracer

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxHops != 12 {
		t.Errorf("MaxHops = %d, want 12", cfg.MaxHops)
	}
	if cfg.MaxEmpty != 8 {
		t.Errorf("MaxEmpty = %d, want 8", cfg.MaxEmpty)
	}
	if cfg.TimeoutHop != 500*time.Millisecond {
		t.Errorf("TimeoutHop = %s, want 500ms", cfg.TimeoutHop)
	}
	if cfg.TimeoutTotal != 60*time.Second {
		t.Errorf("TimeoutTotal = %s, want 60s", cfg.TimeoutTotal)
	}
}

func TestRetryConfig(t *testing.T) {
	cfg := DefaultConfig().RetryConfig()
	if cfg.MaxHops != 25 {
		t.Errorf("MaxHops = %d, want 25", cfg.MaxHops)
	}
	if cfg.TimeoutHop != 1000*time.Millisecond {
		t.Errorf("TimeoutHop = %s, want 1000ms", cfg.TimeoutHop)
	}
	if cfg.TimeoutTotal != 90*time.Second {
		t.Errorf("TimeoutTotal = %s, want 90s", cfg.TimeoutTotal)
	}
}
