package samlidp

import (
	"context"
	"errors"
)

// ErrNotFound is returned from Store.Get() when a stored item is not present
var ErrNotFound = errors.New("not found")

// Store is an interface that describes an abstract key-value store.
type Store interface {
	// Get fetches the data stored in `key` and unmarshals it into `value`.
	Get(ctx context.Context, key string, value interface{}) error

	// Put marshals `value` and stores it in `key`.
	Put(ctx context.Context, key string, value interface{}) error

	// Delete removes `key`
	Delete(ctx context.Context, key string) error

	// List returns all the keys that start with `prefix`. The prefix is
	// stripped from each returned value. So if keys are ["aa", "ab", "cd"]
	// then List("a") would produce []string{"a", "b"}
	List(ctx context.Context, prefix string) ([]string, error)
}
