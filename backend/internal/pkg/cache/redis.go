package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

// Client wraps redis.Client with typed helpers.
type Client struct {
	rdb *redis.Client
}

// New creates a Redis client and verifies connectivity.
func New(ctx context.Context, addr, password string, db int) (*Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DB:           db,
		PoolSize:     20,
		MinIdleConns: 5,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	return &Client{rdb: rdb}, nil
}

// NewFromURL creates a client from a redis:// or rediss:// URL, the form the
// deployment already passes as REDIS_URL. It returns (nil, nil) for an empty
// URL, so a caller can treat Redis as optional without inspecting the
// environment itself.
//
// It fails only on a URL it cannot parse — a configuration bug worth refusing
// to start over. A Redis that is merely unreachable is warned about and the
// client returned anyway: go-redis reconnects on its own, and a service that
// will not start is worse than one running on its fallbacks until Redis is
// back.
func NewFromURL(ctx context.Context, url string, logger zerolog.Logger) (*Client, error) {
	if url == "" {
		return nil, nil
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	applyDefaults(opts)

	c := &Client{rdb: redis.NewClient(opts)}
	if err := c.Ping(ctx); err != nil {
		logger.Warn().Err(err).Str("addr", opts.Addr).
			Msg("redis_unreachable_at_startup_running_on_fallbacks_until_it_returns")
	}
	return c, nil
}

// Ping reports whether Redis is currently answering.
func (c *Client) Ping(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

// applyDefaults sets the pool and timeout settings shared by every entry point.
func applyDefaults(opts *redis.Options) {
	opts.PoolSize = 20
	opts.MinIdleConns = 5
	opts.DialTimeout = 5 * time.Second
	opts.ReadTimeout = 3 * time.Second
	opts.WriteTimeout = 3 * time.Second
}

// Close closes the Redis connection pool.
func (c *Client) Close() error {
	return c.rdb.Close()
}

// Set stores a JSON-serialised value with a TTL. TTL = 0 means no expiry.
func (c *Client) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	b, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal value: %w", err)
	}
	return c.rdb.Set(ctx, key, b, ttl).Err()
}

// Get retrieves and JSON-deserialises a value. Returns redis.Nil if key not found.
func (c *Client) Get(ctx context.Context, key string, dest any) error {
	b, err := c.rdb.Get(ctx, key).Bytes()
	if err != nil {
		return err // caller checks redis.Nil
	}
	return json.Unmarshal(b, dest)
}

// Del removes one or more keys.
func (c *Client) Del(ctx context.Context, keys ...string) error {
	return c.rdb.Del(ctx, keys...).Err()
}

// Exists returns true if the key exists.
func (c *Client) Exists(ctx context.Context, key string) (bool, error) {
	n, err := c.rdb.Exists(ctx, key).Result()
	return n > 0, err
}

// SetNX sets a key only if it does not exist. Returns true if set.
func (c *Client) SetNX(ctx context.Context, key string, value any, ttl time.Duration) (bool, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return false, fmt.Errorf("marshal value: %w", err)
	}
	return c.rdb.SetNX(ctx, key, b, ttl).Result()
}

// TTL returns the remaining TTL of a key.
func (c *Client) TTL(ctx context.Context, key string) (time.Duration, error) {
	return c.rdb.TTL(ctx, key).Result()
}

// IsNotFound returns true if the error is a Redis key-not-found error.
func IsNotFound(err error) bool {
	return err == redis.Nil
}
