package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
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
