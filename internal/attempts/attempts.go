// Package attempts counts the evaluations per Wire user in PostgreSQL, against one or more limits, each with a fixed
// window of its own, e.g. 5 per hour and 12 per day. A window starts with the first attempt after the previous one
// ended. All instances of the service share the counts through the database. A count is never reset early: after a
// limit, the user waits until its window ends.
package attempts

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

// migrationFiles contains the goose migrations. Migrations are append-only: a released migration is never changed.
//
//go:embed migrations/*.sql
var migrationFiles embed.FS

// lockWindows creates the user's rows for the given window lengths, or starts their ended windows over with a count
// of 0, and returns them. The rows stay locked until the transaction ends, so concurrent attempts of one user, also
// from other instances, wait for each other. The rows are locked in the order of the window lengths, so that two
// attempts cannot wait for each other's rows. It returns the database's clock, so that all instances compute
// Retry-After from the same clock.
//
// In DO UPDATE, a.window_end and a.count are the values before the update.
const lockWindows = `
INSERT INTO attempts AS a (user_domain, user_id, window_us, window_end, count)
SELECT $1, $2, w, now() + w * interval '1 microsecond', 0
FROM unnest($3::bigint[]) AS w
ORDER BY w
ON CONFLICT (user_domain, user_id, window_us) DO UPDATE SET
    window_end = CASE WHEN a.window_end <= now() THEN excluded.window_end ELSE a.window_end END,
    count      = CASE WHEN a.window_end <= now() THEN 0 ELSE a.count END
RETURNING window_us, window_end, count, now()`

// countAttempt records an allowed attempt in all of the user's windows.
const countAttempt = `
UPDATE attempts SET count = count + 1
WHERE user_domain = $1 AND user_id = $2 AND window_us = ANY($3::bigint[])`

// deleteExpired removes the rows whose window has ended.
const deleteExpired = `DELETE FROM attempts WHERE window_end <= now()`

// PoolConfig parses the connection string for the counter's pool. Its connections commit with synchronous_commit on,
// whatever the database's default is, so an acknowledged attempt is not lost in a crash of PostgreSQL.
func PoolConfig(databaseURL string) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	cfg.ConnConfig.RuntimeParams["synchronous_commit"] = "on"
	return cfg, nil
}

// Migrate applies all pending migrations. It holds a PostgreSQL session lock, so if several instances start at the
// same time, only one of them migrates.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return fmt.Errorf("create session locker: %w", err)
	}
	files, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return err
	}
	// goose uses database/sql. OpenDBFromPool wraps the existing pool.
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer func() { _ = sqlDB.Close() }()

	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, files, goose.WithSessionLocker(locker))
	if err != nil {
		return fmt.Errorf("create goose provider: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

// Limit allows Attempts attempts per user within Window.
type Limit struct {
	Attempts int
	Window   time.Duration
}

// String returns the limit in the form ParseLimits reads, e.g. 5/1h0m0s.
func (l Limit) String() string {
	return strconv.Itoa(l.Attempts) + "/" + l.Window.String()
}

// ParseLimits reads comma-separated limits of the form <attempts>/<window>, e.g. "5/1h,12/24h". The window is a Go
// duration. Spaces around a limit are ignored. It checks the limits with CheckLimits.
func ParseLimits(s string) ([]Limit, error) {
	var limits []Limit
	for i, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		attempts, window, ok := strings.Cut(item, "/")
		if !ok {
			return nil, fmt.Errorf("limit %d: %q must be <attempts>/<window>, e.g. 5/1h", i+1, item)
		}
		n, err := strconv.Atoi(attempts)
		if err != nil {
			return nil, fmt.Errorf("limit %d: %q is not a number of attempts", i+1, attempts)
		}
		d, err := time.ParseDuration(window)
		if err != nil {
			return nil, fmt.Errorf("limit %d: %q is not a duration, e.g. 1h or 24h", i+1, window)
		}
		limits = append(limits, Limit{Attempts: n, Window: d})
	}
	return limits, CheckLimits(limits)
}

// CheckLimits reports whether limits can be used: at least one, each with at least one attempt in a window of at least
// one second, and no window length twice.
func CheckLimits(limits []Limit) error {
	if len(limits) == 0 {
		return errors.New("at least one limit is required")
	}
	seen := map[time.Duration]bool{}
	for _, l := range limits {
		switch {
		case l.Attempts < 1:
			return fmt.Errorf("%s: at least one attempt is required", l)
		case l.Window < time.Second:
			return fmt.Errorf("%s: the window must be at least one second", l)
		case seen[l.Window]:
			return fmt.Errorf("%s: another limit has the same window", l)
		}
		seen[l.Window] = true
	}
	return nil
}

// Decision is the outcome of one attempt.
type Decision struct {
	// Allowed reports whether the attempt is within all limits. Only then is it counted, and only then may it be
	// evaluated.
	Allowed bool
	// RetryAfter is, for an attempt that is not allowed, the time until the last window whose limit is reached ends.
	RetryAfter time.Duration
	// Remaining is, for an allowed attempt, how many more attempts all limits allow after this one before a window
	// ends. It is 0 for an attempt that is not allowed.
	Remaining int
}

// Counter counts attempts in a pool whose schema is up to date. See Migrate.
type Counter struct {
	pool    *pgxpool.Pool
	limits  map[int64]Limit
	windows []int64
}

// New returns a counter with limits, which CheckLimits must accept. An attempt is allowed if it is within every limit.
func New(pool *pgxpool.Pool, limits []Limit) *Counter {
	c := &Counter{pool: pool, limits: map[int64]Limit{}}
	for _, l := range limits {
		c.limits[l.Window.Microseconds()] = l
		c.windows = append(c.windows, l.Window.Microseconds())
	}
	slices.Sort(c.windows)
	return c
}

// Take decides whether an attempt of the user with the given domain and ID (a UUID) is within all limits, and if so,
// counts it in all windows. An attempt that is not allowed is not counted. Deciding and counting are one transaction,
// so concurrent attempts, also from other instances, never exceed a limit together.
func (c *Counter) Take(ctx context.Context, domain, userID string) (Decision, error) {
	var decision Decision
	err := pgx.BeginFunc(ctx, c.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, lockWindows, domain, userID, c.windows)
		if err != nil {
			return err
		}
		decision.Allowed = true
		decision.Remaining = math.MaxInt
		var windowUs int64
		var windowEnd, now time.Time
		var n int
		_, err = pgx.ForEachRow(rows, []any{&windowUs, &windowEnd, &n, &now}, func() error {
			limit := c.limits[windowUs].Attempts
			if n >= limit {
				decision.Allowed = false
				decision.RetryAfter = max(decision.RetryAfter, windowEnd.Sub(now))
			}
			decision.Remaining = min(decision.Remaining, limit-n-1)
			return nil
		})
		if err != nil || !decision.Allowed {
			decision.Remaining = 0
			return err
		}
		_, err = tx.Exec(ctx, countAttempt, domain, userID, c.windows)
		return err
	})
	if err != nil {
		return Decision{}, fmt.Errorf("attempts: count: %w", err)
	}
	return decision, nil
}

// DeleteExpired removes the rows whose window has ended and returns how many.
func (c *Counter) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := c.pool.Exec(ctx, deleteExpired)
	if err != nil {
		return 0, fmt.Errorf("attempts: delete expired: %w", err)
	}
	return tag.RowsAffected(), nil
}

// CleanUp calls DeleteExpired now and then every interval, until ctx is canceled. Errors are logged.
func (c *Counter) CleanUp(ctx context.Context, interval time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if n, err := c.DeleteExpired(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Error("cleanup of attempts failed", "error", err)
		} else if n > 0 {
			log.Info("deleted ended attempt windows", "rows", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
