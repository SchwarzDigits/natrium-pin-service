// Package attempts counts the evaluations per Wire user in PostgreSQL, against one or more limits, each with a fixed
// window of its own, e.g. 5 per hour and 12 per day. A window starts with the first attempt after the previous one
// ended. All instances of the service share the counts through the database. A count is never reset: after a limit,
// the user waits until its window ends.
//
// A counted attempt stays open for RefundWindow. Within it, a receipt can give it back: the attempt is taken off
// every window it was counted in that has not ended yet. Whether a receipt is valid decides the caller.
package attempts

import (
	"context"
	"crypto/rand"
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

// openAttempt records a counted attempt that a receipt can give back, with the windows it was counted in.
const openAttempt = `
INSERT INTO open_attempts (attempt_id, user_domain, user_id, refund_key, created_at, window_us, window_end)
VALUES ($1, $2, $3, $4, now(), $5::bigint[], $6::timestamptz[])`

// lockOpenAttempt locks an open attempt of the user that is younger than the refund window, given in microseconds.
const lockOpenAttempt = `
SELECT refund_key, window_us, window_end FROM open_attempts
WHERE attempt_id = $1 AND user_domain = $2 AND user_id = $3 AND created_at > now() - $4 * interval '1 microsecond'
FOR UPDATE`

// closeAttempt deletes an open attempt after its receipt.
const closeAttempt = `DELETE FROM open_attempts WHERE attempt_id = $1`

// giveBack takes an attempt off the windows it was counted in that are still the same and have not ended.
const giveBack = `
UPDATE attempts AS a SET count = greatest(a.count - 1, 0)
FROM unnest($3::bigint[], $4::timestamptz[]) AS w (window_us, window_end)
WHERE a.user_domain = $1 AND a.user_id = $2 AND a.window_us = w.window_us AND a.window_end = w.window_end
  AND a.window_end > now()`

// currentCounts returns the user's windows with the database's clock.
const currentCounts = `
SELECT window_us, window_end, count, now() FROM attempts WHERE user_domain = $1 AND user_id = $2`

// deleteExpired removes the rows whose window has ended.
const deleteExpired = `DELETE FROM attempts WHERE window_end <= now()`

// deleteClosed removes the open attempts older than the refund window, given in microseconds.
const deleteClosed = `DELETE FROM open_attempts WHERE created_at <= now() - $1 * interval '1 microsecond'`

// RefundWindow is how long a counted attempt can be given back.
const RefundWindow = 15 * time.Minute

// AttemptIDSize is the size of an attempt ID.
const AttemptIDSize = 16

var (
	// ErrUnknownAttempt reports that the user has no open attempt with the ID: it does not exist, was given back
	// already, or is older than RefundWindow.
	ErrUnknownAttempt = errors.New("attempts: no open attempt with this ID")
	// ErrInvalidReceipt reports that the caller rejected the receipt for the attempt's receipt key.
	ErrInvalidReceipt = errors.New("attempts: the receipt is not valid for the attempt")
)

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
	// AttemptID names an allowed attempt for its receipt, AttemptIDSize random bytes. Nil for an attempt that is
	// not allowed or was taken without receipt key.
	AttemptID []byte
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
// counts it in all windows and keeps it open for a receipt by refundKey. Without refundKey, from a client that sends
// none yet, the attempt is counted but cannot be given back. An attempt that is not allowed is not counted. Deciding and counting are one transaction, so concurrent attempts, also from other instances, never exceed
// a limit together.
func (c *Counter) Take(ctx context.Context, domain, userID string, refundKey []byte) (Decision, error) {
	var decision Decision
	err := pgx.BeginFunc(ctx, c.pool, func(tx pgx.Tx) error {
		decision = Decision{}
		rows, err := tx.Query(ctx, lockWindows, domain, userID, c.windows)
		if err != nil {
			return err
		}
		decision.Allowed = true
		decision.Remaining = math.MaxInt
		var windowUs int64
		var windowEnd, now time.Time
		var n int
		ends := map[int64]time.Time{}
		_, err = pgx.ForEachRow(rows, []any{&windowUs, &windowEnd, &n, &now}, func() error {
			limit := c.limits[windowUs].Attempts
			if n >= limit {
				decision.Allowed = false
				decision.RetryAfter = max(decision.RetryAfter, windowEnd.Sub(now))
			}
			decision.Remaining = min(decision.Remaining, limit-n-1)
			ends[windowUs] = windowEnd
			return nil
		})
		if err != nil || !decision.Allowed {
			decision.Remaining = 0
			return err
		}
		if _, err := tx.Exec(ctx, countAttempt, domain, userID, c.windows); err != nil {
			return err
		}
		if refundKey == nil {
			return nil
		}
		windowEnds := make([]time.Time, len(c.windows))
		for i, w := range c.windows {
			windowEnds[i] = ends[w]
		}
		decision.AttemptID = make([]byte, AttemptIDSize)
		_, _ = rand.Read(decision.AttemptID) // crypto/rand.Read never fails
		_, err = tx.Exec(ctx, openAttempt, decision.AttemptID, domain, userID, refundKey, c.windows, windowEnds)
		return err
	})
	if err != nil {
		return Decision{}, fmt.Errorf("attempts: count: %w", err)
	}
	return decision, nil
}

// Refund gives an open attempt of the user back if valid accepts the receipt for the attempt's receipt key. The
// attempt is taken off every window it was counted in that has not ended since, and closed, so it is given back at
// most once. It returns how many attempts all limits allow now, ErrUnknownAttempt if the user has no open attempt
// with the ID, and ErrInvalidReceipt if valid returns false; the attempt then stays open.
func (c *Counter) Refund(ctx context.Context, domain, userID string, attemptID []byte,
	valid func(refundKey []byte) bool) (int, error) {
	remaining := 0
	err := pgx.BeginFunc(ctx, c.pool, func(tx pgx.Tx) error {
		var refundKey []byte
		var windows []int64
		var ends []time.Time
		err := tx.QueryRow(ctx, lockOpenAttempt, attemptID, domain, userID, RefundWindow.Microseconds()).
			Scan(&refundKey, &windows, &ends)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUnknownAttempt
		}
		if err != nil {
			return err
		}
		if !valid(refundKey) {
			return ErrInvalidReceipt
		}
		if _, err := tx.Exec(ctx, closeAttempt, attemptID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, giveBack, domain, userID, windows, ends); err != nil {
			return err
		}
		remaining, err = c.remaining(ctx, tx, domain, userID)
		return err
	})
	switch {
	case errors.Is(err, ErrUnknownAttempt), errors.Is(err, ErrInvalidReceipt):
		return 0, err
	case err != nil:
		return 0, fmt.Errorf("attempts: refund: %w", err)
	}
	return remaining, nil
}

// remaining returns how many attempts all limits allow the user now. A window that has ended allows its whole limit.
func (c *Counter) remaining(ctx context.Context, tx pgx.Tx, domain, userID string) (int, error) {
	counts := map[int64]int{}
	rows, err := tx.Query(ctx, currentCounts, domain, userID)
	if err != nil {
		return 0, err
	}
	var windowUs int64
	var windowEnd, now time.Time
	var n int
	_, err = pgx.ForEachRow(rows, []any{&windowUs, &windowEnd, &n, &now}, func() error {
		if windowEnd.After(now) {
			counts[windowUs] = n
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	remaining := math.MaxInt
	for _, w := range c.windows {
		remaining = min(remaining, c.limits[w].Attempts-counts[w])
	}
	return remaining, nil
}

// DeleteExpired removes the rows whose window has ended and the open attempts older than RefundWindow, and returns
// how many rows it removed.
func (c *Counter) DeleteExpired(ctx context.Context) (int64, error) {
	windows, err := c.pool.Exec(ctx, deleteExpired)
	if err != nil {
		return 0, fmt.Errorf("attempts: delete expired: %w", err)
	}
	open, err := c.pool.Exec(ctx, deleteClosed, RefundWindow.Microseconds())
	if err != nil {
		return 0, fmt.Errorf("attempts: delete closed attempts: %w", err)
	}
	return windows.RowsAffected() + open.RowsAffected(), nil
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
