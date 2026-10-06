// Integration tests for the counter. They need a PostgreSQL database, set in NATRIUM_PIN_TEST_DATABASE_URL. They
// are skipped without it and with -short:
//
//	docker run -d --rm -p 15433:5432 -e POSTGRES_PASSWORD=nrs -e POSTGRES_USER=nrs -e POSTGRES_DB=nrs postgres:17-alpine
//	NATRIUM_PIN_TEST_DATABASE_URL=postgres://nrs:nrs@localhost:15433/nrs go test ./internal/attempts/...
package attempts_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/SchwarzDigits/natrium-pin-service/internal/attempts"
)

const (
	envTestDatabaseURL = "NATRIUM_PIN_TEST_DATABASE_URL"
	domain             = "wire.example"
	hour               = time.Hour
	day                = 24 * time.Hour
)

// refundKey stands for the receipt key of a key file. The counter stores it and does not check it.
var refundKey = []byte("receipt key of the key file")

// defaults are the limits of the server: 5 per hour and 12 per day.
var defaults = []attempts.Limit{{Attempts: 5, Window: hour}, {Attempts: 12, Window: day}}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test: skipped with -short")
	}
	uri := os.Getenv(envTestDatabaseURL)
	if uri == "" {
		t.Skipf("integration test: %s is not set", envTestDatabaseURL)
	}
	cfg, err := attempts.PoolConfig(uri)
	require.NoError(t, err)
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, attempts.Migrate(t.Context(), pool))
	return pool
}

// newUser returns a random user ID, so that tests sharing a database do not see each other's counts.
func newUser() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// endWindow lets the user's window of the given length end now.
func endWindow(t *testing.T, pool *pgxpool.Pool, user string, window time.Duration) {
	t.Helper()
	tag, err := pool.Exec(t.Context(),
		`UPDATE attempts SET window_end = now() WHERE user_domain = $1 AND user_id = $2 AND window_us = $3`,
		domain, user, window.Microseconds())
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
}

// counted returns the counts of the user's windows, by window length.
func counted(t *testing.T, pool *pgxpool.Pool, user string) map[time.Duration]int {
	t.Helper()
	rows, err := pool.Query(t.Context(),
		`SELECT window_us, count FROM attempts WHERE user_domain = $1 AND user_id = $2`, domain, user)
	require.NoError(t, err)
	defer rows.Close()
	out := map[time.Duration]int{}
	for rows.Next() {
		var us int64
		var n int
		require.NoError(t, rows.Scan(&us, &n))
		out[time.Duration(us)*time.Microsecond] = n
	}
	require.NoError(t, rows.Err())
	return out
}

func take(t *testing.T, counter *attempts.Counter, user string) attempts.Decision {
	t.Helper()
	d, err := counter.Take(t.Context(), domain, user, refundKey)
	require.NoError(t, err)
	return d
}

func TestParseLimits(t *testing.T) {
	limits, err := attempts.ParseLimits(" 5/1h, 12/24h ,")
	require.NoError(t, err)
	require.Equal(t, defaults, limits)
	require.Equal(t, "5/1h0m0s", limits[0].String())

	for _, bad := range []string{"", ",", "5", "5/", "/1h", "five/1h", "5/an hour", "0/1h", "-1/1h", "5/500ms",
		"5/1h,6/60m", "5/1h/2"} {
		_, err := attempts.ParseLimits(bad)
		require.Error(t, err, "%q", bad)
	}
}

func TestMigrateTwice(t *testing.T) {
	pool := testPool(t)
	require.NoError(t, attempts.Migrate(t.Context(), pool))
}

// Within an hour, the hourly limit applies: the 6th attempt is refused until the hour ends.
func TestTheHourlyLimit(t *testing.T) {
	counter := attempts.New(testPool(t), defaults)
	user := newUser()
	for i := 1; i <= 5; i++ {
		d := take(t, counter, user)
		require.True(t, d.Allowed, "attempt %d", i)
		require.Equal(t, 5-i, d.Remaining, "attempts left after attempt %d", i)
	}
	d := take(t, counter, user)
	require.False(t, d.Allowed)
	require.Zero(t, d.Remaining)
	require.Greater(t, d.RetryAfter, 59*time.Minute)
	require.LessOrEqual(t, d.RetryAfter, hour)
}

// Over the hours of a day, the daily limit applies: after 12 attempts the user waits until the day ends, even when an
// hour has ended.
func TestTheDailyLimit(t *testing.T) {
	pool := testPool(t)
	counter := attempts.New(pool, defaults)
	user := newUser()
	allowed := 0
	for range 3 {
		for take(t, counter, user).Allowed {
			allowed++
		}
		endWindow(t, pool, user, hour)
	}
	require.Equal(t, 12, allowed, "5 + 5 + 2")

	d := take(t, counter, user)
	require.False(t, d.Allowed)
	require.Greater(t, d.RetryAfter, day-time.Minute, "the wait is until the day ends, not the hour")
	require.LessOrEqual(t, d.RetryAfter, day)
}

// The attempts left follow the tightest limit.
func TestRemainingFollowsTheTightestLimit(t *testing.T) {
	pool := testPool(t)
	counter := attempts.New(pool, defaults)
	user := newUser()
	for range 5 {
		take(t, counter, user)
	}
	endWindow(t, pool, user, hour)
	for range 5 {
		take(t, counter, user)
	}
	endWindow(t, pool, user, hour)
	d := take(t, counter, user)
	require.True(t, d.Allowed)
	require.Equal(t, 1, d.Remaining, "the 11th attempt of the day leaves 1, though the hour would leave 4")
	d = take(t, counter, user)
	require.True(t, d.Allowed)
	require.Zero(t, d.Remaining)
}

// An attempt that is refused is not counted, in no window.
func TestRefusedAttemptsAreNotCounted(t *testing.T) {
	pool := testPool(t)
	counter := attempts.New(pool, defaults)
	user := newUser()
	for range 5 {
		require.True(t, take(t, counter, user).Allowed)
	}
	for range 20 {
		require.False(t, take(t, counter, user).Allowed)
	}
	require.Equal(t, map[time.Duration]int{hour: 5, day: 5}, counted(t, pool, user))

	endWindow(t, pool, user, hour)
	require.True(t, take(t, counter, user).Allowed, "the refused attempts did not use up the day")
	require.Equal(t, map[time.Duration]int{hour: 1, day: 6}, counted(t, pool, user))
}

func TestUsersAreCountedSeparately(t *testing.T) {
	counter := attempts.New(testPool(t), []attempts.Limit{{Attempts: 1, Window: hour}})
	user := newUser()
	require.True(t, take(t, counter, user).Allowed)
	require.False(t, take(t, counter, user).Allowed)

	require.True(t, take(t, counter, newUser()).Allowed)
	d, err := counter.Take(t.Context(), "other.example", user, refundKey)
	require.NoError(t, err)
	require.True(t, d.Allowed)
}

func TestEndedWindowStartsOver(t *testing.T) {
	pool := testPool(t)
	counter := attempts.New(pool, []attempts.Limit{{Attempts: 2, Window: hour}})
	user := newUser()
	for range 2 {
		require.True(t, take(t, counter, user).Allowed)
	}
	endWindow(t, pool, user, hour)

	require.True(t, take(t, counter, user).Allowed)
	require.Equal(t, map[time.Duration]int{hour: 1}, counted(t, pool, user))
}

func TestDeleteExpired(t *testing.T) {
	pool := testPool(t)
	counter := attempts.New(pool, defaults)
	ended, current := newUser(), newUser()
	for _, user := range []string{ended, current} {
		require.True(t, take(t, counter, user).Allowed)
	}
	endWindow(t, pool, ended, hour)
	endWindow(t, pool, ended, day)
	endWindow(t, pool, current, hour)

	n, err := counter.DeleteExpired(t.Context())
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, int64(3))
	require.Empty(t, counted(t, pool, ended))
	require.Equal(t, map[time.Duration]int{day: 1}, counted(t, pool, current), "only ended windows are deleted")
}

func TestCleanUpStopsWithTheContext(t *testing.T) {
	counter := attempts.New(testPool(t), defaults)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		counter.CleanUp(ctx, time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("CleanUp did not return after cancel")
	}
}

// Two pools stand for two instances of the service at one database. Of many concurrent attempts of one user, exactly
// the hourly limit is allowed and counted.
func TestConcurrentAttemptsFromTwoInstances(t *testing.T) {
	const perInstance = 25
	pool := testPool(t)
	instances := []*attempts.Counter{attempts.New(pool, defaults), attempts.New(testPool(t), defaults)}
	user := newUser()

	var mu sync.Mutex
	allowed, errs := 0, []error{}
	var wg sync.WaitGroup
	for _, counter := range instances {
		for range perInstance {
			wg.Go(func() {
				d, err := counter.Take(t.Context(), domain, user, refundKey)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					errs = append(errs, err)
				} else if d.Allowed {
					allowed++
				}
			})
		}
	}
	wg.Wait()

	require.Empty(t, errs)
	require.Equal(t, 5, allowed)
	require.Equal(t, map[time.Duration]int{hour: 5, day: 5}, counted(t, pool, user))
}

func refund(t *testing.T, counter *attempts.Counter, user string, id []byte, valid bool) (int, error) {
	t.Helper()
	return counter.Refund(t.Context(), domain, user, id, func(key []byte) bool {
		require.Equal(t, refundKey, key, "the receipt key of the attempt")
		return valid
	})
}

func TestRefundGivesTheAttemptBack(t *testing.T) {
	pool := testPool(t)
	counter := attempts.New(pool, defaults)
	user := newUser()
	take(t, counter, user)
	take(t, counter, user)
	d := take(t, counter, user)
	require.Len(t, d.AttemptID, attempts.AttemptIDSize)
	require.Equal(t, 2, d.Remaining)
	require.Equal(t, map[time.Duration]int{hour: 3, day: 3}, counted(t, pool, user))

	remaining, err := refund(t, counter, user, d.AttemptID, true)
	require.NoError(t, err)
	require.Equal(t, 3, remaining, "the earlier attempts stay counted")
	require.Equal(t, map[time.Duration]int{hour: 2, day: 2}, counted(t, pool, user))

	_, err = refund(t, counter, user, d.AttemptID, true)
	require.ErrorIs(t, err, attempts.ErrUnknownAttempt, "an attempt is given back once")
	require.Equal(t, map[time.Duration]int{hour: 2, day: 2}, counted(t, pool, user))
}

func TestRefundNeedsAValidReceipt(t *testing.T) {
	pool := testPool(t)
	counter := attempts.New(pool, defaults)
	user := newUser()
	d := take(t, counter, user)

	_, err := refund(t, counter, user, d.AttemptID, false)
	require.ErrorIs(t, err, attempts.ErrInvalidReceipt)
	require.Equal(t, map[time.Duration]int{hour: 1, day: 1}, counted(t, pool, user), "still counted")

	_, err = refund(t, counter, user, d.AttemptID, true)
	require.NoError(t, err, "the attempt stays open after a rejected receipt")
	require.Equal(t, map[time.Duration]int{hour: 0, day: 0}, counted(t, pool, user))
}

func TestRefundIsOnlyForTheUser(t *testing.T) {
	pool := testPool(t)
	counter := attempts.New(pool, defaults)
	user := newUser()
	d := take(t, counter, user)

	_, err := refund(t, counter, newUser(), d.AttemptID, true)
	require.ErrorIs(t, err, attempts.ErrUnknownAttempt)
	_, err = refund(t, counter, user, make([]byte, attempts.AttemptIDSize), true)
	require.ErrorIs(t, err, attempts.ErrUnknownAttempt)
	require.Equal(t, map[time.Duration]int{hour: 1, day: 1}, counted(t, pool, user))
}

// An attempt counted in a window that has ended since is taken off the windows that still run only.
func TestRefundSkipsEndedWindows(t *testing.T) {
	pool := testPool(t)
	counter := attempts.New(pool, defaults)
	user := newUser()
	d := take(t, counter, user)
	endWindow(t, pool, user, hour)
	take(t, counter, user)
	require.Equal(t, map[time.Duration]int{hour: 1, day: 2}, counted(t, pool, user))

	remaining, err := refund(t, counter, user, d.AttemptID, true)
	require.NoError(t, err)
	require.Equal(t, map[time.Duration]int{hour: 1, day: 1}, counted(t, pool, user),
		"the new hour window does not hold the attempt")
	require.Equal(t, 4, remaining)
}

func TestRefundEndsWithTheRefundWindow(t *testing.T) {
	pool := testPool(t)
	counter := attempts.New(pool, defaults)
	user := newUser()
	d := take(t, counter, user)
	_, err := pool.Exec(t.Context(),
		`UPDATE open_attempts SET created_at = now() - $2 * interval '1 microsecond' WHERE attempt_id = $1`,
		d.AttemptID, attempts.RefundWindow.Microseconds())
	require.NoError(t, err)

	_, err = refund(t, counter, user, d.AttemptID, true)
	require.ErrorIs(t, err, attempts.ErrUnknownAttempt)

	_, err = counter.DeleteExpired(t.Context())
	require.NoError(t, err)
	var open int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM open_attempts WHERE attempt_id = $1`,
		d.AttemptID).Scan(&open))
	require.Zero(t, open, "the cleanup deletes it")
}

func TestRefusedAttemptsHaveNoID(t *testing.T) {
	pool := testPool(t)
	counter := attempts.New(pool, []attempts.Limit{{Attempts: 1, Window: hour}})
	user := newUser()
	require.NotNil(t, take(t, counter, user).AttemptID)
	d := take(t, counter, user)
	require.False(t, d.Allowed)
	require.Nil(t, d.AttemptID)
}
