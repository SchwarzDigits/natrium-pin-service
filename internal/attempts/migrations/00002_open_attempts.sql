-- +goose Up
-- One row per counted attempt that a receipt can still give back, for the refund window after the evaluation: the
-- receipt key the client sent, and the windows the attempt was counted in, by their length and their end. A receipt
-- deletes the row; the cleanup deletes rows older than the refund window.
CREATE TABLE open_attempts (
    attempt_id  bytea         PRIMARY KEY,
    user_domain text          NOT NULL,
    user_id     uuid          NOT NULL,
    refund_key  bytea         NOT NULL,
    created_at  timestamptz   NOT NULL,
    window_us   bigint[]      NOT NULL,
    window_end  timestamptz[] NOT NULL
);

-- For the cleanup of attempts that can no longer be given back.
CREATE INDEX open_attempts_created_at ON open_attempts (created_at);

-- +goose Down
DROP TABLE open_attempts;
