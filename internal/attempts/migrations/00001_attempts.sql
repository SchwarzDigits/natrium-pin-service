-- +goose Up
-- One row per Wire user and limit, identified by the length of the limit's window: when the user's current window
-- ends and how many attempts were allowed in it. A row whose window has ended is started over by the next attempt
-- or deleted by the cleanup.
CREATE TABLE attempts (
    user_domain text        NOT NULL,
    user_id     uuid        NOT NULL,
    -- Length of the window in microseconds.
    window_us   bigint      NOT NULL,
    window_end  timestamptz NOT NULL,
    count       integer     NOT NULL,
    PRIMARY KEY (user_domain, user_id, window_us)
);

-- For the cleanup of ended windows.
CREATE INDEX attempts_window_end ON attempts (window_end);

-- +goose Down
DROP TABLE attempts;
