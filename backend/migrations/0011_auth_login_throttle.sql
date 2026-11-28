CREATE TABLE auth_login_attempts (
    username_hash TEXT PRIMARY KEY NOT NULL CHECK (length(username_hash) = 64),
    window_started_at INTEGER NOT NULL,
    failure_count INTEGER NOT NULL CHECK (failure_count >= 0),
    blocked_until INTEGER
);

CREATE INDEX auth_login_attempts_blocked_until
    ON auth_login_attempts(blocked_until);
