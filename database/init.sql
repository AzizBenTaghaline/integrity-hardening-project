
\c appdb;



CREATE TABLE IF NOT EXISTS users (

    id          SERIAL PRIMARY KEY,

    username    VARCHAR(50) UNIQUE NOT NULL,

    email       VARCHAR(100) UNIQUE NOT NULL,

    password    VARCHAR(255) NOT NULL,

    role        VARCHAR(20) NOT NULL DEFAULT 'user',

    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    last_login  TIMESTAMP,

    active      BOOLEAN DEFAULT TRUE

);



CREATE TABLE IF NOT EXISTS audit_logs (

    id          SERIAL PRIMARY KEY,

    user_id     INTEGER REFERENCES users(id),

    action      VARCHAR(100) NOT NULL,

    target      VARCHAR(255),

    ip_address  INET,

    timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    details     TEXT,

    checksum    VARCHAR(64)

);



CREATE TABLE IF NOT EXISTS integrity_checks (

    id          SERIAL PRIMARY KEY,

    table_name  VARCHAR(100) NOT NULL,

    row_id      INTEGER NOT NULL,

    field_name  VARCHAR(100) NOT NULL,
    field_hash  VARCHAR(64) NOT NULL,
    verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (username, email, password, role) VALUES
    ('admin',   'admin@lab.local',   'admin123',  'admin'),
    ('alice',   'alice@lab.local',   'password',  'user'),
    ('bob',     'bob@lab.local',     '123456',    'user'),
    ('charlie', 'charlie@lab.local', 'charlie',   'user');

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'appuser') THEN
        CREATE ROLE appuser LOGIN PASSWORD 'AppUser_SecureP@ss_2024!';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE appdb TO appuser;
GRANT USAGE ON SCHEMA public TO appuser;
GRANT SELECT, INSERT ON TABLE users TO appuser;
GRANT SELECT, INSERT ON TABLE audit_logs TO appuser;
GRANT SELECT, INSERT ON TABLE integrity_checks TO appuser;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO appuser;

CREATE OR REPLACE FUNCTION protect_role_field()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.role <> OLD.role AND current_user <> 'postgres' THEN
        RAISE EXCEPTION 'Modification du role non autorisee via API';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_protect_role
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION protect_role_field();

CREATE INDEX IF NOT EXISTS idx_users_username  ON users(username);
CREATE INDEX IF NOT EXISTS idx_audit_user_id   ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);

CREATE OR REPLACE VIEW v_users_safe AS
    SELECT id, username, email, role, created_at, last_login, active
    FROM users;

GRANT SELECT ON v_users_safe TO appuser;
