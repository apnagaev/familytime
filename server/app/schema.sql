-- Схема FamilyTime. Применяется при старте под pg_advisory_xact_lock.
CREATE TABLE IF NOT EXISTS ft_settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text
);

CREATE TABLE IF NOT EXISTS ft_children (
    username     text PRIMARY KEY,            -- sAMAccountName в нижнем регистре
    display_name text NOT NULL,
    enabled      boolean NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ft_rules (
    username      text NOT NULL REFERENCES ft_children ON DELETE CASCADE ON UPDATE CASCADE,
    weekday       smallint NOT NULL CHECK (weekday BETWEEN 0 AND 6),
    limit_minutes integer CHECK (limit_minutes IS NULL OR limit_minutes >= 0),
    window_from   time,
    window_to     time,
    PRIMARY KEY (username, weekday)
);

CREATE TABLE IF NOT EXISTS ft_bonus (
    id         bigserial PRIMARY KEY,
    username   text NOT NULL REFERENCES ft_children ON DELETE CASCADE ON UPDATE CASCADE,
    day        date NOT NULL,
    minutes    integer NOT NULL,
    reason     text NOT NULL DEFAULT '',
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ft_bonus_user_day ON ft_bonus (username, day);

CREATE TABLE IF NOT EXISTS ft_usage (
    username        text NOT NULL REFERENCES ft_children ON DELETE CASCADE ON UPDATE CASCADE,
    day             date NOT NULL,
    counted_seconds integer NOT NULL DEFAULT 0,
    free_seconds    integer NOT NULL DEFAULT 0,
    PRIMARY KEY (username, day)
);

CREATE TABLE IF NOT EXISTS ft_activity (
    username        text NOT NULL REFERENCES ft_children ON DELETE CASCADE ON UPDATE CASCADE,
    day             date NOT NULL,
    kind            text NOT NULL CHECK (kind IN ('app', 'site')),
    name            text NOT NULL,
    counted_seconds integer NOT NULL DEFAULT 0,
    free_seconds    integer NOT NULL DEFAULT 0,
    PRIMARY KEY (username, day, kind, name)
);

CREATE TABLE IF NOT EXISTS ft_devices (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname         text NOT NULL UNIQUE,     -- имя.домен в нижнем регистре, он же uniqueId в Traccar
    token_hash       text NOT NULL,
    mode             text NOT NULL DEFAULT 'control' CHECK (mode IN ('control', 'track')),
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_seen        timestamptz,
    last_ip          text,
    last_user        text,
    last_session     text,
    agent_version    text,
    os_version       text,
    last_seq         bigint NOT NULL DEFAULT 0,
    lost             boolean NOT NULL DEFAULT false,
    lost_message     text NOT NULL DEFAULT '',
    lost_lock        boolean NOT NULL DEFAULT false,
    last_lat         double precision,
    last_lon         double precision,
    last_accuracy    double precision,
    last_fix_at      timestamptz,
    last_fix_source  text,
    battery          integer,
    on_ac            boolean,
    traccar_ok       boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS ft_presence (
    username  text NOT NULL REFERENCES ft_children ON DELETE CASCADE ON UPDATE CASCADE,
    device_id uuid NOT NULL REFERENCES ft_devices ON DELETE CASCADE,
    last_seen timestamptz NOT NULL,
    session   text NOT NULL,
    exe       text NOT NULL DEFAULT '',
    domain    text NOT NULL DEFAULT '',
    PRIMARY KEY (username, device_id)
);

CREATE TABLE IF NOT EXISTS ft_requests (
    id          bigserial PRIMARY KEY,
    username    text NOT NULL REFERENCES ft_children ON DELETE CASCADE ON UPDATE CASCADE,
    day         date NOT NULL,
    minutes     integer NOT NULL CHECK (minutes > 0),
    reason      text NOT NULL DEFAULT '',
    status      text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    decided_by  text,
    decided_at  timestamptz,
    tg_messages jsonb NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS ft_requests_status ON ft_requests (status, created_at);

CREATE TABLE IF NOT EXISTS ft_kv (
    key   text PRIMARY KEY,
    value text NOT NULL
);

-- подписки на списки (1.1)
CREATE TABLE IF NOT EXISTS ft_lists (
    id             bigserial PRIMARY KEY,
    category       text NOT NULL CHECK (category IN ('edu_domains', 'blocked_domains', 'edu_apps', 'blocked_apps')),
    name           text NOT NULL DEFAULT '',
    url            text NOT NULL,
    enabled        boolean NOT NULL DEFAULT true,
    interval_hours integer NOT NULL DEFAULT 24 CHECK (interval_hours BETWEEN 1 AND 720),
    entries        jsonb NOT NULL DEFAULT '[]',
    count          integer NOT NULL DEFAULT 0,
    last_fetch     timestamptz,
    last_ok        timestamptz,
    error          text NOT NULL DEFAULT '',
    etag           text NOT NULL DEFAULT '',
    last_modified  text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (category, url)
);

-- понятные названия программ, которые присылают агенты (1.1)
CREATE TABLE IF NOT EXISTS ft_app_names (
    exe        text PRIMARY KEY,
    name       text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE ft_presence ADD COLUMN IF NOT EXISTS app text NOT NULL DEFAULT '';

-- многосемейный режим (1.2)
CREATE TABLE IF NOT EXISTS ft_families (
    id             bigserial PRIMARY KEY,
    name           text NOT NULL,
    messages       jsonb NOT NULL DEFAULT '{}',
    telegram_chats jsonb NOT NULL DEFAULT '[]',
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ft_family_parents (
    family_id bigint NOT NULL REFERENCES ft_families ON DELETE CASCADE,
    username  text NOT NULL,
    PRIMARY KEY (family_id, username)
);
ALTER TABLE ft_children ADD COLUMN IF NOT EXISTS family_id bigint REFERENCES ft_families ON DELETE SET NULL;
ALTER TABLE ft_children ADD COLUMN IF NOT EXISTS email text NOT NULL DEFAULT '';
ALTER TABLE ft_children ADD COLUMN IF NOT EXISTS aliases jsonb NOT NULL DEFAULT '[]';
ALTER TABLE ft_children ADD COLUMN IF NOT EXISTS settings jsonb NOT NULL DEFAULT '{}';
CREATE UNIQUE INDEX IF NOT EXISTS ft_children_email ON ft_children (lower(email)) WHERE email <> '';
ALTER TABLE ft_lists ADD COLUMN IF NOT EXISTS username text REFERENCES ft_children ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE ft_lists DROP CONSTRAINT IF EXISTS ft_lists_category_url_key;
CREATE UNIQUE INDEX IF NOT EXISTS ft_lists_child_url ON ft_lists (username, category, url);
ALTER TABLE ft_devices ADD COLUMN IF NOT EXISTS family_id bigint REFERENCES ft_families ON DELETE SET NULL;

-- место по IP и повторное использование места по Wi-Fi (1.2.1)
CREATE TABLE IF NOT EXISTS ft_geoip (
    ip         text PRIMARY KEY,
    lat        double precision NOT NULL,
    lon        double precision NOT NULL,
    accuracy   double precision NOT NULL,
    source     text NOT NULL,
    place      text NOT NULL DEFAULT '',
    fetched_at timestamptz NOT NULL
);
ALTER TABLE ft_devices ADD COLUMN IF NOT EXISTS last_wifi_sig text NOT NULL DEFAULT '';
ALTER TABLE ft_devices ADD COLUMN IF NOT EXISTS last_place text NOT NULL DEFAULT '';
