-- Every account gets a stable id, which the credential tables key on; the
-- address stays unique but can change. The store supplies the id on insert;
-- existing rows get a random one (`md5` works where `gen_random_uuid` does
-- not exist, before PostgreSQL 13).
ALTER TABLE users ADD COLUMN id UUID;
UPDATE users SET id = md5(random()::text || clock_timestamp()::text || email)::uuid;
ALTER TABLE users ALTER COLUMN id SET NOT NULL;
ALTER TABLE users DROP CONSTRAINT users_pkey;
ALTER TABLE users ADD PRIMARY KEY (id);
ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);
