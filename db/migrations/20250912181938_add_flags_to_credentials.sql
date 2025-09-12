-- migrate:up
ALTER TABLE credentials ADD COLUMN backup_state boolean NOT NULL DEFAULT FALSE;
ALTER TABLE credentials ADD COLUMN backup_eligible boolean NOT NULL DEFAULT FALSE;

-- migrate:down
ALTER TABLE credentials DROP COLUMN backup_eligible;
ALTER TABLE credentials DROP COLUMN backup_state;