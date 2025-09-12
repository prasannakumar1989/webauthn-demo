-- name: CreateCredential :one
INSERT INTO credentials (user_id, credential_id, public_key, sign_count, backup_eligible, backup_state)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, user_id, credential_id, public_key, sign_count, backup_eligible, backup_state, created_at;

-- name: GetCredentialsByUserID :many
SELECT id, user_id, credential_id, public_key, sign_count, backup_eligible, backup_state, created_at 
FROM credentials WHERE user_id = $1;

-- name: UpdateCredentialSignCountAndFlags :exec
UPDATE credentials
SET sign_count = $3,
    backup_eligible = $4,
    backup_state = $5
WHERE user_id = $1 AND credential_id = $2;
