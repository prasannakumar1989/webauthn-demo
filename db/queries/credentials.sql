-- name: CreateCredential :one
INSERT INTO credentials (user_id, credential_id, public_key, sign_count)
VALUES ($1, $2, $3, $4)
RETURNING id, user_id, credential_id, public_key, sign_count, created_at;

-- name: GetCredentialsByUserID :many
SELECT id, user_id, credential_id, public_key, sign_count, created_at 
FROM credentials WHERE user_id = $1;