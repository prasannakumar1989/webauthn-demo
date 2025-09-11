-- name: CreateUser :one
INSERT INTO users(username, display_name)
VALUES ($1, $2)
RETURNING id, username, display_name, created_at;

-- name: GetUserByUsername :one
SELECT id, username, display_name, created_at FROM users where username=$1;