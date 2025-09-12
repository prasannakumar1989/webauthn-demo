# WebAuthn Demo

A demo project implementing WebAuthn registration and login flows with Go (backend) and a simple HTML/JS frontend.

## Features

- WebAuthn registration and login handlers (Go backend)
- Redis session store
- PostgreSQL database for users and credentials
- Frontend for testing registration and login

## Prerequisites

- Go 1.20+
- PostgreSQL
- Redis
- Python 3 (for simple frontend server)

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/prasannakumar1989/webauthn-demo.git
cd webauthn-demo
```

### 2. Setup Database

- Create a PostgreSQL database and user.
- Update your `.env` or environment variables with your database connection string:
  ```
  DATABASE_URL=postgres://user:password@localhost:5432/webauthn_demo?sslmode=disable
  ```
- Run migrations:
  ```bash
  make migrate
  ```

### 3. Setup Redis

- Start Redis locally (default: `localhost:6379`).
- Update `.env` or environment variables if needed:
  ```
  REDIS_ADDR=localhost:6379
  REDIS_PASSWORD=
  REDIS_DB=0
  ```

### 4. Backend Server

- Install dependencies:
  ```bash
  go mod tidy
  ```
- Run the backend server:
  ```bash
  go run main.go
  ```
- The backend will start on `http://localhost:8080` by default.

### 5. Frontend

- The test frontend is in `frontend/testapp.html`.
- Serve it with Python:
  ```bash
  cd frontend
  python3 -m http.server 8081
  ```
- Open [http://localhost:8081/testapp.html](http://localhost:8081/testapp.html) in your browser.

## Usage

- Enter a username and click **Register** to begin WebAuthn registration.
- Click **Login** to test authentication.

## Endpoints

### Backend

- `POST /register/begin` — Start registration
- `POST /register/finish` — Finish registration
- `POST /login/begin` — Start login
- `POST /login/finish` — Finish login
- `GET /health` — Health check

## Environment Variables

See `config/configdetails.go` for all supported environment variables.

## SQL Migrations

- Migrations are in `db/migrations/`
- Use `dbmate` or `make migrate` to apply them.

## Notes

- Make sure `RP_ORIGIN` matches your frontend origin (e.g., `http://localhost:8081`).
- CORS is enabled for frontend-backend communication.
- For production, set environment variables securely and use HTTPS.

## License

MIT
