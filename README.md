# Auth Service

A production-grade authentication and session management REST API built as a standalone service. Designed to be consumed by any application as an independent backend service.

## Tech Stack

- **Node.js + Express** — HTTP server and routing
- **PostgreSQL** — persistent storage for users and refresh tokens
- **Redis** — access token denylist and brute force tracking
- **Docker + Nginx** — containerization and reverse proxy
- **JWT** — stateless access tokens with refresh token rotation
- **bcrypt** — password hashing

## Features

- User registration with hashed passwords
- JWT-based login with short-lived access tokens (15 min)
- Refresh token flow for seamless session continuation (7 days)
- Logout from single device or all devices simultaneously
- Access token denylist on logout via Redis
- Brute force protection — tracks failed attempts per IP and per account separately
- Global rate limiting via express-rate-limit
- Protected route middleware that validates and checks token blacklist
- Fully containerized with Docker Compose

## Architecture

Client → Nginx (port 80) → Node.js App (port 3000) → PostgreSQL → Redis

## API Endpoints

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| POST | `/auth/register` | No | Register a new user |
| POST | `/auth/login` | No | Login and receive tokens |
| POST | `/auth/refresh` | No | Get a new access token |
| POST | `/auth/logout` | No | Logout from current device |
| POST | `/auth/logout-all` | No | Logout from all devices |
| GET | `/auth/me` | Yes | Get current user info |
| GET | `/health` | No | Health check |

## Getting Started

### Prerequisites
- Docker Desktop installed and running

### Run with Docker

```bash
git clone https://github.com/PramukhN767/auth_service.git
cd auth_service
docker-compose up --build
```

The API will be available at `http://localhost` (port 80 via Nginx).

### Run locally

```bash
npm install
# Set up .env file (see .env.example)
npm run dev
```

## Environment Variables

See `.env.example` for all required variables.

| Variable | Description |
|----------|-------------|
| PORT | Server port (default 3000) |
| DB_HOST | PostgreSQL host |
| DB_NAME | Database name |
| DB_USER | Database user |
| DB_PASSWORD | Database password |
| JWT_SECRET | Secret key for signing tokens |
| JWT_EXPIRES_IN | Access token expiry (e.g. 15m) |
| REFRESH_TOKEN_EXPIRES_IN | Refresh token expiry (e.g. 7d) |
| REDIS_URL | Redis connection URL |

## Security Decisions

**Why short-lived access tokens?**
Access tokens expire in 15 minutes. Even if intercepted, the attack window is minimal.

**Why Redis for the denylist?**
JWTs are stateless — a logged-out token is still cryptographically valid until expiry. Redis lets us invalidate tokens instantly on logout with automatic expiry matching the token's remaining TTL.

**Why track brute force per IP and per account separately?**
They represent different threat models. A distributed attack (many IPs, one account) is caught by the account counter. A single attacker probing many accounts is caught by the IP counter.

**Why store refresh tokens in PostgreSQL?**
Persistence and revocability. Refresh tokens need to survive server restarts and be individually revocable — Redis alone can't guarantee this.

## Project Structure

auth_service/
├── src/
│   ├── config/
│   │   ├── db.js          # PostgreSQL connection pool
│   │   └── redis.js       # Redis client
│   ├── controllers/
│   │   └── authController.js
│   ├── middleware/
│   │   └── authenticate.js
│   ├── models/
│   │   ├── userModel.js
│   │   └── refreshTokenModel.js
│   └── routes/
│       └── authRoutes.js
├── Dockerfile
├── docker-compose.yml
├── nginx.conf
├── init.sql
└── server.js