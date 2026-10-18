# Beniwal VPS — real registration/login starter

## Included
- Real server-side registration and login endpoints
- Passwords hashed with bcrypt
- SQLite user database and session store
- Session cookies marked HttpOnly and SameSite=Lax
- Rate limiting on login and registration
- Login, create-account, customer dashboard, logout UI

## Run command
`npm start`

## Required Koyeb configuration
- Port: use the app's detected port / set service port to 8000
- Environment variable `SESSION_SECRET`: a long random string (at least 32 characters)
- Environment variable `NODE_ENV`: `production`
- Optional `DATA_DIR`: path on a persistent volume, e.g. `/data`

## Important deployment warning
This uses SQLite files for a starter implementation. On hosting where the filesystem is temporary or replaced during redeploy, user accounts and sessions can be lost unless a persistent volume is configured. Before accepting real customers, move the user/session database to managed PostgreSQL and add email verification, password reset, CSRF protection, backups, and a privacy policy. Do not use this starter as the sole security review for a production payment service.

## Razorpay
This project does not collect payments or create Linux VPS instances yet. Add payments only after the hosting service and account flows are ready. Never place Razorpay secret keys in browser JavaScript or a public GitHub repository.
