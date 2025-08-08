# Todo App with Keycloak Authentication

This is a Rust (Axum) to-do list app with per-user authentication using Keycloak (OAuth2/OpenID Connect). The frontend uses htmx for dynamic updates.

## Prerequisites

- Docker and Docker Compose
- Rust toolchain (for local development)

## Quick Start

### 1. Clone the repository

```
git clone <your-repo-url>
cd <repo-folder>
```

### 2. Automated Setup, Test, and Cleanup

To build, start, set up Keycloak, run a full test (login, add, update, delete todo), and clean up, simply run:

```
./run.sh
```

This script will:

- Start Keycloak and the Rust service in the background
- Wait for both services to be up
- Run `setup_keycloak.sh` to configure Keycloak (realm, client, test user)
- Log in as the test user, add, toggle, and delete a todo, verifying each step
- Clean up all containers at the end

You can inspect or modify `setup_keycloak.sh` to change the test user, password, or client secret.

---

If you want to use the app interactively:

1. Start the services:
   ```
   docker-compose up --build
   ```
2. Open http://localhost:3000
3. Click "Login" to authenticate with Keycloak
4. Add, toggle, and delete to-dos (each user sees only their own)
5. Click "Logout" to end your session

## Development

- The backend is in `src/main.rs`
- Templates are in `templates/`
- To run locally (without Docker):
  1. Ensure Keycloak is running (via Docker)
  2. Run: `cargo run`
  3. You can use the curl commands in `run.sh` as examples for manual API testing.

## Notes

- Todos are stored in `todos.json` in the project root
- Each todo is associated with the authenticated user's Keycloak ID
- The app uses htmx for inline updates
- `run.sh` and `setup_keycloak.sh` automate setup, test, and cleanup for CI or local testing.

## Troubleshooting

- If you change the Keycloak client secret, update `CLIENT_SECRET` in `src/main.rs`, `setup_keycloak.sh`, and `run.sh`
- If you change ports, update URLs in both `docker-compose.yml`, `src/main.rs`, and the scripts

---

For questions or issues, please open an issue in this repository.
