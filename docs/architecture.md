# Foundation architecture

`create_app(Settings)` constructs a FastAPI instance with its own immutable
settings. The module-level `app` is the Uvicorn entrypoint. Settings load from
environment variables and an optional working-directory `.env`; defaults need
no network access, credentials, or database. Invalid configuration fails at startup.

Request flow: server-generated request ID → route → Pydantic response → completion
log with status and elapsed milliseconds. HTTP/validation errors use ErrorResponse;
unexpected route exceptions are redacted at the HTTP middleware boundary.
HealthResponse describes process liveness only. OpenAPI documents the contracts.

The lifespan configures the application logger and records startup/shutdown.
Logging is process-wide (as in Python's logging library); settings are per app.
The application's logger configuration does not replace third-party handlers.
Run Uvicorn with `--no-access-log` to avoid its raw-URL access logs.

Only Foundation is implemented. There are no detector, scoring, agent, provider,
evaluation, or UI modules. They can be added to the package in later milestones.
