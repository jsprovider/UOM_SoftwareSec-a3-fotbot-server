# FotBot Secure Server

ISYS90125 Software Security — Assessment 3

A secure implementation of the FotBot fitness-tracking server. FotBot records
users' daily step counts and lets users share their step data with selected
other users. The server speaks a plain-text command protocol over TCP.

## Requirements

- Python 3.8 or later (standard library only — no third-party packages)

## Running the server

```bash
python3 fotbot.py
```

The server listens on `127.0.0.1:8559` (loopback only). Connect with any
plain-text TCP client:

```bash
telnet 127.0.0.1 8559
# or
nc 127.0.0.1 8559
```

An administrator account is seeded at startup with username `admin` and
password `admin` (as specified by the assessment brief). All data is held in
memory and is reset each time the server restarts.

## Protocol

Commands are sent one per line.

| Command | Arguments | Description | Auth required |
|---|---|---|---|
| `REGU` | `<username> <password>` | Register a new user | No |
| `USER` | `<username>` | Select the account to log in to | No |
| `PASS` | `<password>` | Authenticate as the selected user | No |
| `UPDA` | `<date> <steps>` | Update your own step count for a date | Yes |
| `GETS` | `<username> <date>` | Read a user's steps, if authorised | Yes |
| `ADDF` | `<username>` | Let that user read your step data | Yes |
| `DELF` | `<username>` | Revoke that user's read access | Yes |
| `GETF` | — | List who can read your step data | Yes |
| `LOGO` | — | Log out (keeps the connection open) | Yes |
| `QUIT` | — | Close the connection | No |

Dates use the format `YYYY-MM-DD`. Step counts are integers in the range
0–100000.

### Response codes

Responses are machine-readable and loosely follow HTTP conventions:

- `2xx` — success
- `4xx` — client or authorisation error (e.g. `400` bad request, `401` not
  authenticated, `403` not authorised, `404` not found, `409` conflict,
  `429` locked out)
- `5xx` — server error

Stack traces and sensitive values are never returned to the client.

### Example session

```
200 FotBot server ready
REGU alice password123
201 User registered
USER alice
200 User selected; send PASS
PASS password123
200 Authentication successful
UPDA 2026-10-01 8500
200 Step count updated
GETS alice 2026-10-01
200 alice 2026-10-01 8500
ADDF bob
200 Friend added
LOGO
200 Logged out
QUIT
200 Goodbye
```

## Running the tests

```bash
python3 -m unittest -v test_fotbot.py
```

The suite starts the server in a background thread and exercises it over real
TCP connections. It covers normal workflows plus the security cases: failed
login, unauthorised reads, self-only updates, malformed and invalid input,
session clearing after LOGO/QUIT, user-enumeration resistance, brute-force
lockout, no silent identity switch, and safe (non-leaking) error responses.

## Security controls (where to find them in `fotbot.py`)

- **Authentication** — `cmd_user` / `cmd_pass`. Passwords stored as salted
  PBKDF2-HMAC-SHA256 hashes; verified in constant time.
- **Authorisation** — `cmd_gets` enforces own / shared / admin access,
  deny-by-default, on every call.
- **Session state** — per-connection `Session` object; cleared on LOGO, QUIT
  and disconnect.
- **Input validation** — `valid_username`, `valid_password`, `valid_date`,
  `valid_steps` (allowlist, length, format and range checks).
- **Availability** — one thread per connection, idle timeout, line-length cap.
- **Brute-force protection** — per-account lockout after repeated failures.

## Notes and limitations

- All state is in memory and lost on restart (per the brief).
- The transport is plain-text TCP with no TLS.
- The `admin`/`admin` default credentials are for assessment testing only.

See the accompanying report for the full requirements analysis, control
mapping, testing discussion and residual-risk reflection.

## AI use

Generative AI was used to assist with the implementation and tests, reviewed
and tested by the author. See the report's reference list for the declaration.
```
