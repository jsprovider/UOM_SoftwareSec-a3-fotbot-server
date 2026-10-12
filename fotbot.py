"""
FotBot secure server (Assessment 3)

A fitness-tracking server that records daily step counts and lets users share
step data with selected other users. Plain-text TCP protocol on port 8559.

Design notes (map these to the report):
- Concurrency:  one thread per connection, so a slow/idle client cannot block
                others (fixes the starter's single-client DoS).
- Session:      per-connection state held in a Session object local to each
                thread. Cleared on LOGO / QUIT / disconnect. One connection can
                never affect another connection's identity.
- Data store:   in-memory dicts shared across connections, guarded by a single
                lock (the brief allows in-memory; persistence is a residual risk).
- Authentication: USER sets a *claim* only; PASS verifies it. Session identity
                is set ONLY after a correct password.
- Authorisation: deny-by-default. Every protected command checks the session,
                and GETS re-checks ownership/sharing/admin on every call
                (complete mediation).
- Validation:   allowlist + length + range checks, applied before any action
                (canonicalise-then-validate). Unexpected input is rejected safely.
- Responses:    machine-readable 2xx/4xx/5xx codes. No stack traces or secrets
                are ever sent to the client; server-side errors are logged
                generically without credentials.
- Passwords:    never stored or logged in plaintext. Stored as a per-user
                salted PBKDF2-HMAC-SHA256 hash; verified in constant time.
"""

import socket
import threading
import hashlib
import hmac
import os
import re
import logging
from datetime import datetime

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------
HOST = "127.0.0.1"          # loopback only: not reachable from the network
PORT = 8559
BUFFER_SIZE = 4096
MAX_LINE_BYTES = 512        # cap a single command line (prevents memory exhaustion)
IDLE_TIMEOUT = 120          # seconds; drop idle connections (prevents slow-DoS)

# Brute-force protection (implements the PASS brute-force misuse case)
MAX_FAILED_ATTEMPTS = 5     # failed PASS attempts before lockout
LOCKOUT_SECONDS = 300       # how long an account stays locked

# Validation rules (documented, strict allowlists)
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
PASSWORD_MIN = 8
PASSWORD_MAX = 64
STEPS_MIN = 0
STEPS_MAX = 100_000         # generous but bounded daily cap
DATE_FORMAT = "%Y-%m-%d"

PBKDF2_ROUNDS = 100_000

# ---------------------------------------------------------------------------
# Logging: server-side only. We NEVER log a PASS argument or a raw password.
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("fotbot")

# ---------------------------------------------------------------------------
# Shared in-memory data store (guarded by STORE_LOCK)
# ---------------------------------------------------------------------------
# users:   username -> {"salt": bytes, "hash": bytes, "is_admin": bool}
# steps:   username -> {date_string: step_count}
# friends: username -> set(usernames allowed to read this user's steps)
# lockouts: username -> {"fails": int, "until": float epoch seconds}
users = {}
steps = {}
friends = {}
lockouts = {}
STORE_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Password hashing helpers
# ---------------------------------------------------------------------------
def hash_password(password: str, salt: bytes = None):
    """Return (salt, hash) using PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return salt, digest


def verify_password(password: str, salt: bytes, expected: bytes) -> bool:
    """Constant-time password check (avoids timing side channels)."""
    _, digest = hash_password(password, salt)
    return hmac.compare_digest(digest, expected)


# ---------------------------------------------------------------------------
# Validation helpers (allowlist / length / range / format)
# ---------------------------------------------------------------------------
def valid_username(name: str) -> bool:
    return bool(USERNAME_RE.match(name))


def valid_password(pw: str) -> bool:
    # Length-bounded and no whitespace or control characters.
    if not (PASSWORD_MIN <= len(pw) <= PASSWORD_MAX):
        return False
    return all(32 < ord(c) < 127 for c in pw)  # printable ASCII, no spaces


def valid_date(text: str) -> bool:
    try:
        datetime.strptime(text, DATE_FORMAT)
        return True
    except ValueError:
        return False


def valid_steps(text: str):
    """Return int steps if valid, else None."""
    if not text.isdigit():          # rejects signs, decimals, letters
        return None
    value = int(text)
    if STEPS_MIN <= value <= STEPS_MAX:
        return value
    return None


# ---------------------------------------------------------------------------
# Per-connection session state
# ---------------------------------------------------------------------------
class Session:
    def __init__(self):
        self.claimed = None   # username from USER (a claim, not yet proven)
        self.user = None      # authenticated username (set only after PASS)

    def clear(self):
        self.claimed = None
        self.user = None

    @property
    def authenticated(self) -> bool:
        return self.user is not None


# ---------------------------------------------------------------------------
# Command handlers. Each returns a response string (without trailing CRLF).
# Pre-login commands: USER, PASS, REGU, QUIT. Everything else needs a session.
# ---------------------------------------------------------------------------
def cmd_user(session: Session, args):
    if len(args) != 1:
        return "400 Usage: USER <username>"
    # Reject a silent identity switch while logged in (brief requirement).
    if session.authenticated:
        return "403 Already logged in; use LOGO first"
    username = args[0]
    if not valid_username(username):
        return "400 Invalid username format"
    # Note: we do NOT reveal whether the account exists (avoids enumeration).
    session.claimed = username
    return "200 User selected; send PASS"


def cmd_pass(session: Session, args):
    if len(args) != 1:
        return "400 Usage: PASS <password>"
    if session.claimed is None:
        return "400 Send USER before PASS"
    if session.authenticated:
        return "403 Already logged in"

    username = session.claimed
    password = args[0]

    with STORE_LOCK:
        # Lockout check (brute-force protection).
        lk = lockouts.get(username)
        now = datetime.now().timestamp()
        if lk and lk["until"] > now:
            return "429 Account temporarily locked; try again later"

        record = users.get(username)
        # Verify only if the account exists; generic message either way so an
        # attacker cannot tell "no such user" from "wrong password".
        ok = record is not None and verify_password(password, record["salt"], record["hash"])

        if ok:
            lockouts.pop(username, None)          # reset counter on success
            session.user = username
            session.claimed = None
            log.info("Login success for %s", username)
            return "200 Authentication successful"

        # Failed: increment counter and maybe lock.
        entry = lockouts.get(username, {"fails": 0, "until": 0})
        entry["fails"] += 1
        if entry["fails"] >= MAX_FAILED_ATTEMPTS:
            entry["until"] = now + LOCKOUT_SECONDS
            entry["fails"] = 0
            log.warning("Account %s locked after repeated failures", username)
        lockouts[username] = entry
        # We never log the attempted password.
        log.info("Login failure for selected user")
        return "401 Authentication failed"


def cmd_regu(session: Session, args):
    if len(args) != 2:
        return "400 Usage: REGU <username> <password>"
    username, password = args
    if not valid_username(username):
        return "400 Invalid username format"
    if not valid_password(password):
        return "400 Invalid password format"
    with STORE_LOCK:
        if username in users:
            return "409 Username already exists"
        salt, digest = hash_password(password)
        users[username] = {"salt": salt, "hash": digest, "is_admin": False}
        steps[username] = {}
        friends[username] = set()
    log.info("Registered new user %s", username)
    return "201 User registered"


def cmd_upda(session: Session, args):
    if not session.authenticated:
        return "401 Not authenticated"
    if len(args) != 2:
        return "400 Usage: UPDA <date> <steps>"
    date_str, steps_str = args
    if not valid_date(date_str):
        return "400 Invalid date; expected YYYY-MM-DD"
    step_value = valid_steps(steps_str)
    if step_value is None:
        return "400 Invalid step count"
    with STORE_LOCK:
        # UPDA only ever writes the logged-in user's own data.
        steps[session.user][date_str] = step_value
    return "200 Step count updated"


def cmd_gets(session: Session, args):
    if not session.authenticated:
        return "401 Not authenticated"
    if len(args) != 2:
        return "400 Usage: GETS <username> <date>"
    target, date_str = args
    if not valid_username(target):
        return "400 Invalid username format"
    if not valid_date(date_str):
        return "400 Invalid date; expected YYYY-MM-DD"

    requester = session.user
    with STORE_LOCK:
        if target not in users:
            return "404 No such user"
        is_admin = users[requester]["is_admin"]
        allowed = (
            requester == target                       # own data
            or requester in friends.get(target, set())  # shared with requester
            or is_admin                               # administrator
        )
        if not allowed:
            return "403 Not authorised to read this user's data"
        value = steps.get(target, {}).get(date_str)
    if value is None:
        return "404 No step data for that date"
    return f"200 {target} {date_str} {value}"


def cmd_addf(session: Session, args):
    if not session.authenticated:
        return "401 Not authenticated"
    if len(args) != 1:
        return "400 Usage: ADDF <username>"
    target = args[0]
    if not valid_username(target):
        return "400 Invalid username format"
    if target == session.user:
        return "400 Cannot add yourself"
    with STORE_LOCK:
        if target not in users:
            return "404 No such user"
        # ADDF only edits the logged-in user's own friend list.
        friends[session.user].add(target)
    return "200 Friend added"


def cmd_delf(session: Session, args):
    if not session.authenticated:
        return "401 Not authenticated"
    if len(args) != 1:
        return "400 Usage: DELF <username>"
    target = args[0]
    if not valid_username(target):
        return "400 Invalid username format"
    with STORE_LOCK:
        friends[session.user].discard(target)   # idempotent; no info leak
    return "200 Friend removed"


def cmd_getf(session: Session, args):
    if not session.authenticated:
        return "401 Not authenticated"
    if len(args) != 0:
        return "400 Usage: GETF"
    with STORE_LOCK:
        names = sorted(friends.get(session.user, set()))
    return "200 " + (" ".join(names) if names else "(none)")


def cmd_logo(session: Session, args):
    if not session.authenticated:
        return "401 Not logged in"
    session.clear()                              # clears session identity
    return "200 Logged out"


# Dispatch table: command name -> handler
HANDLERS = {
    "USER": cmd_user,
    "PASS": cmd_pass,
    "REGU": cmd_regu,
    "UPDA": cmd_upda,
    "GETS": cmd_gets,
    "ADDF": cmd_addf,
    "DELF": cmd_delf,
    "GETF": cmd_getf,
    "LOGO": cmd_logo,
}


# ---------------------------------------------------------------------------
# Connection handling
# ---------------------------------------------------------------------------
def process_line(session: Session, line: str) -> str:
    """Parse and dispatch a single command line. Returns a response string."""
    parts = line.split()
    if not parts:
        return "400 Empty command"
    command = parts[0].upper()
    args = parts[1:]

    if command == "QUIT":
        return "200 Goodbye"
    handler = HANDLERS.get(command)
    if handler is None:
        return "400 Unknown command"
    # Any unexpected error is contained here: generic 500 to client, detail logged.
    try:
        return handler(session, args)
    except Exception:
        log.exception("Internal error handling command %s", command)
        return "500 Internal server error"


def handle_client(connection, address):
    session = Session()
    connection.settimeout(IDLE_TIMEOUT)
    log.info("Connected: %s:%s", address[0], address[1])
    buffer = b""
    try:
        with connection:
            connection.sendall(b"200 FotBot server ready\r\n")
            while True:
                try:
                    data = connection.recv(BUFFER_SIZE)
                except socket.timeout:
                    connection.sendall(b"408 Idle timeout\r\n")
                    break
                if not data:
                    break
                buffer += data

                # Guard against an endless line with no newline (memory DoS).
                if len(buffer) > MAX_LINE_BYTES and b"\n" not in buffer:
                    connection.sendall(b"400 Line too long\r\n")
                    buffer = b""
                    continue

                while b"\n" in buffer:
                    raw, buffer = buffer.split(b"\n", 1)
                    if len(raw) > MAX_LINE_BYTES:
                        connection.sendall(b"400 Line too long\r\n")
                        continue
                    # Strict decoding: reject non-UTF-8 input rather than mangling it.
                    try:
                        line = raw.decode("utf-8").strip()
                    except UnicodeDecodeError:
                        connection.sendall(b"400 Invalid encoding\r\n")
                        continue

                    response = process_line(session, line)
                    connection.sendall((response + "\r\n").encode("utf-8"))

                    if response.startswith("200 Goodbye"):
                        session.clear()          # clear session on QUIT
                        log.info("Disconnected (QUIT): %s:%s", address[0], address[1])
                        return
    except (ConnectionResetError, BrokenPipeError):
        pass  # client vanished; nothing to send
    except Exception:
        log.exception("Unexpected connection error")
    finally:
        session.clear()                          # clear session on any disconnect
        log.info("Closed: %s:%s", address[0], address[1])


def seed_admin():
    """Seed the administrator account (admin/admin) as the brief specifies."""
    with STORE_LOCK:
        if "admin" not in users:
            salt, digest = hash_password("admin")
            users["admin"] = {"salt": salt, "hash": digest, "is_admin": True}
            steps["admin"] = {}
            friends["admin"] = set()
    log.info("Seeded admin account")


def run_server():
    seed_admin()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen()
        log.info("FotBot server listening on %s:%s", HOST, PORT)
        print(f"FotBot server listening on {HOST}:{PORT}")
        print("Connect with: telnet 127.0.0.1 8559")
        while True:
            connection, address = server.accept()
            # One thread per client so a slow client can't block the server.
            thread = threading.Thread(
                target=handle_client, args=(connection, address), daemon=True
            )
            thread.start()


if __name__ == "__main__":
    try:
        run_server()
    except KeyboardInterrupt:
        print("\nServer stopped")
