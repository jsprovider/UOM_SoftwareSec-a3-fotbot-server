"""
Automated tests for the FotBot server (ISYS90125 Assessment 3).

These are black-box tests: they start the real server in a background thread
and talk to it over a TCP socket, exactly as a client (telnet/netcat) would.
Each test resets the in-memory store first so tests are independent.

The tests are grouped to match the misuse cases and the brief's required
test list: happy paths, failed login, duplicate registration, unauthorised
read, self-only update, malformed/missing input, invalid values, session
clearing after LOGO/QUIT, safe error responses, no silent identity switch,
and brute-force lockout.

Run with:   python3 -m unittest -v test_fotbot.py
"""

import socket
import threading
import time
import unittest

import fotbot


# ---------------------------------------------------------------------------
# Start the server once for the whole test module.
# ---------------------------------------------------------------------------
def setUpModule():
    fotbot.seed_admin()
    server_thread = threading.Thread(target=fotbot.run_server, daemon=True)
    server_thread.start()
    time.sleep(0.5)  # give the socket time to bind and listen


class Client:
    """Minimal line-based TCP client for talking to the server."""

    def __init__(self, host="127.0.0.1", port=fotbot.PORT):
        self.sock = socket.socket()
        self.sock.connect((host, port))
        self.sock.settimeout(3)
        self.recv()  # consume the greeting banner

    def send(self, line):
        self.sock.sendall((line + "\n").encode("utf-8"))
        return self.recv()

    def send_raw(self, data: bytes):
        self.sock.sendall(data)
        return self.recv()

    def recv(self):
        return self.sock.recv(4096).decode("utf-8", errors="replace").strip()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def reset_store():
    """Clear all in-memory data and re-seed admin, for test isolation."""
    with fotbot.STORE_LOCK:
        fotbot.users.clear()
        fotbot.steps.clear()
        fotbot.friends.clear()
        fotbot.lockouts.clear()
    fotbot.seed_admin()


class FotBotTestBase(unittest.TestCase):
    def setUp(self):
        reset_store()
        self.clients = []

    def tearDown(self):
        for c in self.clients:
            c.close()

    def new_client(self):
        c = Client()
        self.clients.append(c)
        return c

    def register(self, username, password):
        return self.new_client().send(f"REGU {username} {password}")

    def login(self, username, password):
        c = self.new_client()
        c.send(f"USER {username}")
        resp = c.send(f"PASS {password}")
        return c, resp


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------
class TestNormalWorkflow(FotBotTestBase):
    def test_register_login_update_read(self):
        self.assertTrue(self.register("alice", "password123").startswith("201"))
        c, resp = self.login("alice", "password123")
        self.assertTrue(resp.startswith("200"))
        self.assertTrue(c.send("UPDA 2026-10-01 8500").startswith("200"))
        self.assertIn("8500", c.send("GETS alice 2026-10-01"))

    def test_logout_then_login_again(self):
        self.register("alice", "password123")
        c, _ = self.login("alice", "password123")
        self.assertTrue(c.send("LOGO").startswith("200"))
        c.send("USER alice")
        self.assertTrue(c.send("PASS password123").startswith("200"))

    def test_sharing_grants_read_access(self):
        self.register("alice", "password123")
        self.register("bob", "password456")
        alice, _ = self.login("alice", "password123")
        alice.send("UPDA 2026-10-01 8500")
        bob, _ = self.login("bob", "password456")
        # Before sharing: denied.
        self.assertTrue(bob.send("GETS alice 2026-10-01").startswith("403"))
        # Alice shares with bob.
        self.assertTrue(alice.send("ADDF bob").startswith("200"))
        # After sharing: allowed.
        self.assertIn("8500", bob.send("GETS alice 2026-10-01"))
        # GETF lists the friend.
        self.assertIn("bob", alice.send("GETF"))
        # DELF revokes access again.
        alice.send("DELF bob")
        self.assertTrue(bob.send("GETS alice 2026-10-01").startswith("403"))

    def test_admin_can_read_any_user(self):
        self.register("alice", "password123")
        alice, _ = self.login("alice", "password123")
        alice.send("UPDA 2026-10-01 8500")
        admin, resp = self.login("admin", "admin")
        self.assertTrue(resp.startswith("200"))
        self.assertIn("8500", admin.send("GETS alice 2026-10-01"))


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
class TestAuthentication(FotBotTestBase):
    def test_wrong_password_fails(self):
        self.register("alice", "password123")
        _, resp = self.login("alice", "wrongpass")
        self.assertTrue(resp.startswith("401"))

    def test_pass_without_user_rejected(self):
        c = self.new_client()
        self.assertTrue(c.send("PASS password123").startswith("400"))

    def test_duplicate_registration_rejected(self):
        self.assertTrue(self.register("alice", "password123").startswith("201"))
        self.assertTrue(self.register("alice", "password999").startswith("409"))

    def test_user_enumeration_resistance(self):
        # Wrong password and non-existent user must give the SAME response,
        # so an attacker cannot tell which usernames exist.
        self.register("alice", "password123")
        _, real = self.login("alice", "wrongpass")
        _, fake = self.login("ghost", "whatever1")
        self.assertEqual(real, fake)

    def test_no_silent_identity_switch(self):
        self.register("alice", "password123")
        self.register("bob", "password456")
        c, _ = self.login("alice", "password123")
        # A second USER while logged in must be rejected, not silently switched.
        self.assertTrue(c.send("USER bob").startswith("403"))

    def test_brute_force_lockout(self):
        self.register("alice", "password123")
        c = self.new_client()
        for _ in range(fotbot.MAX_FAILED_ATTEMPTS):
            c.send("USER alice")
            c.send("PASS wrongpass")
        # Next attempt should be locked out, even with the correct password.
        c.send("USER alice")
        self.assertTrue(c.send("PASS password123").startswith("429"))


# ---------------------------------------------------------------------------
# Authorisation
# ---------------------------------------------------------------------------
class TestAuthorisation(FotBotTestBase):
    def test_protected_commands_require_login(self):
        c = self.new_client()
        for cmd in ["UPDA 2026-10-01 100", "GETS alice 2026-10-01",
                    "ADDF bob", "DELF bob", "GETF", "LOGO"]:
            self.assertTrue(c.send(cmd).startswith("401"),
                            f"{cmd} should require authentication")

    def test_unauthorised_read_denied(self):
        self.register("alice", "password123")
        self.register("bob", "password456")
        alice, _ = self.login("alice", "password123")
        alice.send("UPDA 2026-10-01 8500")
        bob, _ = self.login("bob", "password456")
        self.assertTrue(bob.send("GETS alice 2026-10-01").startswith("403"))

    def test_update_writes_only_own_data(self):
        # Bob's UPDA writes Bob's record; it cannot touch Alice's.
        self.register("alice", "password123")
        self.register("bob", "password456")
        alice, _ = self.login("alice", "password123")
        alice.send("UPDA 2026-10-01 8500")
        bob, _ = self.login("bob", "password456")
        bob.send("UPDA 2026-10-01 1")
        # Alice's own value is unchanged.
        self.assertIn("8500", alice.send("GETS alice 2026-10-01"))


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
class TestInputValidation(FotBotTestBase):
    def setUp(self):
        super().setUp()
        self.register("alice", "password123")
        self.c, _ = self.login("alice", "password123")

    def test_invalid_date_rejected(self):
        self.assertTrue(self.c.send("UPDA 2026-13-99 100").startswith("400"))

    def test_negative_steps_rejected(self):
        self.assertTrue(self.c.send("UPDA 2026-10-01 -5").startswith("400"))

    def test_non_numeric_steps_rejected(self):
        self.assertTrue(self.c.send("UPDA 2026-10-01 lots").startswith("400"))

    def test_out_of_range_steps_rejected(self):
        self.assertTrue(self.c.send("UPDA 2026-10-01 999999999").startswith("400"))

    def test_missing_arguments_rejected(self):
        self.assertTrue(self.c.send("UPDA 2026-10-01").startswith("400"))

    def test_bad_username_on_register_rejected(self):
        self.assertTrue(self.register("a", "password123").startswith("400"))   # too short
        self.assertTrue(self.register("bad user", "password123").startswith("400"))  # space

    def test_short_password_on_register_rejected(self):
        self.assertTrue(self.register("charlie", "short").startswith("400"))

    def test_unknown_command_rejected(self):
        self.assertTrue(self.c.send("HELLO world").startswith("400"))

    def test_empty_command_rejected(self):
        self.assertTrue(self.c.send("").startswith("400"))

    def test_overlong_line_rejected(self):
        c = self.new_client()
        resp = c.send_raw(b"A" * (fotbot.MAX_LINE_BYTES + 50) + b"\n")
        self.assertTrue(resp.startswith("400"))


# ---------------------------------------------------------------------------
# Session handling
# ---------------------------------------------------------------------------
class TestSessionHandling(FotBotTestBase):
    def test_commands_fail_after_logo(self):
        self.register("alice", "password123")
        c, _ = self.login("alice", "password123")
        c.send("LOGO")
        self.assertTrue(c.send("GETS alice 2026-10-01").startswith("401"))

    def test_new_connection_has_no_session(self):
        # A fresh connection inherits no identity from a previous one.
        self.register("alice", "password123")
        c1, _ = self.login("alice", "password123")
        c2 = self.new_client()
        self.assertTrue(c2.send("GETF").startswith("401"))


# ---------------------------------------------------------------------------
# Safe error handling (no leakage of internals)
# ---------------------------------------------------------------------------
class TestSafeErrors(FotBotTestBase):
    def test_no_stack_trace_leaked(self):
        self.register("alice", "password123")
        c, _ = self.login("alice", "password123")
        resp = c.send("UPDA 2026-13-99 notanumber")
        # Response is a clean coded error, never Python internals.
        self.assertTrue(resp.startswith("4"))
        for leak in ["Traceback", "Error:", "Exception", "File \""]:
            self.assertNotIn(leak, resp)


if __name__ == "__main__":
    unittest.main(verbosity=2)
