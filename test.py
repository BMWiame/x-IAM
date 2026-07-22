"""
test.py — regression tests for models.py

Run with:
    python -m pytest test.py -v
or, if pytest isn't installed:
    python test.py
"""

import os
import json

from models import User, Resource, StorageManager, AccessEngine, check_hierarchy_permission
from config import SYSTEM_PERMISSIONS

TEST_USERS_FILE = "test_users.json"
TEST_LOG_FILE = "test_audit_log.txt"


def cleanup():
    """Remove test artifacts left on disk between/after runs."""
    for f in (TEST_USERS_FILE, TEST_LOG_FILE):
        if os.path.exists(f):
            os.remove(f)


# ---------------------------------------------------------------------
# User: password hashing
# ---------------------------------------------------------------------

def test_user_created_with_password_has_hash_and_salt():
    # Regression test for the very first bug found: `if password is None`
    # was backwards, so a new user's password was never actually hashed.
    alice = User(username="alice", role="Admin", password="Secret123!")
    assert alice.password_hash is not None
    assert alice.salt is not None


def test_user_created_without_password_has_no_hash():
    # Used by StorageManager when reconstructing users from JSON —
    # password_hash/salt are supplied directly instead of via set_password.
    bob = User(username="bob", role="DevOps", password_hash="deadbeef", salt="beefdead")
    assert bob.password_hash == "deadbeef"
    assert bob.salt == "beefdead"


def test_check_password_correct():
    alice = User(username="alice", role="Admin", password="Secret123!")
    assert alice.check_password("Secret123!") is True


def test_check_password_incorrect():
    alice = User(username="alice", role="Admin", password="Secret123!")
    assert alice.check_password("wrong-password") is False


def test_two_users_same_password_get_different_hashes():
    # Salting should mean identical passwords don't produce identical hashes.
    u1 = User(username="u1", role="Admin", password="samepassword")
    u2 = User(username="u2", role="Admin", password="samepassword")
    assert u1.salt != u2.salt
    assert u1.password_hash != u2.password_hash


# ---------------------------------------------------------------------
# Resource: hierarchy serialization
# ---------------------------------------------------------------------

def test_resource_to_dict_root_has_no_parent():
    root = Resource("Root")
    d = root.to_dict()
    assert d == {"name": "Root", "parent_resource": None}


def test_resource_to_dict_nested_chain():
    root = Resource("Root")
    child = Resource("Child", parent_resource=root)
    grandchild = Resource("Grandchild", parent_resource=child)

    d = grandchild.to_dict()
    assert d["name"] == "Grandchild"
    assert d["parent_resource"]["name"] == "Child"
    assert d["parent_resource"]["parent_resource"]["name"] == "Root"
    assert d["parent_resource"]["parent_resource"]["parent_resource"] is None


def test_resource_from_dict_roundtrip():
    root = Resource("Root")
    child = Resource("Child", parent_resource=root)

    d = child.to_dict()
    rebuilt = StorageManager.resource_from_dict(d)

    assert rebuilt.name == "Child"
    assert rebuilt.parent_resource.name == "Root"
    assert rebuilt.parent_resource.parent_resource is None


def test_resource_from_dict_none_returns_none():
    assert StorageManager.resource_from_dict(None) is None


# ---------------------------------------------------------------------
# check_hierarchy_permission
# ---------------------------------------------------------------------

def test_permission_granted_on_exact_resource():
    root = Resource("Local_Sandbox_Testing")
    assert check_hierarchy_permission("Support_Intern", root, SYSTEM_PERMISSIONS) is True


def test_permission_granted_via_parent_walk():
    root = Resource("Local_Sandbox_Testing")
    child = Resource("Alpha_Mock_DB", parent_resource=root)
    # Intern isn't listed for Alpha_Mock_DB directly, but should inherit
    # access via the Local_Sandbox_Testing parent (per config.py).
    assert check_hierarchy_permission("Support_Intern", child, SYSTEM_PERMISSIONS) is True


def test_permission_denied_for_unrelated_resource():
    root = Resource("Production_Cloud_Cluster")
    child = Resource("Customer_Financial_Profiles", parent_resource=root)
    assert check_hierarchy_permission("Support_Intern", child, SYSTEM_PERMISSIONS) is False


def test_permission_denied_for_unknown_role():
    root = Resource("Local_Sandbox_Testing")
    assert check_hierarchy_permission("Nonexistent_Role", root, SYSTEM_PERMISSIONS) is False


# ---------------------------------------------------------------------
# StorageManager: save/load roundtrip
# ---------------------------------------------------------------------

def test_save_and_load_users_roundtrip():
    cleanup()
    original = [
        User(username="alice", role="Admin", password="pw1"),
        User(username="bob", role="DevOps", password="pw2"),
    ]
    StorageManager.save_objects_to_json(original, TEST_USERS_FILE)

    loaded = StorageManager.load_objects_from_json(TEST_USERS_FILE, StorageManager.user_from_dict)

    assert len(loaded) == 2
    usernames = {u.username for u in loaded}
    assert usernames == {"alice", "bob"}

    reloaded_alice = next(u for u in loaded if u.username == "alice")
    assert reloaded_alice.check_password("pw1") is True
    assert reloaded_alice.check_password("wrong") is False
    cleanup()


def test_load_missing_file_returns_empty_list():
    cleanup()
    result = StorageManager.load_objects_from_json("does_not_exist.json", StorageManager.user_from_dict)
    assert result == []


def test_load_corrupted_json_returns_empty_list():
    with open(TEST_USERS_FILE, "w") as f:
        f.write("{not valid json,,,")
    result = StorageManager.load_objects_from_json(TEST_USERS_FILE, StorageManager.user_from_dict)
    assert result == []
    cleanup()


# ---------------------------------------------------------------------
# AccessEngine: authenticate / request_access / logging
# All calls below pass users_file=TEST_USERS_FILE / log_file=TEST_LOG_FILE
# explicitly, so nothing here ever touches the real users.json or
# audit_log.txt used by main.py.
# ---------------------------------------------------------------------

def _seed_users_file():
    cleanup()
    users = [
        User(username="intern_sam", role="Support_Intern", password="pw123"),
    ]
    StorageManager.save_objects_to_json(users, TEST_USERS_FILE)


def test_authenticate_success():
    _seed_users_file()
    assert AccessEngine.authenticate("intern_sam", "pw123", users_file=TEST_USERS_FILE) is True
    cleanup()


def test_authenticate_wrong_password():
    _seed_users_file()
    assert AccessEngine.authenticate("intern_sam", "wrong", users_file=TEST_USERS_FILE) is False
    cleanup()


def test_authenticate_unknown_user():
    _seed_users_file()
    assert AccessEngine.authenticate("ghost", "pw123", users_file=TEST_USERS_FILE) is False
    cleanup()


def test_request_access_writes_audit_log():
    _seed_users_file()

    sandbox = Resource("Local_Sandbox_Testing")
    AccessEngine.request_access(
        "intern_sam", sandbox,
        users_file=TEST_USERS_FILE,
        log_file=TEST_LOG_FILE
    )

    assert os.path.exists(TEST_LOG_FILE)
    with open(TEST_LOG_FILE) as f:
        content = f.read()
    assert "intern_sam" in content
    assert "Local_Sandbox_Testing" in content
    assert "ALLOWED" in content

    cleanup()


def test_log_attempt_strips_newlines():
    # Regression test for the log-injection fix: a username/resource name
    # containing newlines should not be able to forge extra log lines.
    cleanup()

    AccessEngine.log_attempt("evil\nFAKE LOG LINE", "SomeResource", True, log_file=TEST_LOG_FILE)

    with open(TEST_LOG_FILE) as f:
        lines = f.readlines()

    # Should be exactly one line, not split by the injected newline.
    assert len(lines) == 1
    assert "\n" not in lines[0].rstrip("\n")

    cleanup()


# ---------------------------------------------------------------------
# Simple runner (in case pytest isn't available)
# ---------------------------------------------------------------------

if __name__ == "__main__":
    tests = [obj for name, obj in list(globals().items())
             if name.startswith("test_") and callable(obj)]

    passed, failed = 0, 0
    for test_fn in tests:
        try:
            test_fn()
            print(f"[PASS] {test_fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test_fn.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test_fn.__name__}: {type(e).__name__}: {e}")
            failed += 1

    cleanup()
    print(f"\n{passed} passed, {failed} failed out of {len(tests)} tests")