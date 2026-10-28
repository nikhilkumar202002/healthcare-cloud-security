"""
Unit tests for Healthcare Cloud Access Control.
Tests trusted user lookup, RBAC permissions, and patient record ownership.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

try:
    from src.access_control import check_access, get_trusted_user
except ImportError:
    from access_control import check_access, get_trusted_user


# -------------------------------------------------------------
# 1. Trusted-user lookup tests
# -------------------------------------------------------------

def test_registered_user_is_found():
    user = get_trusted_user("patient_alice")
    assert user is not None
    assert user["role"] == "patient"
    assert user["patient_id"] == "patient_001"


def test_unknown_user_is_rejected():
    assert get_trusted_user("unknown_user") is None


def test_invalid_user_id_is_rejected():
    assert get_trusted_user(None) is None


def test_whitespace_user_id_is_rejected():
    assert get_trusted_user("   ") is None


# -------------------------------------------------------------
# 2. RBAC permission tests (Staff & Roles)
# -------------------------------------------------------------

def test_doctor_can_read_record():
    assert check_access("doctor_001", "read", "record_001") is True


def test_doctor_can_update_record():
    assert check_access("doctor_001", "update", "record_001") is True


def test_nurse_cannot_delete_record():
    # Least privilege: nurses can read, but never delete
    assert check_access("nurse_001", "delete", "record_001") is False


def test_patient_cannot_update_record():
    # Patients cannot edit clinical records
    assert check_access("patient_alice", "update", "record_001") is False


def test_unknown_user_cannot_access_record():
    # Default deny for unauthenticated/unregistered users
    assert check_access("unknown_user", "read", "record_001") is False


def test_unknown_action_is_denied():
    assert check_access("doctor_001", "download_all", "record_001") is False


# -------------------------------------------------------------
# 3. Patient record ownership tests (BOLA / IDOR Prevention)
# -------------------------------------------------------------

def test_patient_can_read_own_record():
    # Alice owns record_001 -> Access granted
    assert check_access("patient_alice", "read", "record_001") is True


def test_patient_cannot_read_another_patients_record():
    # Alice does NOT own record_002 (Bob owns it) -> Access denied
    assert check_access("patient_alice", "read", "record_002") is False


def test_second_patient_can_read_own_record():
    # Bob owns record_002 -> Access granted
    assert check_access("patient_bob", "read", "record_002") is True


# -------------------------------------------------------------
# 4. Missing record and input validation tests
# -------------------------------------------------------------

def test_missing_record_is_denied():
    assert check_access("doctor_001", "read", "record_999") is False


def test_empty_record_id_is_denied():
    assert check_access("doctor_001", "read", "") is False


def test_none_user_id_is_denied():
    assert check_access(None, "read", "record_001") is False


def test_none_action_is_denied():
    assert check_access("doctor_001", None, "record_001") is False


def test_none_record_id_is_denied():
    assert check_access("doctor_001", "read", None) is False


def test_action_is_case_insensitive():
    assert check_access("doctor_001", "READ", "record_001") is True
