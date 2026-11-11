"""
Unit tests for Relationship-Based Access Control (ReBAC).

Tests relationship-driven access decisions:
- Doctor assignment relationships (read & update).
- Nurse care-team membership relationships (read only).
- Patient self-ownership relationships (read only).
- Default-deny (fail-closed) behavior for unassigned, unknown, or invalid users.
"""

import sys
from pathlib import Path

# Add 'src' directory to Python module search path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

try:
    from src.rebac import (
        check_rebac_access,
        is_doctor_assigned,
        is_nurse_in_care_team,
        resolve_patient_id,
        SYNTHETIC_RELATIONSHIPS,
    )
except ImportError:
    from rebac import (
        check_rebac_access,
        is_doctor_assigned,
        is_nurse_in_care_team,
        resolve_patient_id,
        SYNTHETIC_RELATIONSHIPS,
    )


# -----------------------------------------------------------------------------
# 1. Assigned Doctor Tests
# -----------------------------------------------------------------------------

def test_assigned_doctor_can_read_record():
    """
    Test 1: doctor_001 is assigned to patient_001 and can read record_001.
    """
    assert check_rebac_access("doctor_001", "read", "record_001") is True


def test_assigned_doctor_can_update_record():
    """
    Test 2: doctor_001 is assigned to patient_001 and can update record_001.
    """
    assert check_rebac_access("doctor_001", "update", "record_001") is True


# -----------------------------------------------------------------------------
# 2. Unassigned Doctor Tests
# -----------------------------------------------------------------------------

def test_unassigned_doctor_cannot_read_record():
    """
    Test 3: doctor_001 is NOT assigned to patient_002 (empty doctor list)
    and must be denied read access to record_002.
    """
    assert check_rebac_access("doctor_001", "read", "record_002") is False


def test_unassigned_doctor_cannot_update_record():
    """
    Doctor without an assignment relationship cannot update patient_002's record.
    """
    assert check_rebac_access("doctor_001", "update", "record_002") is False


# -----------------------------------------------------------------------------
# 3. Nurse Care Team Tests
# -----------------------------------------------------------------------------

def test_nurse_in_care_team_can_read_record():
    """
    Test 4: nurse_001 belongs to patient_001's care team and can read record_001.
    """
    assert check_rebac_access("nurse_001", "read", "record_001") is True


def test_nurse_cannot_update_record():
    """
    Test 5: nurse_001 is in the care team, but nurses cannot update records
    under the principle of least privilege.
    """
    assert check_rebac_access("nurse_001", "update", "record_001") is False


def test_unassigned_nurse_cannot_read_record():
    """
    A nurse who does not belong to a patient's care team must be denied access.
    """
    custom_relationships = {
        "patient_001": {
            "doctor_ids": ["doctor_001"],
            "nurse_ids": [],  # No nurses assigned
        }
    }
    assert check_rebac_access(
        "nurse_001", "read", "record_001", relationship_store=custom_relationships
    ) is False


# -----------------------------------------------------------------------------
# 4. Patient Self-Ownership Tests
# -----------------------------------------------------------------------------

def test_patient_can_read_own_record():
    """
    Test 6: patient_alice owns patient_001 and can read record_001.
    """
    assert check_rebac_access("patient_alice", "read", "record_001") is True


def test_patient_cannot_read_another_patients_record():
    """
    Test 7: patient_alice (patient_001) cannot read record_002 (patient_002).
    """
    assert check_rebac_access("patient_alice", "read", "record_002") is False


def test_patient_cannot_update_own_record():
    """
    Patients can read their health records, but cannot modify clinical data.
    """
    assert check_rebac_access("patient_alice", "update", "record_001") is False


# -----------------------------------------------------------------------------
# 5. Unknown or Unauthenticated User Tests
# -----------------------------------------------------------------------------

def test_unknown_doctor_is_denied_access():
    """
    Test 8: An unknown or unregistered doctor cannot access records.
    """
    assert check_rebac_access("unknown_doctor", "read", "record_001") is False


def test_unknown_patient_is_denied_access():
    """
    An unauthenticated user claiming to be a patient is denied.
    """
    assert check_rebac_access("unknown_patient", "read", "record_001") is False


# -----------------------------------------------------------------------------
# 6. Missing Patient Relationship Tests
# -----------------------------------------------------------------------------

def test_missing_patient_relationship_is_denied():
    """
    Test 9: Accessing a record or patient with no registered relationship entry
    must fail closed and return False.
    """
    assert check_rebac_access("doctor_001", "read", "record_999") is False
    assert check_rebac_access("doctor_001", "read", "patient_999") is False


# -----------------------------------------------------------------------------
# 7. Invalid or Missing Input Data Tests (Fail-Closed)
# -----------------------------------------------------------------------------

def test_none_user_id_is_denied():
    """
    Test 10a: None as user_id must be denied.
    """
    assert check_rebac_access(None, "read", "record_001") is False


def test_none_action_is_denied():
    """
    Test 10b: None as action must be denied.
    """
    assert check_rebac_access("doctor_001", None, "record_001") is False


def test_none_target_id_is_denied():
    """
    Test 10c: None as target_id must be denied.
    """
    assert check_rebac_access("doctor_001", "read", None) is False


def test_empty_string_user_id_is_denied():
    """
    Test 10d: Empty string user_id must be denied.
    """
    assert check_rebac_access("", "read", "record_001") is False
    assert check_rebac_access("   ", "read", "record_001") is False


def test_invalid_action_is_denied():
    """
    Test 10e: Unsupported actions (e.g. 'delete' or 'export') are rejected.
    """
    assert check_rebac_access("doctor_001", "delete", "record_001") is False


# -----------------------------------------------------------------------------
# 8. Target Resolution and Helper Function Tests
# -----------------------------------------------------------------------------

def test_direct_patient_id_target_supported():
    """
    Test 11: check_rebac_access accepts direct patient_id (e.g. 'patient_001')
    as well as record_id (e.g. 'record_001').
    """
    assert check_rebac_access("doctor_001", "read", "patient_001") is True


def test_action_is_case_insensitive():
    """
    Test 12: Actions like 'READ' or 'UpDaTe' are properly normalized.
    """
    assert check_rebac_access("doctor_001", "READ", "record_001") is True
    assert check_rebac_access("doctor_001", "UPDATE", "record_001") is True

