"""
Unit tests for Attribute-Based Access Control (ABAC).
Tests policy evaluation based on:
- User attributes (role, department, assigned patients, security clearance)
- Resource attributes (patient ID, department, sensitivity level)
- Environmental attributes (time of day, access purpose)
- Action attributes (read, update, etc.)
"""

import sys
from pathlib import Path

# Add the 'src' directory to Python search path so tests can import modules directly
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

try:
    from src.abac import (
        check_abac_access,
        evaluate_abac_access,
        check_abac_access_by_id,
        SYNTHETIC_ABAC_USERS,
        SYNTHETIC_ABAC_RECORDS,
    )
except ImportError:
    from abac import (
        check_abac_access,
        evaluate_abac_access,
        check_abac_access_by_id,
        SYNTHETIC_ABAC_USERS,
        SYNTHETIC_ABAC_RECORDS,
    )


# -----------------------------------------------------------------------------
# 1. Authorised Doctor Access
# -----------------------------------------------------------------------------

def test_authorised_doctor_read_access():
    """
    Test 1: Authorised doctor can read an assigned patient's record
    when belonging to the same department, within permitted hours,
    with purpose 'treatment', and with sufficient clearance.
    """
    doctor = {
        "role": "doctor",
        "department": "Cardiology",
        "assigned_patient_ids": ["patient_001"],
        "clearance_level": 3,  # Confidential
    }
    record = {
        "patient_id": "patient_001",
        "department": "Cardiology",
        "sensitivity_level": 3,  # Confidential
    }
    env = {
        "access_time": "10:30",
        "purpose": "treatment",
    }

    assert check_abac_access(doctor, record, "read", env) is True


# -----------------------------------------------------------------------------
# 2. Unassigned Doctor Denied
# -----------------------------------------------------------------------------

def test_unassigned_doctor_denied():
    """
    Test 2: A doctor who is NOT assigned to the patient must be denied access,
    even if in the same department and with sufficient clearance.
    """
    doctor = {
        "role": "doctor",
        "department": "Cardiology",
        "assigned_patient_ids": ["patient_999"],  # Not assigned to patient_001
        "clearance_level": 3,
    }
    record = {
        "patient_id": "patient_001",
        "department": "Cardiology",
        "sensitivity_level": 3,
    }
    env = {
        "access_time": "11:00",
        "purpose": "treatment",
    }

    assert check_abac_access(doctor, record, "read", env) is False


# -----------------------------------------------------------------------------
# 3. Wrong Department Denied
# -----------------------------------------------------------------------------

def test_wrong_department_doctor_denied():
    """
    Test 3: A doctor from a different department must be denied access,
    even if the patient was listed in assigned patients.
    """
    doctor = {
        "role": "doctor",
        "department": "Pediatrics",  # Different department
        "assigned_patient_ids": ["patient_001"],
        "clearance_level": 3,
    }
    record = {
        "patient_id": "patient_001",
        "department": "Cardiology",
        "sensitivity_level": 3,
    }
    env = {
        "access_time": "11:00",
        "purpose": "treatment",
    }

    assert check_abac_access(doctor, record, "read", env) is False


# -----------------------------------------------------------------------------
# 4. Patient Accessing Own Record
# -----------------------------------------------------------------------------

def test_patient_can_read_own_record():
    """
    Test 4: A patient can read their own healthcare record during permitted hours.
    """
    patient = {
        "role": "patient",
        "patient_id": "patient_001",
        "clearance_level": 3,
    }
    record = {
        "patient_id": "patient_001",
        "department": "Cardiology",
        "sensitivity_level": 3,
    }
    env = {
        "access_time": "14:00",
        "purpose": "treatment",
    }

    assert check_abac_access(patient, record, "read", env) is True


# -----------------------------------------------------------------------------
# 5. Patient Accessing Another Patient's Record Denied
# -----------------------------------------------------------------------------

def test_patient_accessing_another_patients_record_denied():
    """
    Test 5: A patient attempting to access another patient's record must be denied.
    """
    patient_alice = {
        "role": "patient",
        "patient_id": "patient_001",
        "clearance_level": 3,
    }
    record_bob = {
        "patient_id": "patient_002",  # Belongs to Bob, not Alice
        "department": "Cardiology",
        "sensitivity_level": 2,
    }
    env = {
        "access_time": "14:00",
        "purpose": "treatment",
    }

    assert check_abac_access(patient_alice, record_bob, "read", env) is False


# -----------------------------------------------------------------------------
# 6. Insufficient Security Clearance Denied
# -----------------------------------------------------------------------------

def test_insufficient_clearance_denied():
    """
    Test 6: A user whose security clearance is lower than the record's
    sensitivity level must be denied access (Rule 5).
    """
    doctor = {
        "role": "doctor",
        "department": "Cardiology",
        "assigned_patient_ids": ["patient_001"],
        "clearance_level": 2,  # Level 2 (Internal)
    }
    record = {
        "patient_id": "patient_001",
        "department": "Cardiology",
        "sensitivity_level": 4,  # Level 4 (Restricted) -> Clearance < Sensitivity
    }
    env = {
        "access_time": "12:00",
        "purpose": "treatment",
    }

    assert check_abac_access(doctor, record, "read", env) is False


# -----------------------------------------------------------------------------
# 7. Access Outside Permitted Hours Denied
# -----------------------------------------------------------------------------

def test_access_before_permitted_hours_denied():
    """
    Test 7a: Access before 08:00 must be denied (Rule 6).
    """
    doctor = {
        "role": "doctor",
        "department": "Cardiology",
        "assigned_patient_ids": ["patient_001"],
        "clearance_level": 3,
    }
    record = {
        "patient_id": "patient_001",
        "department": "Cardiology",
        "sensitivity_level": 3,
    }
    env_early = {
        "access_time": "07:45",  # Outside permitted 08:00-18:00 window
        "purpose": "treatment",
    }

    assert check_abac_access(doctor, record, "read", env_early) is False


def test_access_after_permitted_hours_denied():
    """
    Test 7b: Access after 18:00 must be denied (Rule 6).
    """
    doctor = {
        "role": "doctor",
        "department": "Cardiology",
        "assigned_patient_ids": ["patient_001"],
        "clearance_level": 3,
    }
    record = {
        "patient_id": "patient_001",
        "department": "Cardiology",
        "sensitivity_level": 3,
    }
    env_late = {
        "access_time": "19:15",  # Outside permitted 08:00-18:00 window
        "purpose": "treatment",
    }

    assert check_abac_access(doctor, record, "read", env_late) is False


# -----------------------------------------------------------------------------
# 8. Doctor Updating an Assigned Record
# -----------------------------------------------------------------------------

def test_doctor_updating_assigned_record_allowed():
    """
    Test 8: A doctor can perform 'update' on an assigned patient's record
    within the same department.
    """
    doctor = {
        "role": "doctor",
        "department": "Cardiology",
        "assigned_patient_ids": ["patient_001"],
        "clearance_level": 3,
    }
    record = {
        "patient_id": "patient_001",
        "department": "Cardiology",
        "sensitivity_level": 3,
    }
    env = {
        "access_time": "15:00",
        "purpose": "treatment",
    }

    assert check_abac_access(doctor, record, "update", env) is True


# -----------------------------------------------------------------------------
# 9. Nurse Attempting an Unauthorised Update Denied
# -----------------------------------------------------------------------------

def test_nurse_attempting_update_denied():
    """
    Test 9: A nurse can read assigned records, but MUST be denied when
    attempting an 'update' operation (Least Privilege / Rule 2).
    """
    nurse = {
        "role": "nurse",
        "department": "Cardiology",
        "assigned_patient_ids": ["patient_001"],
        "clearance_level": 3,
    }
    record = {
        "patient_id": "patient_001",
        "department": "Cardiology",
        "sensitivity_level": 3,
    }
    env = {
        "access_time": "11:00",
        "purpose": "treatment",
    }

    # Nurse CAN read
    assert check_abac_access(nurse, record, "read", env) is True
    # Nurse CANNOT update
    assert check_abac_access(nurse, record, "update", env) is False


# -----------------------------------------------------------------------------
# 10. Administrator Access Requiring an Audit Purpose
# -----------------------------------------------------------------------------

def test_administrator_allowed_for_audit_purpose():
    """
    Test 10a: An administrator is allowed to read records if the purpose is 'audit'.
    """
    admin = {
        "role": "admin",
        "clearance_level": 4,  # High clearance
    }
    record = {
        "patient_id": "patient_001",
        "department": "Cardiology",
        "sensitivity_level": 3,
    }
    env_audit = {
        "access_time": "12:00",
        "purpose": "audit",
    }

    assert check_abac_access(admin, record, "read", env_audit) is True


def test_administrator_denied_for_non_audit_purpose():
    """
    Test 10b: An administrator is denied if the purpose is NOT 'audit' (e.g. 'treatment').
    """
    admin = {
        "role": "admin",
        "clearance_level": 4,
    }
    record = {
        "patient_id": "patient_001",
        "department": "Cardiology",
        "sensitivity_level": 3,
    }
    env_treatment = {
        "access_time": "12:00",
        "purpose": "treatment",  # Admin cannot access for treatment
    }

    assert check_abac_access(admin, record, "read", env_treatment) is False


def test_administrator_cannot_update_record():
    """
    Test 10c: Administrators can only read records for audit, not modify them.
    """
    admin = {
        "role": "admin",
        "clearance_level": 4,
    }
    record = {
        "patient_id": "patient_001",
        "department": "Cardiology",
        "sensitivity_level": 3,
    }
    env_audit = {
        "access_time": "12:00",
        "purpose": "audit",
    }

    assert check_abac_access(admin, record, "update", env_audit) is False


# -----------------------------------------------------------------------------
# 11. Fail-Closed Logic: Missing, Invalid, or Tampered Attributes
# -----------------------------------------------------------------------------

def test_missing_clearance_fails_closed():
    """
    Test 11a: Missing user clearance attribute must default to access denied.
    """
    user_without_clearance = {
        "role": "doctor",
        "department": "Cardiology",
        "assigned_patient_ids": ["patient_001"],
        # clearance_level is missing
    }
    record = {
        "patient_id": "patient_001",
        "department": "Cardiology",
        "sensitivity_level": 2,
    }
    env = {
        "access_time": "10:00",
        "purpose": "treatment",
    }

    assert check_abac_access(user_without_clearance, record, "read", env) is False


def test_missing_record_sensitivity_fails_closed():
    """
    Test 11b: Missing resource sensitivity level must default to access denied.
    """
    doctor = {
        "role": "doctor",
        "department": "Cardiology",
        "assigned_patient_ids": ["patient_001"],
        "clearance_level": 4,
    }
    record_without_sensitivity = {
        "patient_id": "patient_001",
        "department": "Cardiology",
        # sensitivity_level is missing
    }
    env = {
        "access_time": "10:00",
        "purpose": "treatment",
    }

    assert check_abac_access(doctor, record_without_sensitivity, "read", env) is False


def test_invalid_time_format_denied():
    """
    Test 11c: Malformed time attribute string must fail closed.
    """
    doctor = {
        "role": "doctor",
        "department": "Cardiology",
        "assigned_patient_ids": ["patient_001"],
        "clearance_level": 3,
    }
    record = {
        "patient_id": "patient_001",
        "department": "Cardiology",
        "sensitivity_level": 3,
    }
    env_bad_time = {
        "access_time": "not-a-valid-time",
        "purpose": "treatment",
    }

    assert check_abac_access(doctor, record, "read", env_bad_time) is False


def test_unsupported_action_denied():
    """
    Test 11d: Arbitrary or destructive actions outside allowed policy must be denied.
    """
    doctor = {
        "role": "doctor",
        "department": "Cardiology",
        "assigned_patient_ids": ["patient_001"],
        "clearance_level": 3,
    }
    record = {
        "patient_id": "patient_001",
        "department": "Cardiology",
        "sensitivity_level": 3,
    }
    env = {
        "access_time": "10:00",
        "purpose": "treatment",
    }

    assert check_abac_access(doctor, record, "export_all", env) is False


# -----------------------------------------------------------------------------
# 12. Boundary Time Tests
# -----------------------------------------------------------------------------

def test_working_hours_exact_boundaries():
    """
    Test 12: Permitted hours boundaries:
    - 08:00 is allowed
    - 18:00 is allowed
    - 07:59 is denied
    - 18:01 is denied
    """
    doctor = {
        "role": "doctor",
        "department": "Cardiology",
        "assigned_patient_ids": ["patient_001"],
        "clearance_level": 3,
    }
    record = {
        "patient_id": "patient_001",
        "department": "Cardiology",
        "sensitivity_level": 3,
    }

    # Exact start boundary (08:00) -> Allowed
    assert check_abac_access(doctor, record, "read", {"access_time": "08:00", "purpose": "treatment"}) is True

    # Exact end boundary (18:00) -> Allowed
    assert check_abac_access(doctor, record, "read", {"access_time": "18:00", "purpose": "treatment"}) is True

    # One minute before start (07:59) -> Denied
    assert check_abac_access(doctor, record, "read", {"access_time": "07:59", "purpose": "treatment"}) is False

    # One minute after end (18:01) -> Denied
    assert check_abac_access(doctor, record, "read", {"access_time": "18:01", "purpose": "treatment"}) is False


# -----------------------------------------------------------------------------
# 13. Text-Based Sensitivity Level Compatibility
# -----------------------------------------------------------------------------

def test_string_sensitivity_and_clearance_supported():
    """
    Test 13: Attributes passed as string names ('Confidential', 'Restricted')
    are properly normalized and evaluated.
    """
    doctor = {
        "role": "doctor",
        "department": "Cardiology",
        "assigned_patient_ids": ["patient_001"],
        "clearance_level": "Restricted",  # Level 4
    }
    record = {
        "patient_id": "patient_001",
        "department": "Cardiology",
        "sensitivity_level": "Confidential",  # Level 3
    }
    env = {
        "access_time": "14:00",
        "purpose": "treatment",
    }

    # Doctor clearance (4) >= Record sensitivity (3) -> True
    assert check_abac_access(doctor, record, "read", env) is True


# -----------------------------------------------------------------------------
# 14. Catalog Lookup Wrapper Test
# -----------------------------------------------------------------------------

def test_catalog_id_helper_authorised():
    """
    Test 14: check_abac_access_by_id correctly looks up synthetic data.
    """
    env = {"access_time": "10:00", "purpose": "treatment"}
    # doctor_001 has Cardiology, assigned patient_001, clearance 3
    # record_001 has Cardiology, patient_001, sensitivity 3
    assert check_abac_access_by_id("doctor_001", "record_001", "read", env) is True

