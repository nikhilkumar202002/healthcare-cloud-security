"""
Attribute-Based Access Control (ABAC) Module
Healthcare Cloud Security Prototype

This module implements ABAC access decisions based on four types of attributes:
1. User attributes: role, department, assigned patient IDs, security clearance level
2. Resource attributes: patient ID, department, record sensitivity level
3. Action attributes: requested operation (e.g., 'read', 'update')
4. Environmental attributes: access time, purpose of access ('treatment' or 'audit')

Security Design:
- Fail-Closed: Access is denied by default unless all security conditions are explicitly met.
- Principle of Least Privilege: Users only receive access necessary for their defined purpose.
"""

import datetime
from typing import Any, Dict, Optional, Union

# -----------------------------------------------------------------------------
# Sensitivity Level Definitions (NIST-aligned numeric mapping)
# -----------------------------------------------------------------------------
SENSITIVITY_LEVELS = {
    "public": 1,
    "internal": 2,
    "confidential": 3,
    "restricted": 4,
}

# Permitted demonstration working hours: 08:00 to 18:00 (inclusive)
PERMITTED_START_TIME = datetime.time(8, 0)
PERMITTED_END_TIME = datetime.time(18, 0)

# Valid purposes of access in this healthcare system
VALID_PURPOSES = {"treatment", "audit"}


def normalize_level(level: Any) -> Optional[int]:
    """
    Convert a clearance or sensitivity level into an integer (1 to 4).
    Accepts both integers (1-4) and standard text names (e.g. 'Confidential').
    Returns None if the level is invalid, unrecognised, or missing.
    """
    if level is None or isinstance(level, bool):
        return None

    # If already an integer
    if isinstance(level, int):
        if 1 <= level <= 4:
            return level
        return None

    # If provided as a string name
    if isinstance(level, str):
        cleaned = level.strip().lower()
        return SENSITIVITY_LEVELS.get(cleaned)

    return None


def parse_access_time(time_value: Any) -> Optional[datetime.time]:
    """
    Parse a time representation into a datetime.time object.
    Supports:
      - datetime.time objects
      - datetime.datetime objects (extracts time component)
      - string format 'HH:MM' or 'HH:MM:SS'
    Returns None if parsing fails or input is invalid.
    """
    if isinstance(time_value, datetime.time):
        return time_value

    if isinstance(time_value, datetime.datetime):
        return time_value.time()

    if isinstance(time_value, str):
        cleaned = time_value.strip()
        parts = cleaned.split(":")
        if len(parts) in (2, 3):
            try:
                hour = int(parts[0])
                minute = int(parts[1])
                second = int(parts[2]) if len(parts) == 3 else 0
                if 0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59:
                    return datetime.time(hour, minute, second)
            except ValueError:
                return None

    return None


def get_attribute(data: Dict[str, Any], candidate_keys: list) -> Any:
    """
    Helper function to safely look up an attribute by checking multiple
    possible alias keys (e.g. 'patient_id' vs 'owner_patient_id').
    Returns None if not found or if data is not a dictionary.
    """
    if not isinstance(data, dict):
        return None
    for key in candidate_keys:
        if key in data and data[key] is not None:
            return data[key]
    return None


def check_abac_access(
    user_attributes: Dict[str, Any],
    resource_attributes: Dict[str, Any],
    action: str,
    environment_attributes: Dict[str, Any],
) -> bool:
    """
    Evaluate an Attribute-Based Access Control (ABAC) access request.

    Parameters:
      user_attributes (dict):
        - role: str ('doctor', 'nurse', 'patient', 'admin')
        - department: str (for medical staff)
        - assigned_patient_ids: list/set (for medical staff)
        - clearance_level: int or str (1-4 or name)
        - patient_id: str (for patient role)
      resource_attributes (dict):
        - patient_id: str (record owner)
        - department: str (record clinical department)
        - sensitivity_level: int or str (1-4 or name)
      action (str):
        - 'read', 'update', etc.
      environment_attributes (dict):
        - access_time: str ('HH:MM') or datetime.time
        - purpose: str ('treatment' or 'audit')

    Returns:
      bool: True if access is explicitly permitted; False otherwise (fail-closed).
    """

    # -------------------------------------------------------------------------
    # STEP 1: Basic validation of inputs (Fail-Closed)
    # -------------------------------------------------------------------------
    if not isinstance(user_attributes, dict):
        return False
    if not isinstance(resource_attributes, dict):
        return False
    if not isinstance(environment_attributes, dict):
        return False
    if not isinstance(action, str):
        return False

    clean_action = action.strip().lower()
    if not clean_action:
        return False

    # -------------------------------------------------------------------------
    # STEP 2: Environmental Attributes Evaluation (Time & Purpose)
    # -------------------------------------------------------------------------
    # Rule 6: Access is permitted only between 08:00 and 18:00
    raw_time = get_attribute(environment_attributes, ["access_time", "time"])
    access_time = parse_access_time(raw_time)
    if access_time is None:
        return False

    if not (PERMITTED_START_TIME <= access_time <= PERMITTED_END_TIME):
        return False

    # Purpose check: Purpose must be specified and valid ('treatment' or 'audit')
    raw_purpose = get_attribute(environment_attributes, ["purpose", "purpose_of_access"])
    if not isinstance(raw_purpose, str):
        return False
    purpose = raw_purpose.strip().lower()
    if purpose not in VALID_PURPOSES:
        return False

    # -------------------------------------------------------------------------
    # STEP 3: Security Clearance vs Sensitivity Level Check (Rule 5)
    # -------------------------------------------------------------------------
    # Rule 5: User clearance must be greater than or equal to record sensitivity
    raw_clearance = get_attribute(
        user_attributes,
        ["clearance_level", "security_clearance_level", "clearance", "security_clearance"],
    )
    raw_sensitivity = get_attribute(
        resource_attributes,
        ["sensitivity_level", "record_sensitivity_level", "sensitivity"],
    )

    user_clearance = normalize_level(raw_clearance)
    record_sensitivity = normalize_level(raw_sensitivity)

    if user_clearance is None or record_sensitivity is None:
        return False

    if user_clearance < record_sensitivity:
        return False

    # -------------------------------------------------------------------------
    # STEP 4: User Role Extraction & Role-Specific Attribute Checks
    # -------------------------------------------------------------------------
    raw_role = get_attribute(user_attributes, ["role", "user_role"])
    if not isinstance(raw_role, str):
        return False
    role = raw_role.strip().lower()

    # Retrieve common resource attributes
    resource_patient_id = get_attribute(resource_attributes, ["patient_id", "owner_patient_id"])
    if not isinstance(resource_patient_id, str) or not resource_patient_id.strip():
        return False
    resource_patient_id = resource_patient_id.strip()

    # RULE 1: Doctor Access Rules
    # - Can read or update
    # - Must belong to the same department as the record
    # - Must be assigned to the patient
    # - Purpose must be 'treatment'
    if role == "doctor":
        if clean_action not in {"read", "update"}:
            return False

        if purpose != "treatment":
            return False

        user_dept = get_attribute(user_attributes, ["department"])
        res_dept = get_attribute(resource_attributes, ["department"])
        if not isinstance(user_dept, str) or not isinstance(res_dept, str):
            return False
        if user_dept.strip().lower() != res_dept.strip().lower():
            return False

        assigned_list = get_attribute(
            user_attributes, ["assigned_patient_ids", "assigned_patients"]
        )
        if not isinstance(assigned_list, (list, set, tuple)):
            return False

        normalized_assigned = {
            str(pid).strip().lower() for pid in assigned_list if isinstance(pid, str)
        }
        if resource_patient_id.lower() not in normalized_assigned:
            return False

        return True

    # RULE 2: Nurse Access Rules
    # - Can only read (no update or delete)
    # - Must belong to the same department as the record
    # - Must be assigned to the patient
    # - Purpose must be 'treatment'
    elif role == "nurse":
        if clean_action != "read":
            return False

        if purpose != "treatment":
            return False

        user_dept = get_attribute(user_attributes, ["department"])
        res_dept = get_attribute(resource_attributes, ["department"])
        if not isinstance(user_dept, str) or not isinstance(res_dept, str):
            return False
        if user_dept.strip().lower() != res_dept.strip().lower():
            return False

        assigned_list = get_attribute(
            user_attributes, ["assigned_patient_ids", "assigned_patients"]
        )
        if not isinstance(assigned_list, (list, set, tuple)):
            return False

        normalized_assigned = {
            str(pid).strip().lower() for pid in assigned_list if isinstance(pid, str)
        }
        if resource_patient_id.lower() not in normalized_assigned:
            return False

        return True

    # RULE 3: Patient Access Rules
    # - Can only read their own record
    # - Purpose must be 'treatment'
    elif role == "patient":
        if clean_action != "read":
            return False

        if purpose != "treatment":
            return False

        user_patient_id = get_attribute(user_attributes, ["patient_id"])
        if not isinstance(user_patient_id, str):
            return False

        if user_patient_id.strip().lower() != resource_patient_id.lower():
            return False

        return True

    # RULE 4: Administrator Access Rules
    # - Can only read
    # - Can ONLY access for an 'audit' purpose
    elif role in {"admin", "administrator"}:
        if clean_action != "read":
            return False

        if purpose != "audit":
            return False

        return True

    # Any unknown or unhandled role is rejected
    return False


# Convenience alias matching common academic nomenclature
evaluate_abac_access = check_abac_access


# -----------------------------------------------------------------------------
# Synthetic Test Catalog for ABAC Demonstration
# -----------------------------------------------------------------------------
SYNTHETIC_ABAC_USERS = {
    "doctor_001": {
        "role": "doctor",
        "department": "Cardiology",
        "assigned_patient_ids": ["patient_001"],
        "clearance_level": 3,  # Confidential
    },
    "doctor_002": {
        "role": "doctor",
        "department": "Pediatrics",
        "assigned_patient_ids": ["patient_002"],
        "clearance_level": 4,  # Restricted
    },
    "nurse_001": {
        "role": "nurse",
        "department": "Cardiology",
        "assigned_patient_ids": ["patient_001"],
        "clearance_level": 2,  # Internal
    },
    "admin_001": {
        "role": "admin",
        "department": "IT_Audit",
        "assigned_patient_ids": [],
        "clearance_level": 4,  # Restricted
    },
    "patient_alice": {
        "role": "patient",
        "patient_id": "patient_001",
        "clearance_level": 3,  # Confidential
    },
    "patient_bob": {
        "role": "patient",
        "patient_id": "patient_002",
        "clearance_level": 2,  # Internal
    },
}

SYNTHETIC_ABAC_RECORDS = {
    "record_001": {
        "patient_id": "patient_001",
        "department": "Cardiology",
        "sensitivity_level": 3,  # Confidential
    },
    "record_002": {
        "patient_id": "patient_002",
        "department": "Pediatrics",
        "sensitivity_level": 2,  # Internal
    },
    "record_003_restricted": {
        "patient_id": "patient_001",
        "department": "Cardiology",
        "sensitivity_level": 4,  # Restricted
    },
}


def check_abac_access_by_id(
    user_id: str,
    record_id: str,
    action: str,
    environment_attributes: Dict[str, Any],
    user_catalog: Optional[Dict[str, Any]] = None,
    record_catalog: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Convenience wrapper that resolves user and record attributes by ID from
    a test catalog and delegates the decision to check_abac_access.
    """
    if user_catalog is None:
        user_catalog = SYNTHETIC_ABAC_USERS
    if record_catalog is None:
        record_catalog = SYNTHETIC_ABAC_RECORDS

    if not isinstance(user_id, str) or not isinstance(record_id, str):
        return False

    user_attrs = user_catalog.get(user_id.strip())
    record_attrs = record_catalog.get(record_id.strip())

    if user_attrs is None or record_attrs is None:
        return False

    return check_abac_access(user_attrs, record_attrs, action, environment_attributes)

