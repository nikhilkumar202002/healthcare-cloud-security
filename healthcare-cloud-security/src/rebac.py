
from typing import Any, Dict, Optional

# Attempt import from existing project data module
try:
    from src.healthcare_data import TEST_USERS, SYNTHETIC_RECORDS
except ImportError:
    try:
        from healthcare_data import TEST_USERS, SYNTHETIC_RECORDS
    except ImportError:
        TEST_USERS = {}
        SYNTHETIC_RECORDS = {}
SYNTHETIC_RELATIONSHIPS = {
    "patient_001": {
        "doctor_ids": ["doctor_001"],
        "nurse_ids": ["nurse_001"],
    },
    "patient_002": {
        "doctor_ids": [],  # No doctor is assigned to patient_002
        "nurse_ids": ["nurse_001"],  # nurse_001 is on both care teams
    },
}

# Combine or provide fallback for users
SYNTHETIC_REBAC_USERS = {
    **TEST_USERS,
    "doctor_002": {
        "role": "doctor",
        "patient_id": None,
    },
}

# Valid actions allowed in this prototype
ALLOWED_ACTIONS = {"read", "update"}


def get_trusted_user(user_id: Any, user_store: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """
    Look up a registered user from a trusted registry.
    Returns None if user_id is missing, invalid, or not found.
    Relationship checks must never trust unauthenticated or unknown users.
    """
    if user_store is None:
        user_store = SYNTHETIC_REBAC_USERS

    if not isinstance(user_id, str):
        return None

    cleaned_id = user_id.strip()
    if not cleaned_id:
        return None

    return user_store.get(cleaned_id)


def resolve_patient_id(
    target_id: Any,
    record_store: Optional[Dict[str, Any]] = None,
    relationship_store: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """
    Resolve a target identifier (either a record_id like 'record_001'
    or a patient_id like 'patient_001') to a verified patient_id.

    Returns the patient_id string, or None if the target cannot be resolved.
    """
    if record_store is None:
        record_store = SYNTHETIC_RECORDS
    if relationship_store is None:
        relationship_store = SYNTHETIC_RELATIONSHIPS

    if not isinstance(target_id, str):
        return None

    cleaned_target = target_id.strip()
    if not cleaned_target:
        return None

    # Case A: target_id is directly a record_id in the record store
    if cleaned_target in record_store:
        record = record_store[cleaned_target]
        patient_id = record.get("owner_patient_id") or record.get("patient_id")
        if isinstance(patient_id, str) and patient_id.strip():
            return patient_id.strip()

    # Case B: target_id is already a patient_id existing in the relationship store
    if cleaned_target in relationship_store:
        return cleaned_target

    # Target could not be resolved to any existing patient
    return None


def is_doctor_assigned(
    doctor_id: str,
    patient_id: str,
    relationship_store: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Check if a doctor has an active assignment relationship with the patient.
    """
    if relationship_store is None:
        relationship_store = SYNTHETIC_RELATIONSHIPS

    patient_rel = relationship_store.get(patient_id)
    if not isinstance(patient_rel, dict):
        return False

    assigned_doctors = patient_rel.get("doctor_ids", [])
    if not isinstance(assigned_doctors, (list, set, tuple)):
        return False

    normalized_doctors = {str(d).strip().lower() for d in assigned_doctors if isinstance(d, str)}
    return doctor_id.strip().lower() in normalized_doctors


def is_nurse_in_care_team(
    nurse_id: str,
    patient_id: str,
    relationship_store: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Check if a nurse has a care-team relationship with the patient.
    """
    if relationship_store is None:
        relationship_store = SYNTHETIC_RELATIONSHIPS

    patient_rel = relationship_store.get(patient_id)
    if not isinstance(patient_rel, dict):
        return False

    care_team_nurses = patient_rel.get("nurse_ids", [])
    if not isinstance(care_team_nurses, (list, set, tuple)):
        return False

    normalized_nurses = {str(n).strip().lower() for n in care_team_nurses if isinstance(n, str)}
    return nurse_id.strip().lower() in normalized_nurses


def check_rebac_access(
    user_id: Any,
    action: Any,
    target_id: Any,
    user_store: Optional[Dict[str, Any]] = None,
    relationship_store: Optional[Dict[str, Any]] = None,
    record_store: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Evaluate a Relationship-Based Access Control (ReBAC) request.

    Parameters:
      user_id (str): The ID of the user requesting access (e.g. 'doctor_001').
      action (str): The requested operation ('read' or 'update').
      target_id (str): The resource target (either 'record_001' or 'patient_001').
      user_store (dict, optional): Trusted registry of user records.
      relationship_store (dict, optional): Authoritative relationship mapping.
      record_store (dict, optional): Registry of healthcare records.

    Returns:
      bool: True if access is permitted by an authorized relationship;
            False otherwise (Fail-Closed).
    """

    # -------------------------------------------------------------------------
    # STEP 1: Input Validation (Fail-Closed)
    # -------------------------------------------------------------------------
    if not isinstance(user_id, str) or not isinstance(action, str) or not isinstance(target_id, str):
        return False

    clean_user_id = user_id.strip()
    clean_action = action.strip().lower()
    clean_target_id = target_id.strip()

    if not clean_user_id or not clean_action or not clean_target_id:
        return False

    if clean_action not in ALLOWED_ACTIONS:
        return False

    # -------------------------------------------------------------------------
    # STEP 2: Authenticate and Identify the User
    # -------------------------------------------------------------------------
    user = get_trusted_user(clean_user_id, user_store=user_store)
    if user is None:
        return False

    role = user.get("role")
    if not isinstance(role, str):
        return False
    role = role.strip().lower()

    # -------------------------------------------------------------------------
    # STEP 3: Resolve the Target Resource to a Patient ID
    # -------------------------------------------------------------------------
    patient_id = resolve_patient_id(
        clean_target_id,
        record_store=record_store,
        relationship_store=relationship_store,
    )
    if patient_id is None:
        return False

    # Verify that the patient has a registered relationship entry
    if relationship_store is None:
        relationship_store = SYNTHETIC_RELATIONSHIPS

    if patient_id not in relationship_store:
        return False

    # -------------------------------------------------------------------------
    # STEP 4: Evaluate Relationship Rules Based on User Role
    # -------------------------------------------------------------------------

    # RULE 1: Doctor Relationship
    # - Assigned doctor can read or update the patient's record
    # - Unassigned doctor is denied access
    if role == "doctor":
        if clean_action not in {"read", "update"}:
            return False

        if not is_doctor_assigned(clean_user_id, patient_id, relationship_store):
            return False

        return True

    # RULE 2: Nurse Care-Team Relationship
    # - Nurse can read if they belong to the patient's care team
    # - Nurse cannot update records
    elif role == "nurse":
        if clean_action != "read":
            return False

        if not is_nurse_in_care_team(clean_user_id, patient_id, relationship_store):
            return False

        return True

    # RULE 3: Patient Self-Ownership Relationship
    # - Patient can read only their own record
    # - Patient cannot update clinical records
    elif role == "patient":
        if clean_action != "read":
            return False

        user_patient_id = user.get("patient_id")
        if not isinstance(user_patient_id, str):
            return False

        if user_patient_id.strip().lower() != patient_id.lower():
            return False

        return True

    # All other roles or unknown users are denied
    return False
