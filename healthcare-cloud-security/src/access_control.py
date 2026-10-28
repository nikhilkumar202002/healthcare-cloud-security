
"""
Healthcare Cloud Access Control
Step 3: Trusted test-user lookup, RBAC and ownership checks.

Learning prototype only.
Uses synthetic test data and does not provide real authentication.
"""

try:
    from src.healthcare_data import TEST_USERS, SYNTHETIC_RECORDS
except ImportError:
    from healthcare_data import TEST_USERS, SYNTHETIC_RECORDS

# Role-Based Access Control (RBAC) rules.
ROLE_PERMISSIONS = {
    "doctor": {"read", "update"},
    "nurse": {"read"},
    "admin": {"read", "upload", "delete"},
    "patient": {"read"},
}


def get_trusted_user(user_id: str):
    """
    Return a registered test user's details.
    Unknown or invalid user IDs return None.
    """
    if not isinstance(user_id, str):
        return None

    user_id = user_id.strip()

    if not user_id:
        return None

    # The role comes from the registry, not from the request.
    return TEST_USERS.get(user_id)


def check_access(user_id: str, action: str, record_id: str) -> bool:
    """
    Check whether a registered test user may perform an action
    on a synthetic healthcare record.

    Returns True if access is allowed, otherwise False.
    """

    # 1. Reject invalid input.
    if not all(isinstance(value, str) for value in
               (user_id, action, record_id)):
        return False

    user_id = user_id.strip()
    action = action.strip().lower()
    record_id = record_id.strip()

    if not user_id or not action or not record_id:
        return False

    # 2. Look up the registered user.
    user = get_trusted_user(user_id)

    if user is None:
        return False

    role = user["role"]

    # 3. Check whether the record exists.
    record = SYNTHETIC_RECORDS.get(record_id)

    if record is None:
        return False

    # 4. Check RBAC permissions.
    allowed_actions = ROLE_PERMISSIONS.get(role, set())

    if action not in allowed_actions:
        return False

    # 5. Enforce ownership for patient accounts.
    if role == "patient":
        if action != "read":
            return False

        if user["patient_id"] != record["owner_patient_id"]:
            return False

    # All applicable checks passed.
    return True
