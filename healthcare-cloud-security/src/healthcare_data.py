
"""
Synthetic test users and healthcare record metadata.
Learning prototype only. No real patient data.
"""

TEST_USERS = {
    "doctor_001": {
        "role": "doctor",
        "patient_id": None,
    },
    "nurse_001": {
        "role": "nurse",
        "patient_id": None,
    },
    "admin_001": {
        "role": "admin",
        "patient_id": None,
    },
    "patient_alice": {
        "role": "patient",
        "patient_id": "patient_001",
    },
    "patient_bob": {
        "role": "patient",
        "patient_id": "patient_002",
    },
}

SYNTHETIC_RECORDS = {
    "record_001": {
        "owner_patient_id": "patient_001",
    },
    "record_002": {
        "owner_patient_id": "patient_002",
    },
}
