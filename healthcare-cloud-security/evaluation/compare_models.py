"""
Comparative Evaluation Program: RBAC vs ABAC vs ReBAC
MSc Cyber Security Research: "Access Controls for Cloud Data: Implementation & Analysis"

This script performs:
1. Functional Scenario Testing: Evaluates 8 healthcare access scenarios across
   all three models (RBAC, ABAC, ReBAC) using synthetic test records.
2. Precision Benchmarking: Measures policy evaluation execution time (latency)
   in microseconds (μs) using time.perf_counter() with warm-up cycles.
3. Summary & Reporting: Prints a formatted console comparison and exports
   the empirical findings to 'evaluation/evaluation_results.csv'.

Important Research Notice:
This evaluation measures local Python prototype execution latency.
Local Python timing does NOT reflect network latency or AWS cloud database lookups.
"""

import csv
import os
import sys
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

# Safely import the three access control models without modifying existing files
try:
    from src.access_control import check_access as rbac_check
except ImportError:
    from access_control import check_access as rbac_check

try:
    from src.abac import check_abac_access as abac_check
except ImportError:
    from abac import check_abac_access as abac_check

try:
    from src.rebac import check_rebac_access as rebac_check
except ImportError:
    from rebac import check_rebac_access as rebac_check

# Number of benchmarking iterations and warmup cycles
BENCHMARK_ITERATIONS = 10_000
WARMUP_CYCLES = 500


def measure_execution_time(func, *args, iterations=BENCHMARK_ITERATIONS, warmup=WARMUP_CYCLES):
    """
    Measure the average execution time of an access control decision function.
    
    Steps:
      1. Run warmup iterations to allow Python bytecode optimization and CPU cache warm-up.
      2. Record start time using high-resolution time.perf_counter().
      3. Execute the function repeatedly.
      4. Record end time and compute mean latency per decision in microseconds (μs).
    """
    for _ in range(warmup):
        func(*args)

    start_time = time.perf_counter()
    for _ in range(iterations):
        func(*args)
    end_time = time.perf_counter()

    avg_time_seconds = (end_time - start_time) / iterations
    return avg_time_seconds * 1_000_000  # Return microseconds (μs)


# -----------------------------------------------------------------------------
# Synthetic Data Setup for Scenarios
# -----------------------------------------------------------------------------
# ABAC attributes
ABAC_DOCTOR_ASSIGNED = {
    "role": "doctor",
    "department": "Cardiology",
    "assigned_patient_ids": ["patient_001"],
    "clearance_level": 3,  # Confidential
}

ABAC_DOCTOR_UNASSIGNED = {
    "role": "doctor",
    "department": "Cardiology",
    "assigned_patient_ids": ["patient_999"],  # Not assigned to patient_001
    "clearance_level": 3,
}

ABAC_DOCTOR_LOW_CLEARANCE = {
    "role": "doctor",
    "department": "Cardiology",
    "assigned_patient_ids": ["patient_001"],
    "clearance_level": 2,  # Level 2 (Internal) < Level 3 (Confidential)
}

ABAC_NURSE_ASSIGNED = {
    "role": "nurse",
    "department": "Cardiology",
    "assigned_patient_ids": ["patient_001"],
    "clearance_level": 3,
}

ABAC_PATIENT_ALICE = {
    "role": "patient",
    "patient_id": "patient_001",
    "clearance_level": 3,
}

ABAC_ADMIN = {
    "role": "admin",
    "clearance_level": 4,  # High clearance
}

ABAC_RECORD_001 = {
    "patient_id": "patient_001",
    "department": "Cardiology",
    "sensitivity_level": 3,  # Confidential
}

ABAC_RECORD_002 = {
    "patient_id": "patient_002",
    "department": "Pediatrics",
    "sensitivity_level": 2,  # Internal
}

ABAC_ENV_TREATMENT_VALID = {
    "access_time": "10:30",
    "purpose": "treatment",
}

ABAC_ENV_ADMIN_TREATMENT = {
    "access_time": "10:30",
    "purpose": "treatment",  # Admin can only access for audit
}


def run_evaluation():
    """
    Execute all 8 comparative evaluation scenarios across RBAC, ABAC, and ReBAC.
    """
    print("=" * 80)
    print("MSc Cyber Security: Access Controls for Cloud Data - Comparative Evaluation")
    print("Comparing: RBAC (Role-Based), ABAC (Attribute-Based), ReBAC (Relationship-Based)")
    print(f"Timing Benchmarks: {BENCHMARK_ITERATIONS:,} iterations (with {WARMUP_CYCLES} warm-up cycles)")
    print("=" * 80)

    scenarios = [
        {
            "id": 1,
            "name": "Assigned doctor reads patient record",
            "rbac": {
                "applicable": True,
                "func": lambda: rbac_check("doctor_001", "read", "record_001"),
                "expected": "ALLOWED",
                "notes": "Doctor role has read permission in RBAC table.",
            },
            "abac": {
                "applicable": True,
                "func": lambda: abac_check(ABAC_DOCTOR_ASSIGNED, ABAC_RECORD_001, "read", ABAC_ENV_TREATMENT_VALID),
                "expected": "ALLOWED",
                "notes": "Matches role, dept, assigned ID, clearance, hours, purpose.",
            },
            "rebac": {
                "applicable": True,
                "func": lambda: rebac_check("doctor_001", "read", "record_001"),
                "expected": "ALLOWED",
                "notes": "Direct assignment relationship exists (doctor_001 in patient_001.doctor_ids).",
            },
        },
        {
            "id": 2,
            "name": "Unassigned doctor attempts access",
            "rbac": {
                "applicable": True,
                "func": lambda: rbac_check("doctor_001", "read", "record_002"),
                "expected": "ALLOWED",
                "notes": "LIMITATION: Traditional RBAC role permits read across all records.",
            },
            "abac": {
                "applicable": True,
                "func": lambda: abac_check(ABAC_DOCTOR_UNASSIGNED, ABAC_RECORD_001, "read", ABAC_ENV_TREATMENT_VALID),
                "expected": "DENIED",
                "notes": "Denied: Patient ID not in assigned_patient_ids attribute.",
            },
            "rebac": {
                "applicable": True,
                "func": lambda: rebac_check("doctor_001", "read", "record_002"),
                "expected": "DENIED",
                "notes": "Denied: No relationship edge between doctor_001 and patient_002.",
            },
        },
        {
            "id": 3,
            "name": "Assigned nurse reads patient record",
            "rbac": {
                "applicable": True,
                "func": lambda: rbac_check("nurse_001", "read", "record_001"),
                "expected": "ALLOWED",
                "notes": "Nurse role permits read in RBAC table.",
            },
            "abac": {
                "applicable": True,
                "func": lambda: abac_check(ABAC_NURSE_ASSIGNED, ABAC_RECORD_001, "read", ABAC_ENV_TREATMENT_VALID),
                "expected": "ALLOWED",
                "notes": "Nurse matches dept, assignment, clearance, hours, purpose.",
            },
            "rebac": {
                "applicable": True,
                "func": lambda: rebac_check("nurse_001", "read", "record_001"),
                "expected": "ALLOWED",
                "notes": "nurse_001 is a verified member of patient_001 care team.",
            },
        },
        {
            "id": 4,
            "name": "Nurse attempts to update patient record",
            "rbac": {
                "applicable": True,
                "func": lambda: rbac_check("nurse_001", "update", "record_001"),
                "expected": "DENIED",
                "notes": "Nurse role does not have update permission in RBAC table.",
            },
            "abac": {
                "applicable": True,
                "func": lambda: abac_check(ABAC_NURSE_ASSIGNED, ABAC_RECORD_001, "update", ABAC_ENV_TREATMENT_VALID),
                "expected": "DENIED",
                "notes": "ABAC rule strictly restricts nurses to read action only.",
            },
            "rebac": {
                "applicable": True,
                "func": lambda: rebac_check("nurse_001", "update", "record_001"),
                "expected": "DENIED",
                "notes": "Care-team relation grants read-only; update denied.",
            },
        },
        {
            "id": 5,
            "name": "Patient reads own healthcare record",
            "rbac": {
                "applicable": True,
                "func": lambda: rbac_check("patient_alice", "read", "record_001"),
                "expected": "ALLOWED",
                "notes": "Alice owns record_001 (ownership check passes).",
            },
            "abac": {
                "applicable": True,
                "func": lambda: abac_check(ABAC_PATIENT_ALICE, ABAC_RECORD_001, "read", ABAC_ENV_TREATMENT_VALID),
                "expected": "ALLOWED",
                "notes": "Patient ID attribute matches record owner patient ID.",
            },
            "rebac": {
                "applicable": True,
                "func": lambda: rebac_check("patient_alice", "read", "record_001"),
                "expected": "ALLOWED",
                "notes": "Direct self-ownership relationship verified.",
            },
        },
        {
            "id": 6,
            "name": "Patient attempts cross-patient access (BOLA/IDOR)",
            "rbac": {
                "applicable": True,
                "func": lambda: rbac_check("patient_alice", "read", "record_002"),
                "expected": "DENIED",
                "notes": "Alice does not own record_002 (Bob owns it).",
            },
            "abac": {
                "applicable": True,
                "func": lambda: abac_check(ABAC_PATIENT_ALICE, ABAC_RECORD_002, "read", ABAC_ENV_TREATMENT_VALID),
                "expected": "DENIED",
                "notes": "Denied: Alice patient_id does not match record_002 patient_id.",
            },
            "rebac": {
                "applicable": True,
                "func": lambda: rebac_check("patient_alice", "read", "record_002"),
                "expected": "DENIED",
                "notes": "Denied: No relationship edge between Alice and patient_002.",
            },
        },
        {
            "id": 7,
            "name": "User has insufficient security clearance",
            "rbac": {
                "applicable": False,
                "func": None,
                "expected": "N/A",
                "notes": "NOT APPLICABLE: Traditional RBAC does not evaluate security clearance.",
            },
            "abac": {
                "applicable": True,
                "func": lambda: abac_check(ABAC_DOCTOR_LOW_CLEARANCE, ABAC_RECORD_001, "read", ABAC_ENV_TREATMENT_VALID),
                "expected": "DENIED",
                "notes": "Denied: Doctor clearance (2) < Record sensitivity (3).",
            },
            "rebac": {
                "applicable": False,
                "func": None,
                "expected": "N/A",
                "notes": "NOT APPLICABLE: ReBAC evaluates relationships, not clearance levels.",
            },
        },
        {
            "id": 8,
            "name": "Administrator access without audit purpose",
            "rbac": {
                "applicable": True,
                "func": lambda: rbac_check("admin_001", "read", "record_001"),
                "expected": "ALLOWED",
                "notes": "LIMITATION: RBAC admin role has blanket read; purpose is ignored.",
            },
            "abac": {
                "applicable": True,
                "func": lambda: abac_check(ABAC_ADMIN, ABAC_RECORD_001, "read", ABAC_ENV_ADMIN_TREATMENT),
                "expected": "DENIED",
                "notes": "Denied: Admin requires purpose='audit'; purpose was 'treatment'.",
            },
            "rebac": {
                "applicable": True,
                "func": lambda: rebac_check("admin_001", "read", "record_001"),
                "expected": "DENIED",
                "notes": "Denied: Admin has no clinical relationship with patient_001.",
            },
        },
    ]

    evaluation_rows = []
    rbac_latencies = []
    abac_latencies = []
    rebac_latencies = []

    print("\nExecuting Scenarios and Measuring Real Latency...\n")

    for s in scenarios:
        s_id = s["id"]
        s_name = s["name"]

        # 1. RBAC Evaluation
        rbac_info = s["rbac"]
        if rbac_info["applicable"]:
            actual_bool = rbac_info["func"]()
            rbac_actual = "ALLOWED" if actual_bool else "DENIED"
            rbac_time = measure_execution_time(rbac_info["func"])
            rbac_latencies.append(rbac_time)
            rbac_match = "YES" if rbac_actual == rbac_info["expected"] else "NO"
        else:
            rbac_actual = "N/A"
            rbac_time = 0.0
            rbac_match = "N/A"

        # 2. ABAC Evaluation
        abac_info = s["abac"]
        if abac_info["applicable"]:
            actual_bool = abac_info["func"]()
            abac_actual = "ALLOWED" if actual_bool else "DENIED"
            abac_time = measure_execution_time(abac_info["func"])
            abac_latencies.append(abac_time)
            abac_match = "YES" if abac_actual == abac_info["expected"] else "NO"
        else:
            abac_actual = "N/A"
            abac_time = 0.0
            abac_match = "N/A"

        # 3. ReBAC Evaluation
        rebac_info = s["rebac"]
        if rebac_info["applicable"]:
            actual_bool = rebac_info["func"]()
            rebac_actual = "ALLOWED" if actual_bool else "DENIED"
            rebac_time = measure_execution_time(rebac_info["func"])
            rebac_latencies.append(rebac_time)
            rebac_match = "YES" if rebac_actual == rebac_info["expected"] else "NO"
        else:
            rebac_actual = "N/A"
            rebac_time = 0.0
            rebac_match = "N/A"

        evaluation_rows.append({
            "scenario_id": s_id,
            "scenario_name": s_name,
            "rbac_decision": rbac_actual,
            "rbac_latency_us": round(rbac_time, 3) if rbac_time > 0 else "N/A",
            "rbac_notes": rbac_info["notes"],
            "abac_decision": abac_actual,
            "abac_latency_us": round(abac_time, 3) if abac_time > 0 else "N/A",
            "abac_notes": abac_info["notes"],
            "rebac_decision": rebac_actual,
            "rebac_latency_us": round(rebac_time, 3) if rebac_time > 0 else "N/A",
            "rebac_notes": rebac_info["notes"],
        })

    # Display Results in Terminal Table
    header_fmt = "{:<4} | {:<32} | {:<8} {:<10} | {:<8} {:<10} | {:<8} {:<10}"
    row_fmt    = "{:<4} | {:<32} | {:<8} {:<10} | {:<8} {:<10} | {:<8} {:<10}"

    print("-" * 105)
    print(header_fmt.format("ID", "Scenario Description", "RBAC", "Latency", "ABAC", "Latency", "ReBAC", "Latency"))
    print("-" * 105)

    for row in evaluation_rows:
        rbac_lat_str = f"{row['rbac_latency_us']} μs" if row['rbac_latency_us'] != "N/A" else "N/A"
        abac_lat_str = f"{row['abac_latency_us']} μs" if row['abac_latency_us'] != "N/A" else "N/A"
        rebac_lat_str = f"{row['rebac_latency_us']} μs" if row['rebac_latency_us'] != "N/A" else "N/A"

        print(row_fmt.format(
            row["scenario_id"],
            row["scenario_name"][:32],
            row["rbac_decision"],
            rbac_lat_str,
            row["abac_decision"],
            abac_lat_str,
            row["rebac_decision"],
            rebac_lat_str,
        ))

    print("-" * 105)

    avg_rbac = sum(rbac_latencies) / len(rbac_latencies) if rbac_latencies else 0.0
    avg_abac = sum(abac_latencies) / len(abac_latencies) if abac_latencies else 0.0
    avg_rebac = sum(rebac_latencies) / len(rebac_latencies) if rebac_latencies else 0.0

    print("\n" + "=" * 50)
    print("AVERAGE EXECUTION LATENCY (PER DECISION)")
    print("=" * 50)
    print(f"  RBAC  : {avg_rbac:.3f} μs  ({avg_rbac / 1000:.5f} ms)")
    print(f"  ABAC  : {avg_abac:.3f} μs  ({avg_abac / 1000:.5f} ms)")
    print(f"  ReBAC : {avg_rebac:.3f} μs  ({avg_rebac / 1000:.5f} ms)")
    print("=" * 50)

    # Export to CSV
    csv_file_path = PROJECT_ROOT / "evaluation" / "evaluation_results.csv"
    with open(csv_file_path, mode="w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "scenario_id",
            "scenario_name",
            "rbac_decision",
            "rbac_latency_us",
            "rbac_notes",
            "abac_decision",
            "abac_latency_us",
            "abac_notes",
            "rebac_decision",
            "rebac_latency_us",
            "rebac_notes",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in evaluation_rows:
            writer.writerow(r)

    print(f"\n[SUCCESS] Empirical evaluation results successfully exported to:\n  -> {csv_file_path}")
    return avg_rbac, avg_abac, avg_rebac, evaluation_rows


if __name__ == "__main__":
    run_evaluation()

