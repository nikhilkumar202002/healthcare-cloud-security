# Comparative Evaluation Report: RBAC, ABAC, and ReBAC for Healthcare Cloud Data Security

**Degree Programme:** MSc Cyber Security  
**Project Title:** Access Controls for Cloud Data: Implementation & Analysis  
**Date of Evaluation:** November 2026  
**Environment:** macOS (Darwin), Python 3.15.2, pytest 9.2.0, VS Code  

---

## 1. Introduction

Access control mechanisms constitute the primary defense boundary protecting sensitive electronic Protected Health Information (ePHI) in cloud storage environments. Regulatory standards such as the Health Insurance Portability and Accountability Act (HIPAA) and the EU General Data Protection Regulation (GDPR) require healthcare organizations to enforce strict access governance, data segregation, and the principle of least privilege.

This report presents a comparative evaluation of three access control models implemented for a synthetic healthcare cloud security system:
1. **Role-Based Access Control (RBAC)**
2. **Attribute-Based Access Control (ABAC)**
3. **Relationship-Based Access Control (ReBAC)**

The evaluation is based on actual, measured evidence gathered from running reproducible test scenarios and benchmarking execution latencies on local Python prototypes.

---

## 2. Evaluation Objectives

The evaluation is designed to answer the two primary MSc research questions:

1. **Research Question 1 (RQ1):** *How can RBAC, ABAC and ReBAC be implemented to ensure secure and authorised access to sensitive healthcare data in a cloud environment?*
2. **Research Question 2 (RQ2):** *Which of the three access-control models provides the best balance of security, flexibility, complexity, and performance for protecting healthcare data in the cloud?*

Specific criteria examined include:
- **Security:** Granularity of authorization, protection against Broken Object Level Authorization (BOLA / IDOR), least privilege enforcement, and default-deny (fail-closed) behavior.
- **Flexibility:** Policy adaptability to complex clinical constraints (department scoping, time-of-day limits, access purpose).
- **Complexity:** Implementation overhead, policy maintenance burden, and the risk of role explosion.
- **Performance:** Decision evaluation latency measured in microseconds ($\mu\text{s}$) across identical workloads.
- **Scalability:** Computational and administrative scaling behavior when expanding users, records, and relationships.

---

## 3. Testing Methodology

### 3.1 Benchmark Design
- **High-Resolution Timing:** Measurements were gathered using Python's monotonic high-precision timer `time.perf_counter()`.
- **Mitigating Noise:** Each test scenario executed **10,000 iterations** following **500 warm-up cycles** to ensure bytecode compilation and CPU cache stabilization.
- **Isolated Decision Logic:** File I/O, console printing, and network communications were strictly excluded from timed code blocks to isolate pure policy decision overhead.
- **Benchmarking Script:** Automated via `evaluation/compare_models.py` and exported directly to `evaluation/evaluation_results.csv`.

---

## 4. Test Scenarios

The evaluation evaluated eight realistic clinical scenarios against synthetic healthcare entities:

1. **Scenario 1:** Assigned doctor (`doctor_001`) reads an assigned patient's record (`record_001`).
2. **Scenario 2:** Unassigned doctor (`doctor_001`) attempts to read another patient's record (`record_002`).
3. **Scenario 3:** Assigned care-team nurse (`nurse_001`) reads a patient's record (`record_001`).
4. **Scenario 4:** Nurse (`nurse_001`) attempts an unauthorized `update` on a patient's record (`record_001`).
5. **Scenario 5:** Patient (`patient_alice`) reads their own healthcare record (`record_001`).
6. **Scenario 6:** Patient (`patient_alice`) attempts cross-patient access to another patient's record (`record_002`).
7. **Scenario 7:** User with insufficient security clearance (Clearance 2 / Internal) attempts to access a Confidential record (Sensitivity 3).
8. **Scenario 8:** System administrator (`admin_001`) attempts to read a clinical record without an explicit `audit` purpose.

---

## 5. Empirical Results

The empirical results generated from running the evaluation suite (`compare_models.py`) are presented below:

| ID | Scenario Description | RBAC Decision | RBAC Latency ($\mu\text{s}$) | ABAC Decision | ABAC Latency ($\mu\text{s}$) | ReBAC Decision | ReBAC Latency ($\mu\text{s}$) |
|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **1** | Assigned doctor reads patient record | **ALLOWED** | 0.386 | **ALLOWED** | 1.344 | **ALLOWED** | 0.501 |
| **2** | Unassigned doctor attempts access | **ALLOWED** *(Security Gap)* | 0.356 | **DENIED** | 1.231 | **DENIED** | 0.417 |
| **3** | Assigned nurse reads patient record | **ALLOWED** | 0.328 | **ALLOWED** | 1.213 | **ALLOWED** | 0.451 |
| **4** | Nurse attempts to update record | **DENIED** | 0.322 | **DENIED** | 0.860 | **DENIED** | 0.292 |
| **5** | Patient reads own record | **ALLOWED** | 0.343 | **ALLOWED** | 0.960 | **ALLOWED** | 0.346 |
| **6** | Patient attempts cross-patient access (BOLA) | **DENIED** | 0.351 | **DENIED** | 0.953 | **DENIED** | 0.352 |
| **7** | Insufficient security clearance | **N/A** | N/A | **DENIED** | 0.685 | **N/A** | N/A |
| **8** | Administrator access without audit purpose | **ALLOWED** *(Coarse-Grained)* | 0.326 | **DENIED** | 0.877 | **DENIED** | 0.296 |

---

## 6. Performance Comparison

### Average Policy Evaluation Latency (per decision)
- **RBAC:** **0.345 $\mu\text{s}$** ($0.00035\text{ ms}$)
- **ReBAC:** **0.379 $\mu\text{s}$** ($0.00038\text{ ms}$)
- **ABAC:** **1.015 $\mu\text{s}$** ($0.00102\text{ ms}$)

### Analysis of Latency
1. **RBAC is the fastest:** Because RBAC relies solely on an internal dictionary and set lookup (`action in ROLE_PERMISSIONS[role]`), its execution overhead is minimal.
2. **ReBAC exhibits near-RBAC speed:** In-memory graph checks (`doctor_id in relationships[patient_id]["doctor_ids"]`) require only hash table key lookups, incurring just **0.034 $\mu\text{s}$** of additional overhead compared to RBAC.
3. **ABAC exhibits higher overhead (~2.9x slower than RBAC):** ABAC evaluates multiple logical predicates: parsing time strings, normalizing numeric clearance levels, verifying department string equality, checking list membership, and validating purpose keywords. 
4. **Cloud Contextualization:** In a local Python environment, all three models execute in approximately 1 microsecond. When deployed to a cloud environment (e.g., AWS S3 and DynamoDB), policy evaluation latency is dwarfed by network round-trip time (5–50 ms). However, in high-throughput cloud API gateways handling tens of thousands of requests per second, microsecond differences accumulate.

---

## 7. Security Comparison

| Security Dimension | RBAC | ABAC | ReBAC |
|:---|:---|:---|:---|
| **Granularity** | Coarse-grained (Role-wide). | Highly fine-grained (Multi-attribute). | Relation-specific (Entity-to-entity). |
| **BOLA / IDOR Prevention** | Weak for staff; effective for patients only if custom ownership checks exist. | Strong (Checks department, patient ID, and assignments). | Strong (Enforces explicit relationship edges). |
| **Contextual Awareness** | None (Static role evaluation). | High (Evaluates access time and declared purpose). | Low to None (Evaluates relationship existence). |
| **Data Classification** | None (Treats all records identically). | Strong (Enforces clearance $\ge$ sensitivity). | None (Focuses on graph connectivity). |
| **Least Privilege Enforcement** | Limited (Doctor can read any patient's record in the hospital). | High (Access restricted to assigned records, matching department, and shift hours). | High (Access restricted strictly to assigned care-team patients). |

### Key Security Finding (Scenario 2):
In traditional RBAC, `doctor_001` is granted read access to `record_002` (belonging to unassigned `patient_002`) because the role permission `doctor -> read` is global. This demonstrates the primary vulnerability of coarse-grained RBAC in healthcare: it cannot distinguish between *a patient under my care* and *any patient in the hospital*. Both **ABAC** and **ReBAC** successfully resolve this vulnerability.

---

## 8. Flexibility Comparison

- **RBAC (Low Flexibility):** Adding granular rules (such as distinguishing cardiology doctors from pediatric doctors) requires creating new roles (`CardiologyDoctor`, `PediatricDoctor`), directly leading to **Role Explosion**.
- **ABAC (High Flexibility):** Highly expressive. Contextual conditions such as emergency override, shifts (08:00–18:00), location, and purpose of access (`treatment` vs `audit`) can be added without altering the fundamental user role.
- **ReBAC (Moderate to High Flexibility):** Highly dynamic for collaborative, team-based access. Reassigning a patient to a new doctor or adding consulting nurses is accomplished by simply creating a new graph relationship, requiring zero policy alterations.

---

## 9. Complexity Comparison

- **RBAC (Low Complexity):** Straightforward to implement and audit. Roles and permissions can be audited using a simple 2D matrix. However, managing hundreds of specialized roles in a large hospital becomes unsustainable.
- **ABAC (High Complexity):** High implementation and governance complexity. Attribute stores must remain synchronized across identity providers (IdP) and electronic health record (EHR) systems. Policy rule conflicts and auditing boolean policy combinations can become difficult to debug.
- **ReBAC (Moderate Complexity):** Conceptual modeling requires representing relationships as directed graph edges. Simple relationship lookups are easy to manage; however, hierarchical graph traversals (e.g. *hospital $\rightarrow$ department $\rightarrow$ unit $\rightarrow$ care team $\rightarrow$ patient*) require specialized graph databases or Zanzibar-like index services (such as OpenFGA or AWS Verified Permissions).

---

## 10. Scalability Discussion

- **Local Prototype Scalability:** In our Python prototype, in-memory lookups scale at $O(1)$ for RBAC and ReBAC, and $O(K)$ where $K$ is the number of evaluated attributes for ABAC.
- **Cloud Scale Challenges:**
  - **RBAC:** Scales poorly administratively as organizational hierarchy grows.
  - **ABAC:** Scales well across diverse access conditions, but policy decision points (PDP) can become a computational bottleneck if policies require distributed attribute retrieval from multiple microservices.
  - **ReBAC:** Scales exceptionally well for decentralized, collaborative cloud applications, but deep relationship graph traversals require optimized caching and indexing infrastructure.

---

## 11. Limitations

1. **Local Prototype Timing vs Cloud Latency:** All benchmarks were measured on a local macOS environment using in-memory synthetic Python data structures. Real-world cloud deployments incur network latency, database query overhead (e.g., Amazon DynamoDB, AWS IAM, AWS S3), and authentication validation (e.g., OAuth2/OIDC JWT tokens).
2. **Synthetic Data Scope:** The prototype utilizes a controlled dataset of synthetic users and records. Production EHR systems contain millions of historical records and complex delegation trees.
3. **No Active Cloud Infrastructure:** AWS integration (S3 bucket policies, IAM role assumptions, boto3 API calls) has not yet been executed and forms the planned subsequent stage of the research project.

---

## 12. Conclusion

This comparative evaluation produces concrete empirical evidence addressing the core research questions:

1. **Answering RQ1 (Implementation):**
   - RBAC is suitable for baseline, administrative boundaries where coarse-grained permissions suffice.
   - ABAC provides the necessary contextual expressiveness required for healthcare compliance (enforcing data sensitivity, access hours, and clinical purpose).
   - ReBAC delivers direct, natural modeling of clinical care-team relationships, eliminating BOLA vulnerabilities without role explosion.

2. **Answering RQ2 (Optimal Balance):**
   - **No single model is universally superior in isolation.**
   - While **RBAC** is computationally fastest (0.345 $\mu\text{s}$), it fails to prevent unauthorized cross-patient staff access.
   - **ABAC** provides the most rigorous security and context governance, but incurs the highest computational latency (1.015 $\mu\text{s}$) and administrative overhead.
   - **ReBAC** strikes an outstanding balance between execution speed (0.379 $\mu\text{s}$) and relationship-targeted access enforcement.
   - **Recommendation for Cloud Healthcare:** A **hybrid access control architecture**—combining ReBAC for relationship-driven patient-caregiver authorization with ABAC for environmental context (time, purpose) and sensitivity classification—represents the most effective security posture for cloud-hosted healthcare systems.

