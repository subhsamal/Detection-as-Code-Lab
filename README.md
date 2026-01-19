# Detection-as-Code: Automated Splunk Alert Pipeline

## 1. Project Overview
This project implements a full **Detection-as-Code (DaC)** lifecycle. It automates the process of defining security detections in YAML, validating them via Python, and deploying them to a containerized Splunk Enterprise instance using the Splunk REST API.

---

## 2. Environment & Workspace Setup
The project was built on an **Intel-based macOS** environment using the following configuration:

* **Project Structure:**
    * `detections/`: Directory for YAML-based detection rules.
    * `scripts/`: Python logic for validation and deployment.
    * `.venv/`: Isolated Python virtual environment.
* **Dependency Management:** Used `pip` to install `PyYAML` for parsing and `splunk-sdk` for SIEM interaction.
* **Infrastructure:** **Docker Desktop** was used to host Splunk, with manual resource allocation tuned to **4GB RAM** to ensure service stability.

---

## 3. Phase 1: Detection Engineering (YAML)
We authored a detection rule for **Suspicious PowerShell Encoded Commands**. By using YAML, we separated the detection logic from the platform, making the rule portable and version-controllable.

* **File:** `detections/suspicious_powershell.yml`
* **Logic:** Detects the use of `-EncodedCommand` or `-e` flags in PowerShell, a common technique for obfuscating malicious scripts.

---

## 4. Phase 2: Automated Validation
To prevent "broken" rules from reaching production, we implemented a **CI (Continuous Integration)** check.

* **Script:** `validate_detection.py`
* **Function:** This script programmatically verifies that the YAML follows the required schema, checking for mandatory fields like `name`, `search`, and `cron_schedule`.

---

## 5. Phase 3: SIEM Orchestration (Docker)
We deployed Splunk Enterprise using Docker. This stage involved overcoming two critical technical hurdles:

1. **Shell Syntax & Quoting:** Resolved a `dquote>` hanging prompt caused by the Zsh terminal misinterpreting the `!` character in the Splunk password. Fixed by using **single quotes** (`' '`) to encapsulate environment variables.
2. **License Compliance:** Addressed a container crash issue by identifying and adding the `SPLUNK_GENERAL_TERMS` flag, a mandatory requirement for starting modern Splunk Docker images.

**Final Deployment Command:**
```bash
docker run -d -p 8000:8000 -p 8089:8089 \
  -e 'SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com' \
  -e 'SPLUNK_START_ARGS=--accept-license' \
  -e 'SPLUNK_PASSWORD=ComplexPassword123!' \
  --name splunk_lab \
  splunk/splunk:latest
```

---

## 6. Phase 4: Programmatic Code Push
The final stage used the Splunk SDK for Python to bridge the gap between local code and the live SIEM.

* **Script:** `deploy_to_splunk.py`
* **Key Library:** `splunk-sdk` (installed via pip).
* **Mechanism:**
   * **Parsing:** The script reads the validated YAML file from the `detections/` folder.
   * **Connectivity:** Establishes a secure connection to the Splunk Management API via port 8089.
   * **Idempotency:** The script checks if the search already exists. If found, it deletes the old version to perform an update; otherwise, it creates a new "Saved Search."
   * **Deployment:** It pushes the specific search query and cron schedule defined in the YAML directly into the Splunk engine.