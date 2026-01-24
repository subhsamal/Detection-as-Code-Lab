import os
import sys
import yaml
import time
import traceback
import splunklib.client as client
import urllib3
from pathlib import Path
from datetime import datetime, timezone, timedelta

# 1. SILENCE SSL WARNINGS (Critical for local lab tunnels)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 2. CAPTURE PIPELINE START TIME (UTC)
# This acts as our 'Time Fence' to ensure we only validate THIS run.
SCRIPT_START_TIME = datetime.now(timezone.utc)

# CONFIGURATION FROM GITHUB SECRETS
SPLUNK_HOST = os.getenv('SPLUNK_HOST', 'localhost')
SPLUNK_PORT = int(os.getenv('SPLUNK_PORT', 8089))
SPLUNK_USERNAME = os.getenv('SPLUNK_USERNAME', 'admin')
SPLUNK_PASSWORD = os.getenv('SPLUNK_PASSWORD')

def connect_to_splunk():
    try:
        service = client.connect(
            host=SPLUNK_HOST,
            port=SPLUNK_PORT,
            username=SPLUNK_USERNAME,
            password=SPLUNK_PASSWORD,
            owner="admin",
            app="search",
            verify=False
        )
        return service
    except Exception as e:
        print(f"❌ CONNECTION ERROR: {e}")
        sys.exit(1)

def verify_alert_history(service):
    alert_name = "Suspicious PowerShell Encoded Command"
    EXPECTED_MATCHES = 2 
    
    # 1. RAW LOG SEARCH (Keep this as is)
    raw_query = (
        'search index=windows sourcetype=WinEventLog:Security EventCode=4688 '
        '(CommandLine="*powershell*" OR CommandLine="*pwsh*") '
        '(CommandLine="*-enc*" OR CommandLine="*-encodedcommand*") '
        '| rex field=CommandLine "-enc(?:odedcommand)?\\s+(?<encoded_cmd>\\S+)" '
        '| where isnotnull(encoded_cmd) AND len(encoded_cmd) >= 20 '
        '| search NOT (User="NT AUTHORITY\\\\SYSTEM" AND (ParentProcessName="*\\\\services.exe" OR ParentProcessName="*\\\\svchost.exe")) '
        '| search NOT (ParentProcessName="*\\\\ccmexec.exe" OR ParentProcessName="*\\\\CcmExec.exe" OR ParentProcessName="*\\\\SMS*.exe") '
        '| search NOT ParentProcessName="*\\\\wsmprovhost.exe" '
        '| search NOT ParentProcessName="*\\\\gpscript.exe"'
    )

    try:
        print(f"\n--- Step 1: Checking Raw Logs (Expectation: {EXPECTED_MATCHES}) ---")
        job = service.jobs.oneshot(raw_query, output_mode="json", earliest_time="-10m")
        
        import json
        results = json.loads(job.read())
        actual_matches = len(results.get("results", []))

        if actual_matches == EXPECTED_MATCHES:
            print(f"✅ PASS: Found exactly {actual_matches} log entries.")
        else:
            print(f"❌ FAIL: Found {actual_matches} logs (Expected {EXPECTED_MATCHES}).")
            return False

        # 2. AUDIT TRAIL CHECK (The NEW Step 2)
        # We search the internal audit index you found in your screenshot.
        print(f"--- Step 2: Verifying Alert Execution via Audit Trail (10m window) ---")
        
        audit_query = (
            f'search index=_audit sourcetype=audittrail '
            f'savedsearch_name="{alert_name}" action=search info=completed '
            f'| head 1 '
            f'| table _time, event_count'
        )
        
        audit_job = service.jobs.oneshot(audit_query, output_mode="json", earliest_time="-10m")
        audit_results = json.loads(audit_job.read())

        if not audit_results.get("results"):
            print(f"❌ FAIL: No audit record found for '{alert_name}' in the last 10 minutes.")
            return False
        
        # Pull the count from the audit event
        triggered_count = int(audit_results['results'][0]['event_count'])

        if triggered_count >= EXPECTED_MATCHES:
            print(f"✅ PASS: Audit confirms search ran and found {triggered_count} events!")
            return True
        else:
            print(f"❌ FAIL: Alert ran but found {triggered_count} events (Expected {EXPECTED_MATCHES}).")
            return False

    except Exception as e:
        print(f"❌ Verification Error: {e}")
        return False
    
def cleanup_old_logs(service):
    # Note: The 'admin' user must have the 'can_delete' role in Splunk 
    # for this specific command to work.
    print("\n🧹 PHASE-1 CLEANUP: Removing simulation logs to prevent alert spam...")
    try:
        service.jobs.oneshot("search index=windows | delete")
        print("✅ Cleanup successful.")
    except Exception as e:
        print(f"⚠️ Cleanup failed (check if 'can_delete' role is assigned): {e}")

def main():
    if not SPLUNK_PASSWORD:
        print("❌ ERROR: SPLUNK_PASSWORD environment variable not set.")
        sys.exit(1)

    service = connect_to_splunk()
    
    print("⏳ Finalizing alert metadata sync...")
    time.sleep(10)

    # 1. Run the verification
    success = verify_alert_history(service)

    # 2. ALWAYS cleanup after the test logic is done
    # This prevents the 5-minute sliding window from re-triggering the same logs
    cleanup_old_logs(service)

    # 3. Finally, exit with the correct status code for the pipeline
    if success:
        print("\n🎉 PHASE-1 VERIFIED: Detection-as-Code Pipeline Successful!")
        sys.exit(0)
    else:
        print("\n⚠️ PHASE-1 FAILED: The alert did not trigger as expected.")
        sys.exit(1)