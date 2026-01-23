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
    """Checks Splunk metadata to prove the alert fired AND sent a webhook."""
    # Get the alert name dynamically from your YAML detection file
    root_dir = Path(__file__).resolve().parent.parent
    yaml_path = root_dir / "detections" / "suspicious_powershell.yml"

    try:
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
        
        alert_name = data.get('name')
        print(f"\n--- Starting E2E Verification for: {alert_name} ---")
        print(f"🕒 Pipeline Start Time: {SCRIPT_START_TIME.strftime('%Y-%m-%d %H:%M:%S')} UTC")

        if alert_name not in service.saved_searches:
            print(f"❌ ERROR: Alert '{alert_name}' does not exist in Splunk.")
            return False

        saved_search = service.saved_searches[alert_name]
        history = saved_search.history()
        
        # Sort history: Check most recent jobs first
        for job in sorted(history, key=lambda x: x.get("cursorTime", ""), reverse=True):
            job.refresh()
            
            # PARSE SPLUNK UTC TIME
            trigger_time_str = job["cursorTime"]
            trigger_time = datetime.fromisoformat(trigger_time_str.replace('Z', '+00:00'))
            
            # VALIDATION CRITERIA
            # 1. TEMPORAL FENCE: Happened after pipeline start (with 30s buffer for clock skew)
            is_fresh = trigger_time > (SCRIPT_START_TIME - timedelta(seconds=30))
            
            # 2. RESULTS: Job actually found the malicious logs
            result_count = int(job["resultCount"])
            
            # 3. ACTION: Splunk metadata confirms 'webhook' was triggered
            actions = job.get("alert_actions", "")
            webhook_fired = "webhook" in actions

            if is_fresh and result_count > 0 and webhook_fired:
                print(f"✅ PROVEN SUCCESS:")
                print(f"   - Trigger Time: {trigger_time} UTC")
                print(f"   - Result Count: {result_count}")
                print(f"   - Alert Actions: {actions}")
                print(f"   - Job SID: {job.sid}")
                return True
        
        print("❌ FAILED: No fresh alert with a successful webhook found in history.")
        return False

    except Exception as e:
        print(f"❌ Verification Logic Error.")
        traceback.print_exc()
        return False

def main():
    if not SPLUNK_PASSWORD:
        print("❌ ERROR: SPLUNK_PASSWORD environment variable not set.")
        sys.exit(1)

    service = connect_to_splunk()
    
    # 10s wait for Splunk API to finalize the job history metadata
    print("⏳ Finalizing alert metadata sync...")
    time.sleep(10)

    if verify_alert_history(service):
        print("\n🎉 PHASE-1 VERIFIED: Detection-as-Code Pipeline Successful!")
        sys.exit(0)
    else:
        print("\n⚠️ PHASE-1 FAILED: The alert did not trigger as expected.")
        sys.exit(1)

if __name__ == "__main__":
    main()