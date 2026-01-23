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
    root_dir = Path(__file__).resolve().parent.parent
    yaml_path = root_dir / "detections" / "powershell_encoded_command_execution.yml"

    try:
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
        
        alert_name = data.get('name')
        print(f"\n--- Starting E2E Verification for: {alert_name} ---")

        if alert_name not in service.saved_searches:
            print(f"❌ ERROR: Alert '{alert_name}' does not exist.")
            return False

        saved_search = service.saved_searches[alert_name]
        
        # --- FIXED LOGIC: Get history with count=1 to avoid 404 on old/expired jobs ---
        history = saved_search.history(count=1) 
        
        if not history:
            print("⚠️ No history found for this alert yet.")
            return False

        job = history[0]
        job.refresh()
        
        # PARSE TIME
        trigger_time = datetime.fromisoformat(job["cursorTime"].replace('Z', '+00:00'))
        
        # VALIDATION
        # Use a slightly wider window (2 min) to be safe against lag
        is_fresh = trigger_time > (SCRIPT_START_TIME - timedelta(minutes=2))
        result_count = int(job.get("resultCount", 0))
        actions = job.get("alert_actions", "")
        webhook_fired = "webhook" in actions

        if is_fresh and result_count > 0 and webhook_fired:
            print(f"✅ PROVEN SUCCESS: Found fresh job from {trigger_time}")
            return True
        
        print(f"❌ Closest job found was at {trigger_time}, but it didn't meet all criteria.")
        return False

    except Exception as e:
        print(f"❌ Verification Logic Error: {e}")
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