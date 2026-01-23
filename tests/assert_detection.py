import os
import sys
import yaml
import time
import traceback
import splunklib.client as client
from pathlib import Path
from datetime import datetime, timezone, timedelta

# 1. INITIALIZE UTC START TIME
# This is the "secret sauce" to ensure we only validate THIS pipeline run.
SCRIPT_START_TIME = datetime.now(timezone.utc)

# CONFIGURATION
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
        print(f"❌ Connection Error: {e}")
        sys.exit(1)

def verify_alert_history(service):
    """Checks if the actual scheduled alert fired during this pipeline run."""
    root_dir = Path(__file__).resolve().parent.parent
    yaml_path = root_dir / "detections" / "suspicious_powershell.yml"

    try:
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
        
        alert_name = data.get('name')
        print(f"--- Checking Alert History: {alert_name} ---")

        if alert_name not in service.saved_searches:
            print(f"❌ ERROR: Alert '{alert_name}' not found in Splunk.")
            return False

        saved_search = service.saved_searches[alert_name]
        history = saved_search.history()
        
        # Look for the most recent job that matches our timeframe
        for job in history:
            job.refresh()
            
            # Parse Splunk UTC time
            trigger_time_str = job["cursorTime"]
            trigger_time = datetime.fromisoformat(trigger_time_str.replace('Z', '+00:00'))
            
            result_count = int(job["resultCount"])

            # VALIDATION: Results > 0 AND happened after the script started (with 5m buffer)
            if result_count > 0 and trigger_time > (SCRIPT_START_TIME - timedelta(minutes=5)):
                print(f"✅ SUCCESS: Alert fired at {trigger_time} UTC with {result_count} results.")
                print(f"Job SID: {job.sid}")
                return True
        
        return False

    except Exception as e:
        print(f"❌ Verification script failed.")
        traceback.print_exc()
        return False

def main():
    if not SPLUNK_PASSWORD:
        print("❌ ERROR: SPLUNK_PASSWORD not set.")
        sys.exit(1)

    service = connect_to_splunk()
    
    # We wait 10 seconds for the Splunk API to catch up with the scheduler
    print(f"⏳ Verification started at {SCRIPT_START_TIME.strftime('%H:%M:%S')} UTC")
    print("⏳ Finalizing alert metadata sync...")
    time.sleep(10)

    if verify_alert_history(service):
        print("\n✨ PHASE-1 VALIDATED: End-to-end pipeline successful!")
        sys.exit(0)
    else:
        print("\n⚠️ FAILED: No fresh alert trigger found in history. Check scheduler or logs.")
        sys.exit(1)

if __name__ == "__main__":
    main()