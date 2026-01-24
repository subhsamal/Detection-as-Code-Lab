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

        # Access the FIRED ALERTS collection (requires 'track: enabled: true' in YAML)
        fired_alerts = service.fired_alerts()
        
        if alert_name not in fired_alerts:
            print(f"⚠️ No record of '{alert_name}' having ever fired in the 'Triggered Alerts' list.")
            return False

        # Get the alerts for this specific detection
        alert_group = fired_alerts[alert_name]
        
        # Look back 5 minutes from 'now' to see if a record exists
        # This is persistent and does NOT rely on temporary search jobs (No more 404s!)
        recent_fires = alert_group.alerts(earliest_time="-5m")
        
        if not recent_fires:
            print(f"❌ Alert exists, but no trigger events found in the last 5 minutes.")
            return False

        # If we have at least one, we check the most recent one
        latest_alert = recent_fires[0]
        trigger_time_str = latest_alert.get("trigger_time") # Returns Epoch string
        trigger_time = datetime.fromtimestamp(float(trigger_time_str), tz=timezone.utc)

        # Logic check: Was it fired AFTER we started this test run?
        # We use a 1-minute buffer to account for minor clock drift
        is_fresh = trigger_time > (SCRIPT_START_TIME - timedelta(minutes=1))

        if is_fresh:
            print(f"✅ PROVEN SUCCESS: Found fresh triggered alert record from {trigger_time}")
            print(f"✅ Alert Details: SID={latest_alert.get('sid')}")
            return True
        
        print(f"❌ Found a record from {trigger_time}, but it's too old for this test run.")
        return False

    except Exception as e:
        print(f"❌ Verification Logic Error: {e}")
        # Optional: print(traceback.format_exc()) for deep debugging
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