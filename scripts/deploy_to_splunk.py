import os
import sys
import yaml
import urllib3
import splunklib.client as client
from pathlib import Path

# 1. SILENCE SSL WARNINGS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 2. CONFIGURATION
SPLUNK_HOST = os.getenv('SPLUNK_HOST', 'localhost')
SPLUNK_PORT = int(os.getenv('SPLUNK_PORT', 8089))
SPLUNK_USERNAME = os.getenv('SPLUNK_USERNAME', 'admin')
SPLUNK_PASSWORD = os.getenv('SPLUNK_PASSWORD')
TINES_WEBHOOK_URL = os.getenv('TINES_WEBHOOK_URL')

def connect_to_splunk():
    if not SPLUNK_PASSWORD:
        print("❌ ERROR: SPLUNK_PASSWORD environment variable not set.")
        sys.exit(1)
    try:
        service = client.connect(
            host=SPLUNK_HOST,
            port=SPLUNK_PORT,
            username=SPLUNK_USERNAME,
            password=SPLUNK_PASSWORD,
            verify=False
        )
        print(f"✅ Connected to Splunk at {SPLUNK_HOST}:{SPLUNK_PORT}")
        return service
    except Exception as e:
        print(f"❌ FAILURE: Could not connect to Splunk: {e}")
        sys.exit(1)

def deploy_detections(service):
    """Parses YAML and deploys the Alert with Tines Automation."""
    # Path logic: finds detections/ relative to this script
    root_dir = Path(__file__).resolve().parent.parent
    yaml_path = root_dir / "detections" / "suspicious_powershell.yml"

    print(f"--- Reading detection: {yaml_path.name} ---")
    
    try:
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
        
        alert_name = data.get('name')
        search_query = data.get('detection', {}).get('search')

        if not alert_name or not search_query:
            print(f"❌ YAML Error: Missing name or search in {yaml_path}")
            return False

        # --- CONFIGURE ALERT PARAMETERS ---
        alert_params = {
            "is_scheduled": 1,
            "cron_schedule": data.get('schedule', "*/5 * * * *"),
            "actions": "webhook",
            "action.webhook": 1,
            "action.webhook.param.url": TINES_WEBHOOK_URL,
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": "0",
            "disabled": 0
        }

        # Lifecycle Management: Clean up old versions
        if alert_name in service.saved_searches:
            service.saved_searches.delete(alert_name)
            print(f"  - Cleaned up existing version of '{alert_name}'")

        # Deploy fresh Alert
        service.saved_searches.create(alert_name, search_query.strip(), **alert_params)
        print(f"🚀 SUCCESS: '{alert_name}' deployed and linked to Tines.")
        return True

    except Exception as e:
        print(f"❌ Deployment failed: {e}")
        return False

def main():
    service = connect_to_splunk()
    success = deploy_detections(service)
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()