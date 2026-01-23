import os
import sys
import yaml
import splunklib.client as client
import urllib3
from pathlib import Path

# 1. SILENCE SSL WARNINGS
# Essential for self-signed certificates in local lab environments.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 2. RETRIEVE CONFIGURATION FROM ENVIRONMENT
# Uses variables mapped from GitHub Secrets.
SPLUNK_HOST = os.getenv('SPLUNK_HOST', 'localhost')
SPLUNK_PORT = int(os.getenv('SPLUNK_PORT', 8089))
SPLUNK_USERNAME = os.getenv('SPLUNK_USERNAME', 'admin')
SPLUNK_PASSWORD = os.getenv('SPLUNK_PASSWORD')
TINES_WEBHOOK_URL = (os.getenv('TINES_WEBHOOK_URL') or "").strip()

# Safety Check: Stop the script if secrets are missing
if not SPLUNK_PASSWORD:
    print("❌ ERROR: SPLUNK_PASSWORD environment variable not set.")
    sys.exit(1)

def connect_to_splunk():
    """Establishes a connection to the Splunk Management API."""
    try:
        print(f"--- Attempting to connect to Splunk ---")
        print(f"Host: {SPLUNK_HOST}")
        print(f"Port: {SPLUNK_PORT}")
        
        # 3. ESTABLISH THE CONNECTION
        # 'verify=False' is critical for local labs using self-signed certs.
        service = client.connect(
            host=SPLUNK_HOST,
            port=SPLUNK_PORT,
            username=SPLUNK_USERNAME,
            password=SPLUNK_PASSWORD,
            verify=False
        )
        
        print("✅ SUCCESS: Connected to Splunk successfully.")
        return service
    except Exception as e:
        print(f"❌ FAILURE: Could not connect to Splunk.")
        print(f"Error details: {e}")
        sys.exit(1)

def deploy_detections(service):
    """Reads YAML detection file and creates/updates alerts in Splunk."""
    
    # Locate the detections directory relative to this script
    root_dir = Path(__file__).resolve().parent.parent
    yaml_path = root_dir / "detections" / "suspicious_powershell.yml"
    
    if not yaml_path.exists():
        print(f"❌ ERROR: Detection file not found at {yaml_path}")
        return False

    print(f"\n--- Reading detection: {yaml_path.name} ---")
    
    try:
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
        
        alert_name = data.get('name')
        search_query = data.get('detection', {}).get('search')
        schedule = data.get('schedule', "* * * * *")
        
        if not alert_name or not search_query:
            print(f"❌ YAML Error: Missing 'name' or 'detection.search' in {yaml_path}")
            return False
        
        print(f"Alert Name: {alert_name}")
        print(f"Schedule: {schedule}")
        
        # 4. CONFIGURE BASE ALERT PARAMETERS
        alert_params = {
            "is_scheduled": 1,
            "cron_schedule": schedule,
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": "0",
            "disabled": 0,
            "dispatch.earliest_time": "-60m@m",
            "dispatch.latest_time": "now",
            "check_config": "false"  # Prevents validation errors during update
        }
        
        # 5. ADD WEBHOOK ACTION IF URL IS PROVIDED
        if TINES_WEBHOOK_URL:
            alert_params["actions"] = "webhook"
            alert_params["action.webhook"] = 1
            alert_params["action.webhook.param.url"] = TINES_WEBHOOK_URL
            webhook_status = "✅ with Tines webhook"
            print(f"Webhook: Configured for {TINES_WEBHOOK_URL[:50]}...")
        else:
            webhook_status = "⚠️ without webhook (TINES_WEBHOOK_URL not set)"
            print(f"Webhook: Not configured - TINES_WEBHOOK_URL is empty")
        
        # 6. CREATE OR UPDATE ALERT
        if alert_name in service.saved_searches:
            print(f"🔄 Alert '{alert_name}' exists. Updating {webhook_status}...")
            saved_search = service.saved_searches[alert_name]
            saved_search.update(search=search_query.strip(), **alert_params).refresh()
            print(f"🔄 SUCCESS: Alert '{alert_name}' updated.")
        else:
            print(f"🚀 Creating new alert '{alert_name}' {webhook_status}...")
            service.saved_searches.create(alert_name, search_query.strip(), **alert_params)
            print(f"🚀 SUCCESS: Alert '{alert_name}' created.")
        
        return True
    
    except Exception as e:
        print(f"❌ Deployment failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    service = connect_to_splunk()
    print(f"Splunk Version: {service.info['version']}")
    
    success = deploy_detections(service)
    
    if not success:
        sys.exit(1)
    
    print("\n✅ Phase-1 Deployment complete!")

if __name__ == "__main__":
    main()