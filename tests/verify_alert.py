import os
import yaml
import time
import sys
import splunklib.client as client
import splunklib.results as results
from pathlib import Path

# --- SECURE CONFIGURATION ---
# Fetched from GitHub Secrets (Action Environment) or local export
TINES_WEBHOOK_URL = os.environ.get('TINES_WEBHOOK_URL')
SPLUNK_HOST = os.environ.get('SPLUNK_HOST', 'localhost')
SPLUNK_PORT = int(os.environ.get('SPLUNK_PORT', 8089))
SPLUNK_USER = os.environ.get('SPLUNK_USERNAME', 'admin')
SPLUNK_PWD = os.environ.get('SPLUNK_PASSWORD')

def connect_splunk():
    """Connect to Splunk API using Environment Variables."""
    if not SPLUNK_PWD:
        print("❌ Error: SPLUNK_PASSWORD is not set in environment.")
        sys.exit(1)
    try:
        service = client.connect(
            host=SPLUNK_HOST,
            port=SPLUNK_PORT,
            username=SPLUNK_USER,
            password=SPLUNK_PWD
        )
        print(f"✅ Connected to Splunk at {SPLUNK_HOST}")
        return service
    except Exception as e:
        print(f"❌ Splunk Connection Failed: {e}")
        sys.exit(1)

def sync_detection(service):
    """Parses YAML and deploys the Alert with Tines Automation."""
    print("\nStep 1: Syncing YAML to Splunk...")

    # Root calculation: finds Detection-as-Code-Lab/ from tests/verify_alert.py
    root_dir = Path(__file__).resolve().parent.parent
    yaml_path = root_dir / "detections" / "suspicious_powershell.yml"

    try:
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
        
        alert_name = data.get('name')
        search_query = data.get('detection', {}).get('search')

        if not alert_name or not search_query:
            print(f"❌ YAML Error: Missing fields in {yaml_path}")
            return None

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
            print(f"  - Replaced existing alert: {alert_name}")

        # Deploy fresh Alert
        service.saved_searches.create(alert_name, search_query.strip(), **alert_params)
        print(f"🚀 Success: {alert_name} deployed & linked to Tines.")
        
        return {"name": alert_name, "query": search_query.strip()}

    except Exception as e:
        print(f"❌ Sync failed: {e}")
        return None

def verify_data(service, metadata):
    """Check if the detection actually finds the logs we ingested."""
    print(f"\nStep 2: Verifying detection logic in Splunk...")
    
    # Prepend 'search' for the oneshot API job
    query = f"search {metadata['query']}"
    
    try:
        job = service.jobs.oneshot(query)
        reader = results.ResultsReader(job)
        matches = [event for event in reader if isinstance(event, dict)]
        
        print(f"📊 Result: Found {len(matches)} matching events.")
        return len(matches) > 0
    except Exception as e:
        print(f"❌ Search verification failed: {e}")
        return False

def main():
    service = connect_splunk()
    
    # 1. Sync
    metadata = sync_detection(service)
    if not metadata:
        sys.exit(1)

    # 2. Wait for indexing
    print("Waiting 5 seconds for indexing...")
    time.sleep(5)

    # 3. Verify
    if verify_data(service, metadata):
        print("\n✨ PHASE-1 VALIDATED: YAML synced, Alert active, Events found!")
        sys.exit(0)
    else:
        print("\n⚠️ FAILED: No events found. Pipeline is live but nothing to alert on.")
        sys.exit(1)

if __name__ == "__main__":
    main()