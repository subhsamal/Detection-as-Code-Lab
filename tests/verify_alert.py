import os
import sys
import yaml
import time
import splunklib.client as client
import splunklib.results as results
from pathlib import Path

# CONFIGURATION
SPLUNK_HOST = os.getenv('SPLUNK_HOST', 'localhost')
SPLUNK_PORT = int(os.getenv('SPLUNK_PORT', 8089))
SPLUNK_USERNAME = os.getenv('SPLUNK_USERNAME', 'admin')
SPLUNK_PASSWORD = os.getenv('SPLUNK_PASSWORD')

def verify_logic(service):
    """Checks if the detection logic actually finds the logs we ingested."""
    root_dir = Path(__file__).resolve().parent.parent
    yaml_path = root_dir / "detections" / "suspicious_powershell.yml"

    try:
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
        
        search_query = data.get('detection', {}).get('search').strip()
        print(f"--- Running Verification Search ---\n{search_query}")

        # Prepend 'search' for the oneshot API job
        query = f"search {search_query}"
        
        # Execute search
        job = service.jobs.oneshot(query)
        reader = results.ResultsReader(job)
        matches = [event for event in reader if isinstance(event, dict)]
        
        print(f"📊 Result: Found {len(matches)} matching events.")
        return len(matches) > 0

    except Exception as e:
        print(f"❌ Verification script failed: {e}")
        return False

def main():
    if not SPLUNK_PASSWORD:
        sys.exit(1)

    service = client.connect(host=SPLUNK_HOST, port=SPLUNK_PORT, username=SPLUNK_USERNAME, password=SPLUNK_PASSWORD, verify=False)
    
    print("⏳ Waiting 10 seconds for Splunk to index ingested logs...")
    time.sleep(10)

    if verify_logic(service):
        print("\n✨ PHASE-1 VALIDATED: Alert deployed, logs found, logic is sound!")
        sys.exit(0)
    else:
        print("\n⚠️ FAILED: Detection logic did not find any events. Check your search syntax.")
        sys.exit(1)

if __name__ == "__main__":
    main()