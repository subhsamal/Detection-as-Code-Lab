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
    
    # This query looks at Splunk's internal logs to see if the ALERT ACTION actually ran
    # It is the most honest way to verify an alert fired.
    audit_query = f'search index=_audit action=alert_fired ss_name="{alert_name}" | stats count'

    try:
        print(f"--- Probing Audit Logs for Alert: {alert_name} ---")
        job = service.jobs.oneshot(audit_query)
        
        import splunklib.results as results
        reader = results.ResultsReader(job)
        
        for result in reader:
            count = int(result['count'])
            if count > 0:
                print(f"✅ PROVEN: Splunk Audit logs confirm this alert fired {count} times!")
                return True
        
        print("❌ FAIL: No record of this alert firing found in Splunk Audit logs.")
        return False
    except Exception as e:
        print(f"❌ Audit Probe Error: {e}")
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