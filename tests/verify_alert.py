import os
import sys
import time
import urllib3
import splunklib.client as client

# Silence SSL warnings for local Docker/Self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration from Environment Variables
SPLUNK_HOST = os.getenv('SPLUNK_HOST', 'localhost')
SPLUNK_PORT = int(os.getenv('SPLUNK_PORT', 8089))
SPLUNK_USERNAME = os.getenv('SPLUNK_USERNAME', 'admin')
SPLUNK_PASSWORD = os.getenv('SPLUNK_PASSWORD')
TINES_WEBHOOK_URL = os.getenv('TINES_WEBHOOK_URL')

def setup_tines_alert(service):
    """
    Deploys the actual detection logic to Splunk as a Saved Search.
    This includes the full exclusion logic and the Webhook action for Tines.
    """
    alert_name = "Phase-1_Encoded_PowerShell_Detection"
    
    # The Full Detection Query from YAML
    search_query = '''index=windows sourcetype=WinEventLog:Security EventCode=4688
    | search (CommandLine="*powershell*" OR CommandLine="*pwsh*")
    | search (CommandLine="*-enc*" OR CommandLine="*-encodedcommand*")
    | rex field=CommandLine "-enc(?:odedcommand)?\\s+(?<encoded_cmd>\\S+)"
    | where isnotnull(encoded_cmd) AND len(encoded_cmd) >= 20
    | eval decoded_cmd=replace(base64decode(encoded_cmd), "\\x00", "")
    | where isnotnull(decoded_cmd)
    | search NOT [
        (User="NT AUTHORITY\\\\SYSTEM" AND ParentProcessName IN ("*\\\\services.exe", "*\\\\svchost.exe"))
        OR ParentProcessName IN ("*\\\\ccmexec.exe", "*\\\\CcmExec.exe", "*\\\\SMS*.exe")
        OR ParentProcessName="*\\\\wsmprovhost.exe"
        OR ParentProcessName="*\\\\gpscript.exe"
      ]
    | table _time, Computer, User, ParentProcessName, CommandLine, decoded_cmd'''

    alert_config = {
        "disabled": 0,
        "is_scheduled": 1,
        "cron_schedule": "*/1 * * * *",
        "actions": "webhook",
        "action.webhook.param.url": TINES_WEBHOOK_URL,
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "alert.track": 1,
        "dispatch.earliest_time": "-2m",
        "dispatch.latest_time": "now"
    }

    if alert_name in service.saved_searches:
        print(f"Updating existing Tines bridge alert: {alert_name}")
        service.saved_searches[alert_name].update(**alert_config).refresh()
    else:
        print(f"Creating new Tines bridge alert: {alert_name}")
        service.saved_searches.create(alert_name, search_query, **alert_config)

def verify_detection_results(service):
    """
    Runs the full query to verify that exclusions are working.
    Based on ingest_logs_for_detection.py, we expect exactly 2 matches
    (DownloadString and Mimikatz) after exclusions are applied.
    """
    # 1. Define the query (it's okay to have newlines here for readability)
    raw_query = r"""
    index=windows sourcetype=WinEventLog:Security EventCode=4688 
    | search (CommandLine="*powershell*" OR CommandLine="*pwsh*") 
    | search (CommandLine="*-enc*" OR CommandLine="*-encodedcommand*") 
    | rex field=CommandLine "-enc(?:odedcommand)?\s+(?<encoded_cmd>\S+)" 
    | where isnotnull(encoded_cmd) AND len(encoded_cmd) >= 20 
    | search NOT ((User="NT AUTHORITY\SYSTEM" AND (ParentProcessName="*\\services.exe" OR ParentProcessName="*\\svchost.exe")) 
    OR ParentProcessName IN ("*\\ccmexec.exe", "*\\CcmExec.exe", "*\\SMS*.exe") 
    OR ParentProcessName="*\\wsmprovhost.exe" 
    OR ParentProcessName="*\\gpscript.exe")
    """

    # 2. SANITIZE: Remove newlines and extra spaces before sending to API
    # This is the "Magic Fix" for the 400 Error
    verification_query = " ".join(raw_query.split())

    # 3. Print it to your GitHub Action logs so you can see exactly what Splunk gets
    print(f"DEBUG: Sending query: {verification_query}")
    
    print("Running strict verification search (checking main logic + exclusions)...")
    job = service.jobs.create(verification_query, exec_mode="blocking")
    result_count = int(job["resultCount"])
    
    # Validation logic
    if result_count == 2:
        print(f"SUCCESS: Found {result_count} malicious instances. Exclusions respected.")
        return True
    elif result_count > 2:
        print(f"FAILURE: Found {result_count} instances. Exclusions are NOT working correctly.")
        return False
    else:
        print(f"FAILURE: Found {result_count} instances. Main detection logic may be too restrictive.")
        return False

def verify_tines_received_alert():
    """
    Conceptual check: Use Tines API to verify the webhook actually arrived.
    In Phase-1, we usually check this manually in the Tines UI, 
    but for CI/CD automation, you'd use a GET request here.
    """
    print("Checking Tines for received events...")
    # Example logic:
    # response = requests.get(TINES_API_URL, headers=AUTH_HEADERS)
    # if response.status_code == 200: return True
    return True

def main():
    if not all([SPLUNK_PASSWORD, TINES_WEBHOOK_URL]):
        print("ERROR: Missing SPLUNK_PASSWORD or TINES_WEBHOOK_URL.")
        sys.exit(1)

    try:
        service = client.connect(
            host=SPLUNK_HOST,
            port=SPLUNK_PORT,
            username=SPLUNK_USERNAME,
            password=SPLUNK_PASSWORD,
            verify=False
        )
        print("Connected to Splunk successfully.")

        setup_tines_alert(service)
        
        if verify_detection_results(service):
            print("Detection-as-Code Pipeline: PASS")
            sys.exit(0)
        else:
            print("Detection-as-Code Pipeline: FAIL")
            sys.exit(1)

    except Exception as e:
        print(f"ERROR: Script failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()