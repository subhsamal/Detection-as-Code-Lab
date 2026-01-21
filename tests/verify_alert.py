import os
import splunklib.client as client
import splunklib.results as results
import time
import sys

def connect_to_splunk():
    # Adjusted to use standard environment variables or local defaults
    host = os.environ.get('SPLUNK_HOST', 'localhost')
    port = int(os.environ.get('SPLUNK_PORT', 8089))
    username = os.environ.get('SPLUNK_USERNAME', 'admin')
    password = os.environ.get('SPLUNK_PASSWORD', 'YourPassword')
    
    return client.connect(host=host, port=port, username=username, password=password)

def setup_tines_alert(service):
    print("Step 1: Creating/Updating Tines bridge alert...")
    
    # The 'Surgical' Search Query - Flattened for API stability
    # This version removes the problematic NT AUTHORITY\SYSTEM backslash trap
    search_query = (
        r'index=windows sourcetype=WinEventLog:Security EventCode=4688 '
        r'| search (CommandLine="*powershell*" OR CommandLine="*pwsh*") '
        r'| search (CommandLine="*-enc*" OR CommandLine="*-encodedcommand*") '
        r'| rex field=CommandLine "-enc(?:odedcommand)?\s+(?<encoded_cmd>\S+)" '
        r'| where isnotnull(encoded_cmd) AND len(encoded_cmd) >= 20 '
        r'| search NOT (ParentProcessName IN ("*\\ccmexec.exe", "*\\CcmExec.exe", "*\\SMS*.exe", '
        r'"*\\wsmprovhost.exe", "*\\gpscript.exe", "*\\services.exe", "*\\svchost.exe")) '
        r'| table _time, Computer, User, ParentProcessName, CommandLine, encoded_cmd'
    )

    try:
        alert_name = "Phase-1_Encoded_PowerShell_Detection"
        if alert_name in service.saved_searches:
            service.saved_searches.delete(alert_name)
            print(f"  - Deleted existing alert: {alert_name}")
        
        service.saved_searches.create(alert_name, search_query)
        print(f"✅ Saved Search '{alert_name}' created successfully.")
        return True
    except Exception as e:
        print(f"❌ Failed to create Saved Search: {e}")
        return False

def verify_detection_results(service):
    print("Step 2: Verifying detection results in index=windows...")
    
    # Must mirror the logic in setup_tines_alert exactly
    verification_query = (
        r'search index=windows sourcetype=WinEventLog:Security EventCode=4688 '
        r'| search (CommandLine="*powershell*" OR CommandLine="*pwsh*") '
        r'| search (CommandLine="*-enc*" OR CommandLine="*-encodedcommand*") '
        r'| rex field=CommandLine "-enc(?:odedcommand)?\s+(?<encoded_cmd>\S+)" '
        r'| where isnotnull(encoded_cmd) AND len(encoded_cmd) >= 20 '
        r'| search NOT (ParentProcessName IN ("*\\ccmexec.exe", "*\\CcmExec.exe", "*\\SMS*.exe", '
        r'"*\\wsmprovhost.exe", "*\\gpscript.exe", "*\\services.exe", "*\\svchost.exe"))'
    )

    try:
        # Running as a oneshot job for immediate results
        job = service.jobs.oneshot(verification_query)
        reader = results.ResultsReader(job)
        
        events = []
        for result in reader:
            if isinstance(result, dict):
                events.append(result)
        
        count = len(events)
        print(f"📊 Verification complete. Found {count} matching events.")
        
        if count > 0:
            print("  - Detection Confirmed: Malicious activity identified.")
            return True
        else:
            print("  - Detection Failed: No events matched the criteria.")
            return False
            
    except Exception as e:
        print(f"❌ Verification search failed: {e}")
        return False

def main():
    try:
        service = connect_to_splunk()
        print("Connected to Splunk successfully.")
        
        # 1. Create/Update the Alert
        alert_ok = setup_tines_alert(service)
        
        # 2. Wait for indexing (Phase-1 buffer)
        print("Waiting 5 seconds for Splunk indexing...")
        time.sleep(5)
        
        # 3. Run Verification
        detection_ok = verify_detection_results(service)
        
        if alert_ok and detection_ok:
            print("\n🚀 PHASE-1 SUCCESS: Pipeline validated.")
            sys.exit(0)
        else:
            print("\n❌ PHASE-1 FAILURE: Pipeline checks failed.")
            sys.exit(1)
            
    except Exception as e:
        print(f"\nCRITICAL ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()