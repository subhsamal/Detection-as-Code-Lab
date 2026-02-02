import os
import sys
import json
import time
import splunklib.client as client
import urllib3
from datetime import datetime, timezone

# SILENCE SSL WARNINGS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# SPLUNK CONFIGURATION and CONNECTION OBJECT
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
        print("✅ Connected to Splunk")
        return service
    except Exception as e:
        print(f"❌ CONNECTION ERROR: {e}")
        sys.exit(1)

def verify_alert_history(service):
    """
    NEW APPROACH: Actually check if alerts were triggered
    This queries the triggered_alerts index, not just audit logs
    """
    alert_name = "Suspicious PowerShell Encoded Command"
    EXPECTED_MATCHES = 2 
    
    print(f"\n{'='*70}")
    print(f"DETECTION VERIFICATION - Expected {EXPECTED_MATCHES} alerts")
    print(f"{'='*70}\n")
    
    # STEP 1: Verify raw logs exist
    print(f"--- Step 1: Verifying Raw Logs ---")
    raw_query = (
        'search index=windows sourcetype=WinEventLog:Security source=dac_test_suite '
        '| spath '  # To fix the field extraction issue
        '| search EventCode=4688 '
        '(CommandLine="*powershell*" OR CommandLine="*pwsh*") '
        '(CommandLine="*-enc*" OR CommandLine="*-encodedcommand*") '
        '| rex field=CommandLine "-enc(?:odedcommand)?\\s+(?<encoded_cmd>\\S+)" '
        '| where isnotnull(encoded_cmd) AND len(encoded_cmd) >= 20 '
        '| search NOT (User="NT AUTHORITY\\\\SYSTEM" AND (ParentProcessName="*\\\\services.exe" OR ParentProcessName="*\\\\svchost.exe")) ' # KEEP
        '| search NOT (ParentProcessName="*\\\\ccmexec.exe" OR ParentProcessName="*\\\\CcmExec.exe" OR ParentProcessName="*\\\\SMS*.exe") '   # KEEP
        '| search NOT ParentProcessName="*\\\\wsmprovhost.exe" '                                                                             # KEEP
        '| search NOT ParentProcessName="*\\\\gpscript.exe"'                                                                                # KEEP
    )

    try:
        job = service.jobs.oneshot(raw_query, output_mode="json", earliest_time="-15m")
        results = json.loads(job.read())
        actual_matches = len(results.get("results", []))

        if actual_matches >= EXPECTED_MATCHES:
            print(f"✅ PASS: Found {actual_matches} matching log entries")
            for i, result in enumerate(results.get("results", [])[:3], 1):
                print(f"   Event {i}: User={result.get('User')}, Computer={result.get('Computer')}")
        else:
            print(f"❌ FAIL: Found only {actual_matches} logs (Expected {EXPECTED_MATCHES})")
            print("   This means test data injection failed or logs haven't indexed yet")
            return False

    except Exception as e:
        print(f"❌ ERROR in Step 1: {e}")
        return False

    # STEP 2: Check if the scheduled search actually ran
    print(f"\n--- Step 2: Verifying Scheduled Search Execution ---")
    audit_query = (
        f'search index=_audit action=search info=completed '
        f'savedsearch_name="{alert_name}" '
        f'| head 1 '
        f'| table _time, user, search_id, total_run_time, result_count, event_count'
    )
    
    try:
        audit_job = service.jobs.oneshot(audit_query, output_mode="json", earliest_time="-15m")
        audit_results = json.loads(audit_job.read())
        
        if not audit_results.get("results"):
            print(f"❌ FAIL: No recent executions of '{alert_name}' found in audit logs")
            print("   The scheduled search may not have run yet (check cron schedule)")
            return False
        
        audit_record = audit_results['results'][0]
        print(f"✅ PASS: Search executed at {audit_record.get('_time')}")
        print(f"   Result count: {audit_record.get('result_count', 'N/A')}")
        print(f"   Event count: {audit_record.get('event_count', 'N/A')}")
        
    except Exception as e:
        print(f"❌ ERROR in Step 2: {e}")
        return False

    # STEP 3: IMPORTANT - Check if alerts were actually TRIGGERED
    print(f"\n--- Step 3: Verifying Triggered Alerts (THE REAL TEST) ---")
    
    triggered_query = (
        f'search index=_audit action=alert_fired '
        f'savedsearch_name="{alert_name}" '
        f'| stats count'
    )
    
    try:
        triggered_job = service.jobs.oneshot(triggered_query, output_mode="json", earliest_time="-15m")
        triggered_results = json.loads(triggered_job.read())
        
        if not triggered_results.get("results"):
            print(f"❌ FAIL: No triggered alerts found for '{alert_name}'")
            print("   Possible reasons:")
            print("   1. Alert threshold not met (check alert_threshold in config)")
            print("   2. Alert suppression prevented firing (check suppress settings)")
            print("   3. Time window mismatch between search and events")
            return False
        
        triggered_count = int(triggered_results['results'][0].get('count', 0))
        
        if triggered_count >= 1:  # At least one alert should have fired, can be tightend
            print(f"✅ PASS: Alert fired {triggered_count} time(s)")
            return True
        else:
            print(f"❌ FAIL: Expected alerts but count is {triggered_count}")
            return False
            
    except Exception as e:
        print(f"❌ ERROR in Step 3: {e}")
        import traceback
        traceback.print_exc()
        return False

# def cleanup_old_logs(service):
#     """Clean up test data after verification"""
#     print(f"\n{'='*70}")
#     print("CLEANUP: Removing test data")
#     print(f"{'='*70}\n")
    
#     try:
#         service.jobs.oneshot("search index=windows source=dac_test_suite | delete")
#         print("✅ Test data cleaned up successfully")
#     except Exception as e:
#         print(f"⚠️ Cleanup failed (this is OK if 'can_delete' role not assigned): {e}")

def main():
    if not SPLUNK_PASSWORD:
        print("❌ ERROR: SPLUNK_PASSWORD environment variable not set.")
        sys.exit(1)

    print(f"\n{'='*70}")
    print("STARTING DETECTION-AS-CODE VERIFICATION")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*70}\n")

    service = connect_to_splunk()
    
    # Give Splunk time to process scheduled search
    print("⏳ Waiting for alert execution window...")
    print("   (Scheduled searches run every 2 minutes)")
    time.sleep(30)

    # Run verification
    success = verify_alert_history(service)

    # Always cleanup or alert will trigger continously
    # cleanup_old_logs(service)

    # Final verdict
    print(f"\n{'='*70}")
    if success:
        print("🎉 VERIFICATION SUCCESSFUL: Detection pipeline is working!")
        print(f"{'='*70}\n")
        sys.exit(0)
    else:
        print("❌ VERIFICATION FAILED: Alerts did not trigger as expected")
        print(f"{'='*70}\n")
        print("\nDEBUGGING TIPS:")
        print("1. Check Splunk UI: Settings > Searches, reports, and alerts")
        print(f"   Look for 'Suspicious PowerShell Encoded Command'")
        print("2. Verify alert is enabled (not disabled)")
        print("3. Check 'Last Run' timestamp - should be recent")
        print("4. Click 'View' > 'Triggered Alerts' to see alert history")
        print("5. Manually run the search to verify it finds events\n")
        sys.exit(1)

if __name__ == "__main__":
    main()