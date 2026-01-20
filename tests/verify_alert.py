import os
import sys
import time
import splunklib.client as client
import urllib3

# 1. SILENCE SSL WARNINGS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 2. CONFIGURATION
SPLUNK_HOST = os.getenv('SPLUNK_HOST', 'localhost')
SPLUNK_PORT = int(os.getenv('SPLUNK_PORT', 8089))
SPLUNK_USERNAME = os.getenv('SPLUNK_USERNAME', 'admin')
SPLUNK_PASSWORD = os.getenv('SPLUNK_PASSWORD')

def verify_detection(service):
    """
    Queries Splunk to see if the simulated attack log was correctly indexed
    and reachable by the detection logic.
    """
    # This search specifically looks for the 'malicious' payload we injected
    search_query = 'search index=windows ("*powershell*" OR "*pwsh*") ("-enc" OR "-encodedcommand")'
    
    print(f"🔍 Running verification search: {search_query}")
    
    # Execute the search in 'blocking' mode (waits until finished)
    job = service.jobs.create(search_query, exec_mode="blocking")
    
    result_count = int(job["resultCount"])
    
    if result_count > 0:
        print(f"✅ SUCCESS: Found {result_count} instances of the simulated attack.")
        print("🚀 Detection-as-Code Pipeline: PASS")
        return True
    else:
        print("❌ FAILURE: The simulated attack was not found in Splunk.")
        print("⚠️ Check if the indexer is lagging or if the 'test_detection' step failed.")
        return False

def main():
    if not SPLUNK_PASSWORD:
        print("❌ ERROR: SPLUNK_PASSWORD not set.")
        sys.exit(1)

    try:
        service = client.connect(
            host=SPLUNK_HOST,
            port=SPLUNK_PORT,
            username=SPLUNK_USERNAME,
            password=SPLUNK_PASSWORD,
            verify=False
        )
        
        # 3. RUN THE VERIFICATION
        if verify_detection(service):
            sys.exit(0) # Tells GitHub Actions the job PASSED
        else:
            sys.exit(1) # Tells GitHub Actions the job FAILED

    except Exception as e:
        print(f"❌ ERROR: Verification script failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()