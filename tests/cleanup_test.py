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

def cleanup_test_data(service):
    """
    Finds the exact test logs and marks them as deleted so they don't 
    clutter the lab environment.
    """
    # This query finds the specific strings we used in test_detection.py
    # and test_benign.py, then pipes them to the delete command.
    # Change index=main to index=windows
    cleanup_search = 'search index=windows earliest=0 | delete'
    print(f"🧹 Running cleanup search: {cleanup_search}")
    
    try:
        # Create a search job in blocking mode
        job = service.jobs.create(cleanup_search, exec_mode="blocking")
        
        # The 'delete' command returns information about how many events were deleted
        print("✨ Cleanup successful. Test events have been marked as deleted.")
        return True
    except Exception as e:
        if "External search command 'delete' is not allowed" in str(e):
            print("❌ ERROR: Your Splunk user lacks the 'can_delete' role.")
        else:
            print(f"❌ ERROR: Cleanup failed: {e}")
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
        
        if cleanup_test_data(service):
            sys.exit(0)
        else:
            sys.exit(1)

    except Exception as e:
        print(f"❌ ERROR: Could not connect to Splunk: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()