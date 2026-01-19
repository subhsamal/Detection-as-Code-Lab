import os
import sys
import splunklib.client as client
import urllib3

# 1. SILENCE SSL WARNINGS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 2. CONFIGURATION (Matches your deploy script)
SPLUNK_HOST = os.getenv('SPLUNK_HOST', 'localhost')
SPLUNK_PORT = int(os.getenv('SPLUNK_PORT', 8089))
SPLUNK_USERNAME = os.getenv('SPLUNK_USERNAME', 'admin')
SPLUNK_PASSWORD = os.getenv('SPLUNK_PASSWORD')

def trigger_test_event(service):
    """Injects a fake malicious log into Splunk to test the detection rule."""
    # This payload must match the logic in your YAML detection
    malicious_log = '2026-01-19 10:00:00 EventCode=4104 Message="powershell.exe -e BASE64_ENCODED_MALWARE"'
    
    try:
        index = service.indexes["main"]
        # Tagging with the correct sourcetype so the detection rule picks it up
        index.submit(malicious_log, sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational")
        print("🚀 SUCCESS: Test event injected into Splunk.")
    except Exception as e:
        print(f"❌ ERROR: Failed to inject test event: {e}")
        sys.exit(1)

def main():
    if not SPLUNK_PASSWORD:
        print("❌ ERROR: SPLUNK_PASSWORD not set.")
        sys.exit(1)

    try:
        # 3. CREATE THE SERVICE OBJECT
        service = client.connect(
            host=SPLUNK_HOST,
            port=SPLUNK_PORT,
            username=SPLUNK_USERNAME,
            password=SPLUNK_PASSWORD,
            verify=False
        )
        
        # 4. RUN THE TEST
        trigger_test_event(service)

    except Exception as e:
        print(f"❌ ERROR: Could not connect to Splunk: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()