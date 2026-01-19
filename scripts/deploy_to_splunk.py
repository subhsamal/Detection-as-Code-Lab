import os
import sys
import splunklib.client as client
import urllib3

# 1. SILENCE SSL WARNINGS
# Since local Splunk uses a self-signed certificate, we tell Python to 
# trust it for this lab. This prevents the "SSL: CERTIFICATE_VERIFY_FAILED" error.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 2. RETRIEVE CONFIGURATION FROM ENVIRONMENT
# GitHub Actions will inject your Secrets into these variables.
SPLUNK_HOST = os.getenv('SPLUNK_HOST', 'localhost')
# The tunnel port changes every time; we convert the string to an integer.
SPLUNK_PORT = int(os.getenv('SPLUNK_PORT', 8089))
SPLUNK_USERNAME = os.getenv('SPLUNK_USERNAME', 'admin')
SPLUNK_PASSWORD = os.getenv('SPLUNK_PASSWORD')

# Safety Check: Stop the script if secrets are missing
if not SPLUNK_PASSWORD:
    print("❌ ERROR: SPLUNK_PASSWORD environment variable not set.")
    sys.exit(1)

def connect_to_splunk():
    """Establishes a connection to the Splunk Management API."""
    try:
        print(f"--- Attempting to connect to Splunk ---")
        print(f"Host: {SPLUNK_HOST}")
        print(f"Port: {SPLUNK_PORT}")
        
        # 3. ESTABLISH THE CONNECTION
        # 'verify=False' is critical for local labs using self-signed certs.
        service = client.connect(
            host=SPLUNK_HOST,
            port=SPLUNK_PORT,
            username=SPLUNK_USERNAME,
            password=SPLUNK_PASSWORD,
            verify=False
        )
        
        print("✅ SUCCESS: Connected to Splunk successfully.")
        return service

    except Exception as e:
        print(f"❌ FAILURE: Could not connect to Splunk.")
        print(f"Error details: {e}")
        # Exiting with 1 ensures the GitHub Action shows a RED failure icon.
        sys.exit(1)

def main():
    service = connect_to_splunk()
    
    # 4. PLACEHOLDER FOR DEPLOYMENT LOGIC
    # This is where you would add code to upload your .conf files or apps.
    print(f"Splunk Version: {service.info['version']}")
    print("Deployment logic complete.")

if __name__ == "__main__":
    main()