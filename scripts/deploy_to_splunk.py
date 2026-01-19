import os
import sys
import yaml
import splunklib.client as client

# 1. Retrieve Sensitive Data from Environment Variables
# Locally, these come from your shell; in GitHub, they come from Secrets.
SPLUNK_HOST = os.getenv('SPLUNK_HOST', 'localhost')
SPLUNK_PORT = 8089
SPLUNK_USERNAME = os.getenv('SPLUNK_USERNAME', 'admin')
SPLUNK_PASSWORD = os.getenv('SPLUNK_PASSWORD')

# Safety Check: Exit if the password isn't found
if not SPLUNK_PASSWORD:
    print("ERROR: SPLUNK_PASSWORD environment variable not set.")
    sys.exit(1)

def deploy_rule():
    try:
        # 2. Connect to Splunk using the secure variables
        service = client.connect(
            host=SPLUNK_HOST,
            port=SPLUNK_PORT,
            username=SPLUNK_USERNAME,
            password=SPLUNK_PASSWORD
        )
        print("Connected to Splunk successfully.")
        
        # ... rest of your parsing and deployment logic ...

    except Exception as e:
        print(f"Deployment failed: {e}")

if __name__ == "__main__":
    deploy_rule()