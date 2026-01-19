"""
########### The Script's Checklist ###############

YAML Syntax: It checks if the file is a valid YAML document (e.g., no messy indentation or missing colons).

Presence of name: Ensures the detection has a title so you know what the alert is called in Splunk.

Presence of id: Confirms there is a unique ID to track this rule throughout its lifecycle.

Detection Block: Verifies that a detection section exists where the "meat" of the rule should be.

Search Logic: Checks specifically for the search key to ensure there is an actual SPL query to run.

Schedule: Ensures a schedule is defined so Splunk knows how often to run the search.

Exit Code: It tells your computer (and later GitHub) "Success (0)" or "Failure (1)," which is the "Code" part of Detection as Code.
"""
import yaml
import os
import sys

def validate_detection_file(file_path):
    """Checks if a YAML file has the required fields for our Splunk lab."""
    # These are the 'Must-Have' keys in your YAML file
    required_fields = ['name', 'id', 'detection', 'schedule']
    
    try:
        with open(file_path, 'r') as f:
            # Step 1: Check if the YAML is formatted correctly (indentation, colons, etc.)
            data = yaml.safe_load(f)
            
        # Step 2: Check if any of our required top-level fields are missing
        missing = [field for field in required_fields if field not in data]
        
        if missing:
            print(f"❌ {file_path}: Missing required fields: {', '.join(missing)}")
            return False
            
        # Step 3: Dig deeper—make sure there is an actual SPL search string inside
        if 'search' not in data['detection']:
            print(f"❌ {file_path}: Missing 'search' logic inside the detection block.")
            return False
            
        print(f"✅ {file_path}: Passed validation.")
        return True

    except yaml.YAMLError as exc:
        # This catches "Syntax Errors" (like if you used a Tab instead of Spaces)
        print(f"🚨 {file_path}: Invalid YAML Syntax! Error: {exc}")
        return False
    except Exception as e:
        print(f"🚨 {file_path}: Unexpected error: {e}")
        return False

if __name__ == "__main__":
    # The folder where we keep our rules
    detections_path = 'detections'
    all_valid = True

    print("--- Starting Detection Validation ---")
    
    # Look through every file in the /detections folder
    if not os.path.exists(detections_path):
        print(f"🚨 Error: The folder '{detections_path}' was not found.")
        sys.exit(1)

    for filename in os.listdir(detections_path):
        if filename.endswith(".yml") or filename.endswith(".yaml"):
            full_path = os.path.join(detections_path, filename)
            if not validate_detection_file(full_path):
                all_valid = False

    # --- THE MISSING PART IS BELOW ---
    
    if not all_valid:
        print("--- Validation FAILED: Fix the errors above ---")
        sys.exit(1)
    else:
        print("--- Validation SUCCESS: All rules are healthy ---")
        sys.exit(0)