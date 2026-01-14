#!/bin/bash

# --- Configuration ---
# Define the array of secrets to loop through
SECRETS_ARRAY=(2300 4600 6820)

# Output file for the final averages
RESULTS_FILE="results_64_dpss.csv"

# Ensure the logs directory exists
mkdir -p logs

# Initialize the results file with a header
echo "Secrets,Average_Metric,TwoThirds_Metric" > "$RESULTS_FILE"

# --- Functions ---

# Function to extract a value from the output string based on a label
get_value() {
    local label="$1"
    local text="$2"
    echo "$text" | grep "$label" | awk -F': ' '{print $2}' | tr -d '[:space:]'
}

# --- Main Execution ---

for secret in "${SECRETS_ARRAY[@]}"; do
    echo "=========================================="
    echo "Starting batch for num_secrets = $secret"
    echo "=========================================="

    # 1. Edit fabfile.py to set num_secrets
    # Uses sed to replace "num_secrets = <number>" with "num_secrets = $secret"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # MacOS sed requires an empty string for -i
        sed -i '' "s/num_secrets *= *[0-9]\{1,\}/num_secrets = $secret/" fabfile.py
    else
        # Standard Linux sed
        sed -i "s/num_secrets *= *[0-9]\{1,\}/num_secrets = $secret/" fabfile.py
    fi

    # Flag to control the retry mechanism (2.e)
    batch_has_valid_data=false

    # Repeat this batch as long as there is NO valid reading (2.e)
    j=0
    while [ "$batch_has_valid_data" = false ]; do
        
        # Reset accumulators for this batch of 3
        sum_average=0
        sum_twothird=0
        valid_count=0

        # Sub-loop of size 3 (2)
        for i in {1..3}; do
            echo "--- Iteration $i of 3 (Secrets: $secret) ---"

            # 2.a. Execute fab remote (1st time) or fab rerun (2nd+)
            if [ "$j" -eq 0 ]; then
                echo "Executing: fab remote"
                fab rerun
            else
                echo "Executing: fab rerun"
                fab rerun
            fi

            # 2.b. Wait for 3 minutes and execute fab kill
            echo "Waiting for 3 minutes..."
            sleep 75
            echo "Executing: fab kill"
            fab kill

            # 2.c. Execute fab logs, rename and move
            echo "Pulling logs..."
            fab logs
            
            # NOTE: We assume 'fab logs' downloads a file. 
            # Please ensure the command below matches the actual name of the file 
            # downloaded by 'fab logs'. Here we assume it defaults to 'syncer.log'.
            # If the name is dynamic, you may need to use wildcards (e.g., *.log).
            DOWNLOADED_FILE="syncer.log" 
            
            TARGET_FILE="logs/syncer-logs-${secret}-${i}.log"

            if [ -f "$DOWNLOADED_FILE" ]; then
                mv "$DOWNLOADED_FILE" "$TARGET_FILE"
            else
                echo "Warning: Log file not found after 'fab logs'. Skipping parsing."
                continue
            fi

            # 2.d. Run command python3 <logfile> and extract results
            echo "Analyzing $TARGET_FILE..."
            # Capture standard output
            OUTPUT=$(python3 latency_print.py "$TARGET_FILE")
            echo "Output received:"
            echo "$OUTPUT"

            # Extract values using helper function
            val_avg=$(get_value "Average" "$OUTPUT")
            val_23rd=$(get_value "2/3rd" "$OUTPUT")

            # Check if both values were found and are not empty
            if [[ -n "$val_avg" && -n "$val_23rd" ]]; then
                echo "Valid data found: Avg=$val_avg, 2/3rd=$val_23rd"
                
                # Add to sums using awk for floating point math
                sum_average=$(awk "BEGIN {print $sum_average + $val_avg}")
                sum_twothird=$(awk "BEGIN {print $sum_twothird + $val_23rd}")
                
                ((valid_count++))
            else
                echo "Output did not contain required metrics. Ignoring this run."
            fi
            ((j++))
        done

        # 2.e. Check if we got at least one valid reading in the loop of 3
        if [ "$valid_count" -gt 0 ]; then
            batch_has_valid_data=true
            
            # 3. Compute Averages and Write to file
            final_avg=$(awk "BEGIN {print $sum_average / $valid_count}")
            final_23rd=$(awk "BEGIN {print $sum_twothird / $valid_count}")
            
            echo "Batch Complete. Writing results..."
            echo "$secret, $final_avg, $final_23rd" >> "$RESULTS_FILE"
            echo "Saved: $secret, $final_avg, $final_23rd"
        else
            echo "!!! No valid values found in the last 3 iterations. Retrying the batch..."
        fi
    done
done

echo "All experiments completed."
