import re
import os
import sys

def parse_log_file(file_path):
    """
    Parses a log file to find specific protocol completion lines 
    and calculates the average latency for each occurrence.
    """
    
    # Check if file exists
    if not os.path.exists(file_path):
        print(f"Error: The file '{file_path}' was not found.")
        return

    # Regex pattern explanation:
    # latency\s+ -> matches the word "latency" followed by whitespace
    # \[ -> matches the literal opening bracket
    # ([\d,\s]+) -> Capture Group 1: Matches digits, commas, and whitespace inside the brackets
    # \] -> matches the literal closing bracket
    pattern = re.compile(r"latency\s+\[([\d,\s]+)\]")
    
    match_count = 0

    try:
        with open(file_path, 'r') as file:
            for line_number, line in enumerate(file, 1):
                # We filter first by the specific text to avoid running regex on every single line
                if "All n nodes completed the protocol" in line:
                    match = pattern.search(line)
                    if match:
                        match_count += 1
                        # Extract the string content inside the brackets (e.g., "13009, 13010")
                        numbers_str = match.group(1)
                        
                        # Convert the string list into a list of integers
                        # We split by comma and strip whitespace for safety
                        try:
                            latencies = [int(num.strip()) for num in numbers_str.split(',') if num.strip()]
                            
                            if latencies:
                                # Calculate Average
                                average = sum(latencies) / len(latencies)
                                
                                # Calculate 2/3rd Value (approx 67th percentile)
                                # We sort the list to ensure we are getting the value by magnitude/rank
                                sorted_latencies = sorted(latencies)
                                index_2_3 = int(len(sorted_latencies) * (2/3))
                                # Safety check to ensure index is within bounds (though math guarantees it for len >= 1)
                                index_2_3 = min(index_2_3, len(sorted_latencies) - 1)
                                value_2_3 = sorted_latencies[index_2_3]

                                print(f"Average: {average:.2f}")
                                print(f"2/3rd: {value_2_3}")
                                
                        except ValueError:
                            pass

    except Exception:
        pass

if __name__ == "__main__":
    # Create the sample file if it doesn't exist so the script is runnable immediately
    if len(sys.argv) != 2:
        print("Usage: python script.py <filename>")
        sys.exit(1)

    filename = sys.argv[1]
    if not os.path.exists(filename):
        print(f"'{filename}' not found. Please create it or use the generated text file.")
    else:
        parse_log_file(filename)
