import re
import sys

def is_number_list(text):
    """Check if the comma/space separated values are all numeric."""
    parts = text.replace(',', ' ').split()
    try:
        [float(p) for p in parts]
        return True
    except ValueError:
        return False

def extract_and_compute(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()

    last_line = lines[-1].strip()

    # Extract all bracketed contents
    arrays = re.findall(r'\[([^\]]+)\]', last_line)
    if not arrays:
        raise ValueError("No arrays found in the last line")

    # Find the first array that contains *only* numbers
    numeric_array_str = None
    for arr in arrays:
        if is_number_list(arr):
            numeric_array_str = arr
            break

    if numeric_array_str is None:
        raise ValueError("No numeric array found in the last line")

    # Convert to list of floats
    numbers = list(map(float, numeric_array_str.replace(',', ' ').split()))

    # Compute average
    avg = sum(numbers) / len(numbers)

    # Compute 2/3rd index
    index_2_3 = int((2 * len(numbers)) / 3)
    value_2_3 = numbers[index_2_3]

    return avg, value_2_3


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <filename>")
        sys.exit(1)

    filename = sys.argv[1]
    average, two_thirds_value = extract_and_compute(filename)

    print("Average:", average)
    print("2/3rd element:", two_thirds_value)

