import csv

def filter_csv(input_file, output_file):
    # Read the CSV file
    with open(input_file, 'r') as infile:
        reader = csv.reader(infile)
        rows = list(reader)

    # Filter the rows
    filtered_rows = []
    function_register_map = {}

    for row in rows:
        if len(row) != 6:
            continue
        function_name, _, offset, _, types, _ = row
        base_register = offset.split(" ")[0]

        if types == "write other [TODO]":
            key = (function_name, base_register)
            if key not in function_register_map:
                function_register_map[key] = []
            function_register_map[key].append(row)

    # Keep only the first and last items for each (function_name, base_register) pair
    for key, value in function_register_map.items():
        if len(value) > 1:
            filtered_rows.append(value[0])
            filtered_rows.append(value[-1])

    # Write the filtered rows to a new CSV file
    with open(output_file, 'w', newline='') as outfile:
        writer = csv.writer(outfile)
        writer.writerows(filtered_rows)

# Specify the input and output CSV file paths
input_file = '/home/ppw/Documents/on-the-fly-compartment/bin-project/result.csv'
output_file = './output.txt'

filter_csv(input_file, output_file)
