import csv
import os

cache = 'kmalloc-192'

path = '/home/ppw/Documents/on-the-fly-compartment/train-data/'

def parse_and_classify_csv(input_file):
    # Dictionary to store lines classified by type
    classified_data = {}
    
    # Read the CSV file
    with open(input_file, 'r') as csvfile:
        csvreader = csv.reader(csvfile)
        
        # Skip header if needed
        # next(csvreader)
        
        # Loop through each row in the CSV
        for row in csvreader:
            type_, content = row[0], row[1]
            
            # Classify and store the content by type
            if type_ not in classified_data:
                classified_data[type_] = []
            classified_data[type_].append(content)
    
    # Write the classified data into separate files
    for type_, contents in classified_data.items():
        xpath = path + cache + '/' + type_
        with open(xpath, 'w') as f:
            for content in contents:
                f.write(f"{content}\n")

if __name__ == "__main__":
    input_file = '/home/ppw/Documents/on-the-fly-compartment/ebpf-project/projects/' + cache + '.csv'  # Replace with your CSV file name
    parse_and_classify_csv(input_file)