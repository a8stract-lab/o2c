import os
import csv
import re
from collections import defaultdict

def extract_data_from_file(file_path):
    req_per_sec = []
    transfer_rate = []
    
    with open(file_path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            match_req = re.search(r"Requests per second:\s+([\d.]+)", line)
            if match_req:
                req_per_sec.append(float(match_req.group(1)))
            
            match_transfer = re.search(r"Transfer rate:\s+([\d.]+)", line)
            if match_transfer:
                transfer_rate.append(float(match_transfer.group(1)))
                
    return req_per_sec, transfer_rate

def main():
    directory_path = "ab-res"
    output_csv_req = "requests_per_second.csv"
    output_csv_rate = "transfer_rate.csv"

    all_req_data = defaultdict(list)
    all_rate_data = defaultdict(list)

    # Loop through each file in the directory
    for filename in os.listdir(directory_path):
        if filename.endswith(".txt"):
            file_path = os.path.join(directory_path, filename)
            req_per_sec, transfer_rate = extract_data_from_file(file_path)
            
            all_req_data[filename] = req_per_sec
            all_rate_data[filename] = transfer_rate

    # Write to CSV for Requests per Second
    with open(output_csv_req, 'w', newline='') as csvfile_req:
        csv_writer_req = csv.writer(csvfile_req)
        headers = ["Index"] + list(all_req_data.keys())
        csv_writer_req.writerow(headers)
        
        for i in range(len(next(iter(all_req_data.values())))):
            row = [i] + [all_req_data[filename][i] for filename in all_req_data.keys()]
            csv_writer_req.writerow(row)

    # Write to CSV for Transfer Rate
    with open(output_csv_rate, 'w', newline='') as csvfile_rate:
        csv_writer_rate = csv.writer(csvfile_rate)
        headers = ["Index"] + list(all_rate_data.keys())
        csv_writer_rate.writerow(headers)
        
        for i in range(len(next(iter(all_rate_data.values())))):
            row = [i] + [all_rate_data[filename][i] for filename in all_rate_data.keys()]
            csv_writer_rate.writerow(row)

if __name__ == "__main__":
    main()
