import re
from collections import defaultdict

seconds = 1000000000
milliseconds = 1000000

def analyze_distribution(numbers, step):
    distribution = defaultdict(int)
    
    # Find the minimum and maximum numbers in the array
    # min_num = min(numbers)
    min_num = 0
    max_num = ((max(numbers)//step) + 1) * step
    
    # Initialize the distribution dictionary
    for i in range(min_num, max_num + 1, step):
        distribution[i] = 0
    
    # Count the frequency of numbers in each range
    for num in numbers:
        bucket = (num // step) * step
        distribution[bucket] += 1
    
    return distribution


def read_numbers_from_file(file_path):
    numbers = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()  # Remove leading and trailing whitespaces
            if re.fullmatch(r'\d+', line):  # Check if the line is a number
                numbers.append(int(line))
    return numbers


if __name__ == '__main__':
    # file_path = 'trace-kmalloc.txt'  # Replace with the path to your file
    # file_path = 'trace-kmem_cache_alloc.txt'  # Replace with the path to your file
    # file_path = 'trace-mm_page_alloc.txt'  # Replace with the path to your file
    all_data = list()
    numbers = read_numbers_from_file('trace-kmalloc.txt')
    all_data += numbers
    numbers = read_numbers_from_file('trace-kmem_cache_alloc.txt')
    all_data += numbers
    numbers = read_numbers_from_file('trace-mm_page_alloc.txt')
    all_data += numbers

    step = seconds * 10
    distribution = analyze_distribution(all_data, step)
    
    # Print the distribution
    for bucket, count in sorted(distribution.items()):
        print(f"{(bucket//step)+1}: {count}")
    # print("Numbers in the file:", numbers)