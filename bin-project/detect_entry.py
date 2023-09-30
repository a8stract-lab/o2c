import csv
import re

tmp = open("need optimized.txt","w")
optimized_result = open("optimized_result.csv","w")
csv_writer = csv.writer(optimized_result)
need_optimized = 0

def parse_line(line):
    target = line[2]
    pattern = re.compile(r'ctx->(\b\w+)')
    result = re.findall(pattern,target)
    if len(result) != 0:
        return result[0]

def find_border(sequence):
    print("optimized",file=tmp)
    if len(sequence) == 2:
        for i in range(len(sequence)):
            print(sequence[i],file=tmp)
        return 0
    else:
        _min = 2<<31
        _max = -_min
        lower_bound = ""
        upper_bound = ""
        for line in sequence:
            offset = 0
            target = line[2].split(" ")
            if len(target) == 1:
                offset = 0
            elif len(target) == 3:
                offset = int(target[2],16)
            else:
                print("cannot optimize",file=tmp)
                return -1           
                # input()
            if offset < _min:
                _min = offset
                lower_bound = line
            if offset > _max:
                _max = offset
                upper_bound = line
        print(lower_bound,file=tmp)
        print(upper_bound,file=tmp)
        csv_writer.writerow(lower_bound)
        csv_writer.writerow(upper_bound)
    return 0


csv_writer.writerow(["function","offset","target addr","instruction","type"])
with open('result.csv')as f:
    reader = csv.reader(f)
    headers = next(reader)
    times = 1
    last_reg = ""
    entry_line = ""
    last_function = ""
    entries = {}
    sequence = []

    optimized_entry = 0
    cannot_optimized_entry = [0,0]

    for row in reader:
        if len(row) == 0:
            continue
        if "write other" not in row[4]:
            csv_writer.writerow(row)
            continue
        if "write stack" in row[4]:
            last_reg = "invalid"
            csv_writer.writerow(row)
            continue
        if "write" not in row[4]:
            last_reg = "invalid"
            csv_writer.writerow(row)
            continue
        # avoid only [register], but this is not fully correct
        if  "+" not in row[2] and times == 1:
            last_reg = "invalid"
            csv_writer.writerow(row)
            continue
        if "gs" in row[2]:
            last_reg = "invalid"
            csv_writer.writerow(row)
            continue
        need_optimized += 1
        # if "hmac_create" in row[0]:
        #    print(row,reg_used,last_reg,func,last_function)
        reg_used = parse_line(row)
        func = row[0]
        if reg_used == last_reg and func == last_function:
            sequence.append(row)
            times += 1
        else:
            if times > 1:
                print(times,file=tmp)
                for i in range(len(sequence)):
                    print(sequence[i],file=tmp)
                if find_border(sequence) == -1:
                    cannot_optimized_entry[0] += 1
                    cannot_optimized_entry[1] += times

                    for i in range(len(sequence)):
                        csv_writer.writerow(sequence[i])
                else:
                    optimized_entry += 1
                # print(reg_used,last_reg,file=tmp)
                # input()
                # print(entry_line,"\t",times,"\t",last_reg)
                if times not in entries:
                    entries[times] = 1
                else:
                    entries[times] += 1
                
            sequence.clear()
            sequence.append(row)

            entry_line = row
            last_reg = reg_used
            last_function = func
            times = 1
f.close()

tot = 0

for key in entries:
    tot += entries[key]
print(need_optimized,tot,entries)
print("optimized: ",optimized_entry,",cannot optimized: ",cannot_optimized_entry)
print(need_optimized,tot,entries,file=tmp)


tmp.close()
optimized_result.close()