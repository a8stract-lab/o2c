import csv
import re

tmp = open("tmp.txt","w")

def parse_line(line):
    target = line[2]
    pattern = re.compile(r'ctx->(\b\w+)')
    result = re.findall(pattern,target)
    if len(result) != 0:
        return result[0]
with open('result.csv')as f:
    reader = csv.reader(f)
    headers = next(reader)
    times = 1
    last_reg = ""
    entry_line = ""
    last_function = ""
    entries = {}
    sequence = []
    for row in reader:
        if len(row) == 0:
            continue
        if "write stack" in row[4]:
            last_reg = "invalid"
            continue
        if "write" not in row[4]:
            last_reg = "invalid"
            continue
        # avoid only [register], but this is not fully correct
        if  "+" not in row[2] and times == 1:
            last_reg = "invalid"
            continue
        if "gs" in row[2]:
            last_reg = "invalid"
            continue

        # if "hmac_create" in row[0]:
        #    print(row,reg_used,last_reg,func,last_function)
        reg_used = parse_line(row)
        func = row[0]
        if reg_used == last_reg and func == last_function:
            sequence.append(row)
            times += 1
        else:
            if times > 1:
                for i in range(len(sequence)):
                    print(sequence[i],file=tmp)
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
print(tot,entries)
print(tot,entries,file=tmp)


tmp.close()