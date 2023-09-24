#Instruction statics in binary file (x86_64)
#@Qinrun Dai
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


from ghidra.program.model.address import AddressSpace
from ghidra.program.model.symbol import SymbolTable
from ghidra.program.model.listing import Function, CodeUnit
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import CodeUnitIterator
from aQute.bnd import properties
from ghidra.program.model.lang import OperandType
from ghidra.program.model.pcode import PcodeOp
import csv
import re

debug = 0
feature = 1
output_path = "/home/ppw/Documents/on-the-fly-compartment/bin-project/"
output_file = open(output_path+"result.csv","w+")
tmp_file = open(output_path+"tmp.txt","w+")
csv_writer = csv.writer(output_file)
g_previousCall = False

class funcInfo:
    def __init__(self):
        self.entrypoint = 0
        self.name = ''

class statics():
    def __init__(self):
        self.total = 0
        self.insCnt = {"MOV_WRITE":0,"MOV_READ":0,"CALL_DIRECT":0,"CALL_INDIRECT":0,"RET":0,"XCHG":0,"XCHG_WRITE":0,"STOS":0,"OUT":0,"REP":0,"CALL_NEXT":0}
    def statics(self):
        statics_file = open(output_path+"statics.txt","w+")
        statics_file.write("total num of kernel instructions: "+str(self.total)+"\n")
        for key in self.insCnt:
            statics_file.write(key+": "+str(self.insCnt[key])+" rate: "+str(1.0*self.insCnt[key]/self.total)+"\n")
        statics_file.close()

def log2tmp(*msg):
    print >> tmp_file, msg

def parseOperand(raw_expression):
    # filter use dirty trick
    # if " " not in raw_expression:
    #    return raw_expression#.strip("[]")
    raw_expression = raw_expression.replace("["," ")
    raw_expression = raw_expression.replace("]"," ")
    tokens = raw_expression.split(" ")
    expression = ""
    prefix = "ctx->"
    for token in tokens:
        if token == "":
            continue
        if ":" in token:
            expression += prefix+token[:token.index(":")].lower()
            expression += "+"
        elif token.startswith("-"):
            expression = expression[:-1]
            expression += "-" + token[1:]
        elif token == "+" or token == "-":
            expression += token
        elif token.startswith("0x"):
            expression += token
        else:
            expression += prefix+token.lower()
    final = ""
    for i in range(len(expression)):
        if expression[i] in ["+","-","*"] and expression[i+1] != ">":
            final += " "+expression[i]+" "
        else:
            final += expression[i]
    return final

def getHelp(x):
    help(x)
    exit(0)

def log(*msg):
    if not feature:
        # print >> output_file, msg
        print(msg)
def log2csv(function,offset,target_addr,instruction,type,need_parse=True):
    # dest_pattern = re.compile(r'.word ptr \[.*\]')
    # _t = re.findall(dest_pattern,target_addr)
    if "ptr" in target_addr:
        target_addr = re.sub(r'(.*word|byte) ptr ','',target_addr)
    if need_parse:
        csv_writer.writerow([function,offset.rstrip("L"),parseOperand(target_addr),instruction,type])
    else:
        csv_writer.writerow([function,offset.rstrip("L"),target_addr,instruction,type])

def insClassification(insStatics,funcinfo,insAddress,codeUnit,n,mnemonic):

    global g_previousCall

    if g_previousCall:
        log2csv(funcinfo.name,hex(insAddress-funcinfo.entrypoint)," ",codeUnit,"call next")
        insStatics.insCnt["CALL_NEXT"] += 1
        g_previousCall = False

    if (mnemonic.startswith('CALL')):
        # print(codeUnit.getOperandType(0),numOperands,OperandType.ADDRESS)
        if codeUnit.getOperandType(0) == (OperandType.ADDRESS | OperandType.CODE):
            # log("\t this is a direct call") # call register
            insStatics.insCnt["CALL_DIRECT"] += 1
            targetFunAddr = codeUnit.getOpObjects(0)[0]
            calledFunction = getFunctionAt(targetFunAddr)
            log(funcinfo.name+"+"+hex(insAddress-funcinfo.entrypoint)+" direct call",codeUnit)
            log2csv(funcinfo.name,hex(insAddress-funcinfo.entrypoint),calledFunction.toString(),codeUnit,"direct call",False)
        else:
            # log("\t this is a in-direct call") # call address
            insStatics.insCnt["CALL_INDIRECT"] += 1
            log(funcinfo.name+"+"+hex(insAddress-funcinfo.entrypoint)+" in-direct call",codeUnit)
            log2csv(funcinfo.name,hex(insAddress-funcinfo.entrypoint),codeUnit.getDefaultOperandRepresentation(0),codeUnit,"in-direct call")
        g_previousCall = True
    
    if (mnemonic.startswith('RET')):
        # log("\t this is a ret")
        insStatics.insCnt["RET"] += 1
        log(funcinfo.name+"+"+hex(insAddress-funcinfo.entrypoint)+" ret",codeUnit)
        log2csv(funcinfo.name,hex(insAddress-funcinfo.entrypoint)," ",codeUnit,"ret")
        
    if (mnemonic.startswith('MOV')):
        if codeUnit.getOperandType(0) == OperandType.REGISTER:
            if (codeUnit.getOperandType(1) & OperandType.ADDRESS) or (codeUnit.getOperandType(1) & OperandType.DYNAMIC):
                insStatics.insCnt["MOV_READ"] += 1
            elif codeUnit.getOperandType(1) != OperandType.REGISTER and codeUnit.getOperandType(1) != OperandType.SCALAR:
                # ignore mov reg, imm and mov reg, reg
                print(codeUnit)
            return # we do not consider read operation in
        
        if codeUnit.getOperandType(0) == (OperandType.ADDRESS | OperandType.REGISTER):
            # this condition contains: mov reg,reg and mov reg,addr , and we do not want op-1 is reg type
            if codeUnit.getOperandType(1) != OperandType.REGISTER:
                insStatics.insCnt["MOV_READ"] += 1
            return
        
        # get the operand expression
        dest = codeUnit.getDefaultOperandRepresentation(0)

        if codeUnit.getOperandType(0) == ((OperandType.ADDRESS | OperandType.DATA)):
            # log("\t this write data segment")
            insStatics.insCnt["MOV_WRITE"] += 1
            log(funcinfo.name+"+"+hex(insAddress-funcinfo.entrypoint)+" write .data to ",dest)
            log2csv(funcinfo.name,hex(insAddress-funcinfo.entrypoint),dest,codeUnit,"write .data")
        else:
            insStatics.insCnt["MOV_WRITE"] += 1
            # need to examine every op in a operand
            for op in codeUnit.getOpObjects(0):
                if op.toString().startswith("RBP") or op.toString().startswith("RSP"):
                    # log("\t this write stack")
                    log(funcinfo.name+"+"+hex(insAddress-funcinfo.entrypoint)+" write stack to",dest)
                    log2csv(funcinfo.name,hex(insAddress-funcinfo.entrypoint),dest,codeUnit,"write stack")
                    return
                if op.toString().startswith("RIP"):
                    # log("\t this write data segment")
                    log(funcinfo.name+"+"+hex(insAddress-funcinfo.entrypoint)+" write .data to",dest)
                    log2csv(funcinfo.name,hex(insAddress-funcinfo.entrypoint),dest,codeUnit,"write .data")
                    return
            # maybe write to .data, like MOV qword ptr [RAX + RBX*0x8 + 0x80],RDX
            # type ADDR | DYN
            log(funcinfo.name+"+"+hex(insAddress-funcinfo.entrypoint)+" write other [TODO] to",dest)
            log2csv(funcinfo.name,hex(insAddress-funcinfo.entrypoint),dest,codeUnit,"write other [TODO]")
    
    if mnemonic.startswith('XCHG'):
        insStatics.insCnt["XCHG"] += 1
        # now we do not consider XCHG reg, reg
        if (codeUnit.getOperandType(0) != OperandType.REGISTER) or (codeUnit.getOperandType(1) != OperandType.REGISTER):
            insStatics.insCnt["XCHG_WRITE"] += 1

    if mnemonic.startswith('STOS'):
        insStatics.insCnt["STOS"] += 1
    
    if mnemonic.startswith('OUT'):
        insStatics.insCnt["OUT"] += 1

    if mnemonic.startswith('REP'):
        insStatics.insCnt["REP"] += 1

currentProgram = getCurrentProgram()
symbolTable = currentProgram.getSymbolTable()
functions = currentProgram.getFunctionManager().getFunctions(True)
baseAddress = currentProgram.getImageBase().getOffsetAsBigInteger()
log("Base Address: ",hex(baseAddress),"\n")

csv_writer.writerow(["function","offset","target addr","instruction","type"])
insStatics = statics()
insCount = 0
for function in functions:
    funcAddr = function.getEntryPoint().getOffsetAsBigInteger()
    funcinfo = funcInfo()
    funcinfo.entrypoint = funcAddr
    funcinfo.name = function.getName()
    # func restriction to better develop and debug
    # if funcAddr not in [0xffffffff8101e2e0]:
    #     continue
    log("function: ",function.getName()," with addr ",hex(funcAddr))
    codeUnitIterator = currentProgram.getListing().getCodeUnits(function.getBody(), True)

    for codeUnit in codeUnitIterator:
        insCount += 1
        insAddress = codeUnit.getAddress().getOffsetAsBigInteger()
        # ops = codeUnit.getOpObjects(0)
        mnemonic = codeUnit.getMnemonicString() # first op
        numOperands = codeUnit.getNumOperands()
        # print(hex(insAddress),codeUnit)
        insClassification(insStatics,funcinfo,insAddress,codeUnit,numOperands,mnemonic)

insStatics.total = insCount
insStatics.statics()
            