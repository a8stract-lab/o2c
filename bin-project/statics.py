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
output_path = "C:\\Users\\mouse\\Code\\research\\ebpf\\result\\"
output_file = open(output_path+"result.csv","w+")
csv_writer = csv.writer(output_file)

class funcInfo:
    def __init__(self):
        self.entrypoint = 0
        self.name = ''

class statics():
    def __init__(self):
        self.total = 0
        self.insCnt = {"MOV_WRITE":0,"MOV_READ":0,"CALL_DIRECT":0,"CALL_INDIRECT":0,"RET":0,"XCHG":0,"XCHG_WRITE":0,"STOS":0,"OUT":0,"REP":0}
    def statics(self):
        statics_file = open(output_path+"statics.txt","w+")
        statics_file.write("total num of kernel instructions: "+str(self.total)+"\n")
        for key in self.insCnt:
            statics_file.write(key+": "+str(self.insCnt[key])+" rate: "+str(1.0*self.insCnt[key]/self.total)+"\n")
        statics_file.close()

def getHelp(x):
    help(x)
    exit(0)

def log(*msg):
    if not feature:
        # print >> output_file, msg
        print(msg)
def log2csv(function,offset,target_addr,instruction,type):
    # dest_pattern = re.compile(r'.word ptr \[.*\]')
    # _t = re.findall(dest_pattern,target_addr)
    if "ptr" in target_addr:
        target_addr = re.sub(r'.word ptr ','',target_addr)
    csv_writer.writerow([function,offset.rstrip("L"),target_addr,instruction,type])

def insClassification(insStatics,funcinfo,insAddress,codeUnit,n,mnemonic):
    if (mnemonic.startswith('CALL')):
        # print(codeUnit.getOperandType(0),numOperands,OperandType.ADDRESS)
        if codeUnit.getOperandType(0) == (OperandType.ADDRESS | OperandType.CODE):
            # log("\t this is a direct call") # call register
            insStatics.insCnt["CALL_DIRECT"] += 1
            log(funcinfo.name+"+"+hex(insAddress-funcinfo.entrypoint)+" direct call",codeUnit)
            log2csv(funcinfo.name,hex(insAddress-funcinfo.entrypoint),codeUnit.getDefaultOperandRepresentation(0),codeUnit,"direct call")
        else:
            # log("\t this is a in-direct call") # call address
            insStatics.insCnt["CALL_INDIRECT"] += 1
            log(funcinfo.name+"+"+hex(insAddress-funcinfo.entrypoint)+" in-direct call",codeUnit)
            log2csv(funcinfo.name,hex(insAddress-funcinfo.entrypoint),codeUnit.getDefaultOperandRepresentation(0),codeUnit,"in-direct call")
    
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
    # f funcAddr not in [0xffffffff831b5c4b]:
    #     continue
    log("function: ",function.getName()," with addr ",hex(funcAddr))
    codeUnitIterator = currentProgram.getListing().getCodeUnits(function.getBody(), True)

    for codeUnit in codeUnitIterator:
        insCount += 1
        insAddress = codeUnit.getAddress().getOffsetAsBigInteger()
        # ops = codeUnit.getOpObjects(0)
        mnemonic = codeUnit.getMnemonicString() # first op
        numOperands = codeUnit.getNumOperands()
        # log(insAddress,codeUnit)
        insClassification(insStatics,funcinfo,insAddress,codeUnit,numOperands,mnemonic)

insStatics.total = insCount
insStatics.statics()
            