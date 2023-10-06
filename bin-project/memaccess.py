from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.mem import MemoryAccessException

output_path = "/home/ppw/Documents/on-the-fly-compartment/bin-project/memaccess.txt"
# Get the current program
program = getCurrentProgram()

# Get the listing of the current program
listing = program.getListing()

# Get the memory of the current program
memory = program.getMemory()

# Get the first and last addresses of the program
min_address = program.getMinAddress()
max_address = program.getMaxAddress()

# Iterate through all instructions in the program
instruction = getFirstInstruction()
with open(output_path, 'w') as f:
    while instruction is not None and instruction.getAddress() <= max_address:
        # Get references made by the instruction
        references = instruction.getReferencesFrom()
        for ref in references:
            # Check if the reference is a memory access (read or write)
            if ref.isMemoryReference():
                # Print the instruction and its address
                # print(f'Memory Access Instruction: {instruction} at {instruction.getAddress()}')
                x = str(instruction)
                if x.find('[') != -1:
                    # print(x)
                    f.write(x)
                    f.write('\n')
    
        # Get the next instruction
        instruction = getInstructionAfter(instruction)

# End of script
print("Script execution completed.")