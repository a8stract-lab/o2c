def split_64bit_to_32bit(num_64bit):
    # Extract the back 32 bits by bitwise AND with 0xFFFFFFFF
    back_32bit = num_64bit & 0xFFFFFFFF
    
    # Extract the front 32 bits by right-shifting 32 bits
    front_32bit = (num_64bit >> 32) & 0xFFFFFFFF
    
    return front_32bit, back_32bit

# Example usage
num_64bit = 0x123456789ABCDEF0
front_32bit, back_32bit = split_64bit_to_32bit(num_64bit)

print(f"Original 64-bit integer: {hex(num_64bit)}")
print(f"Front 32 bits: {hex(front_32bit)}")
print(f"Back 32 bits: {hex(back_32bit)}")