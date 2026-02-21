import sys

"""
RSA signature data
These could be any values that meet the criteria of RSA
"""
P = 4013756539255022581843
Q = 4032658848359024928157
N = P * Q
E = 0x10001


"""
Compute an FNV1A hash of bytes using a slightly changed algorithm
This matches the algorithm used in the compiled FlipVM binary
"""
def fnv1a_hash(data: bytes) -> int:
    hash_val = 0x3140101438
    for byte in data:
        b = 0
        for j in range(8):
            b |= (byte << (8 * j))
        hash_val = (hash_val * 8675309) ^ b
    hash_val &= 0xFFFFFFFFFFFFFFFF
    return hash_val


"""
Driver function to patch code.flp to recover the flag
"""
def main(codeFlpPath):
    # Read the virtual code file
    try:
        with open(codeFlpPath, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f'Failed to read {codeFlpPath}')
        print(e)
        exit()

    # Skip the header information
    code = bytearray(data[3+128+3+128+4:])

    # MODE 1
    bigInsn = b'\x58\x01\x01'

    # MOV R0, 0x243f245f5f6e316733625f676e216b6340685f2368545f54654c5f5f243f24
    movInsn = b'\x28\x88\x1f\x24\x3f\x24\x5f\x5f\x4c\x65\x54\x5f\x54\x68\x23\x5f\x68\x40\x63\x6b\x21\x6e\x67\x5f\x62\x33\x67\x31\x6e\x5f\x5f\x24\x3f\x24'

    # Calculate offsets to where we want to be in the code
    mutateOffs = 0xfa1
    bigOffs = mutateOffs - len(bigInsn) - len(movInsn)
    movOffs = mutateOffs - len(movInsn)
    
    # Apply patches
    code[bigOffs:bigOffs+len(bigInsn)] = bigInsn
    code[movOffs:movOffs+len(movInsn)] = movInsn

    # Set the entrypoint to the first injected instruction
    entrypoint = bigOffs

    # Calculate the file header
    h = fnv1a_hash(code)
    signature = pow(h, E, N)
    xor = (signature ^ entrypoint) & 0xFFFFFFFF
    flpHdr = b'FLP' + \
             N.to_bytes(128, byteorder="little") + \
             E.to_bytes(3, byteorder="little") + \
             signature.to_bytes(128, byteorder='little') + \
             xor.to_bytes(4, byteorder="little")

    # Rewrite the virtual code file
    with open('patched.flp', 'wb') as f:
        f.write(flpHdr)
        f.write(code)


"""
Entry point
"""
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'USAGE: python3 {sys.argv[0]} /path/to/code.flp')
        exit()
    main(sys.argv[1])
