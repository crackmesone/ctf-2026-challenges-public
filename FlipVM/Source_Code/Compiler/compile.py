import os
import random
import re
import sys


###
# OpcodeMap class to track which opcode set to use
###
class OpcodeMap():
    def __init__(self):
        self.mode = 0
        self.codes = []
        self.codes.append({ 'MOV':  0x14, 'GET':   0x1e
                          , 'ADD':  0x04, 'SUB':   0x0a, 'MUL':   0x07, 'DIV':  0x13, 'MOD':  0x1b
                          , 'AND':  0x1f, 'OR':    0x0e, 'XOR':   0x0d, 'SHL':  0x0c, 'SHR':  0x0f, 'NOT':   0x15
                          , 'CMP':  0x19, 'JMP':   0x0b, 'CALL':  0x1d, 'RET':  0x16, 'EXIT': 0x06, 'JMPC':   0x03
                          , 'MODE': 0x00, 'PRINT': 0x09, 'SLEEP': 0x05 })

        self.codes.append({ 'MOV':  0x15, 'GET':   0x19
                          , 'ADD':  0x1e, 'SUB':   0x14, 'MUL':   0x11, 'DIV':  0x10, 'MOD':  0x06
                          , 'AND':  0x0d, 'OR':    0x04, 'XOR':   0x0f, 'SHL':  0x1d, 'SHR':  0x1c, 'NOT':  0x1f
                          , 'CMP':  0x03, 'JMP':   0x02, 'CALL':  0x00, 'RET':  0x18, 'EXIT': 0x08, 'JMPC':   0x07
                          , 'MODE': 0x0c, 'PRINT': 0x13, 'SLEEP': 0x01 })

        self.codes.append({ 'MOV':  0x1b, 'GET':   0x10
                          , 'ADD':  0x0f, 'SUB':   0x1c, 'MUL':   0x0a, 'DIV':  0x0c, 'MOD':  0x17
                          , 'AND':  0x15, 'OR':    0x11, 'XOR':   0x12, 'SHL':  0x00, 'SHR':  0x0d, 'NOT':  0x05
                          , 'CMP':  0x1d, 'JMP':   0x19, 'CALL':  0x09, 'RET':  0x1a, 'EXIT': 0x1f, 'JMPC':   0x18
                          , 'MODE': 0x16, 'PRINT': 0x0b, 'SLEEP': 0x08 })

        self.codes.append({ 'MOV':  0x10, 'GET':   0x1f
                          , 'ADD':  0x00, 'SUB':   0x15, 'MUL':   0x0e, 'DIV':  0x17, 'MOD':  0x03
                          , 'AND':  0x04, 'OR':    0x0c, 'XOR':   0x07, 'SHL':  0x12, 'SHR':  0x11, 'NOT':  0x1a
                          , 'CMP':  0x0b, 'JMP':   0x16, 'CALL':  0x0f, 'RET':  0x1c, 'EXIT': 0x05, 'JMPC':   0x02
                          , 'MODE': 0x1d, 'PRINT': 0x01, 'SLEEP': 0x1b })
    def get(self, mneumonic):
        mneumonic = mneumonic.upper()
        if mneumonic not in self.codes[self.mode]:
            return None
        return self.codes[self.mode][mneumonic]
    def has(self, mneumonic):
        mneumonic = mneumonic.upper()
        return mneumonic in self.codes[self.mode]

###
# Register dictionary
# C for counters        (non-volatile)
# P for persistent data (non-volatile)
# R for general purpose (volatile)
###
REGS = { 'C0': 0x00, 'C1': 0x01, 'C2': 0x02, 'C3': 0x03
       , 'P0': 0x04, 'P1': 0x05, 'P2': 0x06, 'P3': 0x07
       , 'R0': 0x08, 'R1': 0x09, 'R2': 0x0A, 'R3': 0x0B, 'R4': 0x0C, 'R5': 0x0D, 'R6': 0x0E, 'R7': 0x0F }

###
# Flag masks for conditional jumps
###
FLAGS = { 'EQ': 0b1000, 'NEQ': 0b0110
        , 'LT': 0b0100, 'LTE': 0b1100
        , 'GT': 0b0010, 'GTE': 0b1010
        , 'ERR': 0b0001 }

###
# Operand types
###
TYPES = { 'T_IMM': 0b00, 'T_NONE': 0b01, 'T_REG': 0b10, 'T_MEM': 0b11 }


###
# Some instructions are not allowed to potentially XOR memory
# For example, an XOR in a small loop with hundreds of iterations would be killer
# Track this with compiler intrinsics
###
tryXor = True
forceXor = False

###
# RSA signature data
###
P = 13309215236911714190055252501729887043185109452814203147674038026855588992498974512602654794584899673285158209427702919678806386750824437636920561407640151
Q = 6759531615623871360698014105623825871862153371743234253530125972765453045616467165911264062488138496158977943798483338633551879749859808193110865724029353
N = P * Q
E = 0x10001


###
# Compute an FNV1A hash of bytes using a slightly changed algorithm
# @param data - Bytes to hash
# @return hash of data as a 64-bit int
###
def fnv1a_hash(data: bytes) -> int:
    hash_val = 0x3140101438
    for byte in data:
        b = 0
        for j in range(8):
            b |= (byte << (8 * j))
        hash_val = (hash_val * 8675309) ^ b
    hash_val &= 0xFFFFFFFFFFFFFFFF
    return hash_val


###############################################################################################################################
###############################################################################################################################
###############################################################################################################################

###
# Parse an operand as a register
###
def parse_register(op):
    op = op.upper()
    if op not in REGS:
        print(f'\033[1m\033[31mERROR: \033[37mInvalid register ({op})')
        exit()
    regid = REGS[op]
    return TYPES['T_REG'], regid, None


###
# Parse an operand as a memory access
###
def parse_memory(op, labs):
    # Chunk up the memory access
    op = op[1:-1]
    chunks = [c.strip() for c in op.split('+')]
    if len(chunks) > 2:
        print(f'\033[1m\033[31mERROR: \033[37mToo many memory modifiers ({op})')
        exit()

    # Process the sub operands
    ti = 0; di = 1; vi = 2
    base = parse_operand(chunks[0], labs)
    disp = None
    if len(chunks) == 2:
        disp = parse_operand(chunks[1], labs)

    # Validate no nested memory parts
    allowed = [TYPES['T_IMM'], TYPES['T_REG']]
    if base[ti] not in allowed or (disp is not None and disp[ti] not in allowed):
        print(f'\033[1m\033[31mERROR: \033[37mMemory addressing parts must be register or immediate ({op})')
        exit()

    # Compound memory access
    if disp:
        # Register base, register displacement
        if base[ti] == TYPES['T_REG'] and disp[ti] == TYPES['T_REG']:
            value = (((((0b1111 << 4) | base[di]) << 4) | disp[di]) << 4 ) | random.getrandbits(4)
            print(f'value = {value:x} = {value:b}')
            return TYPES['T_MEM'], 2, value

        # Register base, immediate displacement
        elif base[ti] == TYPES['T_REG'] and disp[ti] == TYPES['T_IMM']:
            imm_width = (disp[vi].bit_length() + 7) // 8 or 1
            value = (((0b1110 << 4) | base[di]) << (imm_width * 8)) | disp[vi]
            if imm_width > 20:
                print(f'\033[1m\033[31mERROR: \033[37mMemory offset beyond maximum vmem address ({base[xi]:x})')
                exit()
            return TYPES['T_MEM'], disp[di] + 1, value

        # Immediate base, immediate displacement (don't be silly)
        else:
            print(f'\033[1m\033[31mERROR: \033[37mCompound memory access use a register base ({op})')

    # Simple memory access
    else:
        if base[ti] == TYPES['T_REG']:
            value = (((0b110 << 1) | random.getrandbits(1)) << 4) | base[di]
            return TYPES['T_MEM'], 1, value

        elif base[ti] == TYPES['T_IMM']:
            imm_width = (base[vi].bit_length() + 7) // 8 or 1
            value = (((0b100 << 5) | random.getrandbits(5)) << (imm_width * 8)) | base[vi]
            if imm_width > 20*8:
                print(f'\033[1m\033[31mERROR: \033[37mMemory offset beyond maximum vmem address ({base[xi]:x})')
                exit()
            return TYPES['T_MEM'], base[di] + 1, value

        else:
            print(f'\033[1m\033[31mERROR: \033[37mYou have reached dead code... congrats?')
            exit()


###
# Parse an operand as an immediate
###
def parse_immediate(op):
    # Immediate is a flag
    if op.upper() in FLAGS:
        return TYPES['T_IMM'], 1, FLAGS[op]
    op = op.lower()

    # Convert the string to an int
    val = 0
    try:
        if op.startswith('0x'): val = int(op, 16)
        elif op.startswith('0b'): val = int(op, 2)
        elif op.startswith('0'): val = int(op, 8)
        else: val = int(op, 10)
    except:
        print(f'\033[1m\033[31mERROR: \033[37mInvalid immediate format ({op})')
        exit()

    # Calculate the minimum required length
    l = (val.bit_length() + 7) // 8 or 1
    if l >= 64:
        print(f'\033[1m\033[31mERROR: \033[37mImmediate exceeds 63 bytes ({op})')
        exit()

    # Return
    return TYPES['T_IMM'], l, val


###
# Parse an operand as a label
###
def parse_label(op, labs):
    op = op[1:-1]
    val = labs[op] if op in labs else 0xb000b5
    return TYPES['T_IMM'], 3, val


###
# Parse an operand without knowing its type
# Return type, descriptor, value
# For registers, the descriptor is the register ID and the value is None
# For memory and immediates, the descriptor is the length in bytes of the value
###
def parse_operand(op, labs):
    if op[0].upper() == 'P' or op[0].upper() == 'R' or op[0].upper() == 'C': return parse_register(op)
    elif op[0] == '[': return parse_memory(op, labs)
    elif op[0] == '<': return parse_label(op, labs)
    else: return parse_immediate(op)


###############################################################################################################################
###############################################################################################################################
###############################################################################################################################


###
# Compile a single plain text instruction to binary
###
def compile_insn(insn, opmap, labs, doXor=None, quiet=False):
    # Global tryXor and forceXor flag
    global tryXor
    global forceXor

    # Split the line into the mneumonic and operands
    mneumonic, opDescs = insn.split(' ', maxsplit=1)
    opDescs = [op.strip() for op in opDescs.split(',')]
    if not opmap.has(mneumonic):
        print(f'\033[1m\033[31mERROR: \033[37mInvalid operation ({mneumonic})')
        exit()
    if len(opDescs) > 2 and mneumonic != 'CALL':
        print(f'\033[1m\033[31mERROR: \033[37mInvalid number of operands ({len(opDescs)})')
        exit()
    elif len(opDescs) > 1+8:
        print('\n'+insn)
        print(f'\033[1m\033[31mERROR: \033[37mCall parameters exceeded. Current maximum is 8, found {len(opDescs)-1}')
        print(f'       If you choose to change that, remember to also change it in handle_call of the VM!!!')
        exit()
    
    # Randomize the opcode map
    opmap.mode = random.getrandbits(2)
    opcode = opmap.get(mneumonic)
    if not quiet:
        print(f'    [*] Opcode Mode is {opmap.mode:02b}')
        print(f'    [*] Opcode is {opcode:05b}')

    # Decide whether or not to update encryption at rest, updating the instruction header
    if forceXor:
        doXor = 1
    elif tryXor:
        if doXor is None:
            doXor = 1 if random.randrange(10) == 0 else 0
    else:
        doXor = 0
    asBin = ((((opmap.mode << 5) | opcode) << 1) | doXor).to_bytes(1)
    if not quiet: print(f'    [*] doXor is {doXor:b}')

    # Conditionally append the XOR key
    if doXor:
        key = random.getrandbits(8)
        asBin += key.to_bytes(1)
        if not quiet: print(f'    [*] Update XOR key with {key:08b}')

    # Parse the operands
    ops = []
    for i, op in enumerate(opDescs):
        ops.append(parse_operand(op, labs))

    # Update the instruction header to include operand information
    if mneumonic == 'CALL':
        callDst = ops[0]
        opHdr = (callDst[0] << 6) | callDst[1]
        asBin += opHdr.to_bytes(1)
        asBin += (len(ops) - 1).to_bytes(1)
        for i, (opType, opDesc, opValue) in enumerate(ops):
            if i == 0: continue
            opHdr = (opType << 6) | opDesc
            asBin += opHdr.to_bytes(1)
    else:
        for opType, opDesc, opValue in ops:
            opHdr = (opType << 6) | opDesc
            asBin += opHdr.to_bytes(1)

    # Append the operands
    for i, (opType, opDesc, opValue) in enumerate(ops):
        if opType == TYPES['T_REG']:
            if not quiet: print(f'    [*] Operand {i} = ({opType:02b} {opDesc:06b} None)')
            pass
        elif opType == TYPES['T_IMM']:
            if not quiet: print(f'    [*] Operand {i} = ({opType:02b} {opDesc:06b} {opValue:b})')
            asBin += opValue.to_bytes(opDesc, 'little')
        else:
            if not quiet: print(f'    [*] Operand {i} = ({opType:02b} {opDesc:06b} {opValue:b})')
            asBin += opValue.to_bytes(opDesc, 'little')

    # Return the binary instruction
    if not quiet:
        bytesAsByteStr = ''.join(f'{b:02x}' for b in asBin)
        bytesAsBinStr = ''.join(f'{b:08b}' for b in asBin)
        print(f'    [*] Instruction is {bytesAsBinStr} = {bytesAsByteStr}')
    return asBin, doXor


###
# Driver function to convert plaintext FLP code to binary FLP code
###
def main():
    # Global tryXor and forceXor flag
    global tryXor
    global forceXor

    # Read the plaintext assembly into a list, sanitizing spaces
    asm = []
    with open('flipvmcode.ptf', 'r') as f:
        asm = f.read()
    asm = [re.sub(r'\s+', ' ', a).split(';')[0].strip() for a in asm.split('\n') if a and len(a.strip()) != 0 and a.strip()[0] != ';']
    print(f'[+] Identified {(len(asm))} lines of code and data')
    print()

    # Record global constant values
    print('[+] Searching for global constants')
    consts = {}
    for line in asm:
        if line[0] != '{': continue
        chunks = line[1:-1].strip().split(' ')
        print(f'    [*] {chunks[0]} = {chunks[1]}')
        if chunks[0] in consts:
            print(f'\033[1m\033[31mERROR: \033[37mDuplicate global constant ({chunks[0]})')
            exit()
        consts[chunks[0]] = chunks[1]

    # Perform global constant replacement
    print(f'[+] Replacing instances of {len(consts)} global constants with their value')
    for key,value in consts.items():
        asm = [re.sub(key, value, line) for line in asm]
    print()

    # Perform initial-pass compiling, stubbing unresolved label references
    print(f'[+] Performing initial-pass compiling')
    labs = {}
    labRefs = {}
    compiled = []
    xors = []
    opmap = OpcodeMap()
    for i, insn in enumerate(asm):
        # Skip global constant declarations
        if insn[0] == '{': continue

        # Detect compiler intrinsics
        if insn[0] == '#':
            intrinsic = insn.split('#')[1].strip()
            key = intrinsic.split('=')[0].strip()
            value = intrinsic.split('=')[1].strip()
            if key == 'tryXor':
                tryXor = True if value == 'True' else False
                print(f'    [*] Updating tryXor to {tryXor} @ 0x{currOffset:>06x}.')
                continue
            elif key == 'forceXor':
                forceXor = True if value == 'True' else False
                print(f'    [*] Updating forceXor to {forceXor} @ 0x{currOffset:>06x}.')
                continue

        # Record the offset of labels
        if insn[0] == '<' and insn[-1] == '>':
            lab = insn[1:-1]
            if lab in labs:
                print(f'\033[1m\033[31mERROR: \033[37mDuplicate label ({lab})')
                exit()

            currOffset = sum([len(c) for c in compiled])
            labs[lab] = currOffset
            print(f'    [*] Label {lab} points to instruction @ 0x{currOffset:>06x}.')
            continue

        # Parse as assumed instruction
        asBin, xorDone = compile_insn(insn, opmap, labs, quiet=True)
        compiled.append(asBin)
        xors.append(xorDone)
    print()

    # Perform final-pass compiling, when all label offsets should be known
    print(f'[+] Performing final-pass compiling')
    compiled = []
    for insn in asm:
        if insn[0] == '{': continue
        if insn[0] == '<': continue
        if insn[0] == '#': continue
        currOffset = sum([len(c) for c in compiled])
        print(f'0x{currOffset:>06x}    {insn}')
        asBin, _ = compile_insn(insn, opmap, labs, doXor=xors.pop(0), quiet=True)
        compiled.append(asBin)
        # for x in asBin:
        #     print(f'\\x{x:02x}', end='')
        # exit()

    # Find the entrypoint by label
    if 'FUN_main' not in labs:
        print(f'\033[1m\033[31mERROR: \033[37mFailed to find FUN_main label')
        exit()
    entry = labs['FUN_main']

    # Convert the compiled code to one byte string
    code = b''.join(compiled) + b'\xff'
    #print(' '.join(f'{b:02x}' for b in code))
    
    # Calculate the file header contents
    h = fnv1a_hash(code)
    signature = pow(h, E, N)
    xor = (signature ^ entry) & 0xFFFFFFFF
    flpHdr = b'FLP' + \
             N.to_bytes(128, byteorder="little") + \
             E.to_bytes(3, byteorder="little") + \
             signature.to_bytes(128, byteorder='little') + \
             xor.to_bytes(4, byteorder="little")

    # Write the binary file
    with open('code.flp', 'wb') as f:
        f.write(flpHdr)
        f.write(code)


###
# Entry point
###
if __name__ == '__main__':
    main()
