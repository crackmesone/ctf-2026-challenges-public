def mutate(passwd, atlas, rounds):
    mutated = passwd

    for _ in range(rounds):
        # Build the XOR
        xorByte = atlas & 0xFF
        xorWord = xorByte
        for _ in range(19):
            xorWord <<= 8
            xorWord |= xorByte

        # Perform the XOR
        mutated ^= xorWord

        # Rotate right by one
        lsb = mutated & 1
        mutated = mutated >> 1
        if lsb == 1:
            mutated |= 0x80000000000000000000000000000000000000000000000000000000000000

        # Update the atlas
        atlas >>= 8

    return mutated


def restore(mutated, atlas, rounds):
    # Pre-extract all bytes from the atlas
    atlas_bytes = []
    for _ in range(rounds):
        atlas_bytes.append(atlas & 0xFF)
        atlas >>= 8

    # The passwd starts as mutated
    passwd = mutated

    for _ in range(rounds):
        # Rotate left by one
        msb = passwd & 0x80000000000000000000000000000000000000000000000000000000000000
        passwd = (passwd << 1) & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        if msb != 0:
            passwd |= 1

        # Build the XOR (note that pop() reverses the order of atlas's bytes)
        xorByte = atlas_bytes.pop()
        xorWord = xorByte
        for _ in range(19):
            xorWord <<= 8
            xorWord |= xorByte

        # Perform the XOR
        passwd ^= xorWord
    return passwd


atlas = 0xa8769f686ab4449a2eace1dc0ca25d64264b530fb3fa93973c320d902befa31c62571fd0d2a65d830a2381a1160d63dca1478f43fc298439537986bffc0220d33b68ad52e8ecdd7f935b4035aa0772bd4463218bb499a4e338f9de155354bb02d73b9b3bbdcee2d16062b6fba6a54867493a55bb7cf48f82b688ff264280012a7cca37ab3d1e8a575fb89628e5e7cd6becc4dfb5529b8a5b2250d2063c6e5f808da3c8b386b2e2ad2908bb11d70dede5e34fe74a2569de6841204b3ec2a06c069f0d7d09e533c588052e166d5548e8dd1063603b3cd42c503f8c56c0ca6d57faefb3d6c0556038ef1224b9809650c80718459e3f61f006ffec3dee234a85012d
rounds = 0x100

passwd = "$?$__LeT_Th#_h@ck!ng_b3g1n__$?$"
asInt = int.from_bytes(passwd.encode(), 'little')
mutated = mutate(asInt, atlas, rounds)
restored = restore(mutated, atlas, rounds)

print()
print(f'Original: 0x{asInt:062x} = { asInt.to_bytes(31, 'little').decode() }')
print(f'Mutated:  0x{mutated:062x}')
print(f'Restored: 0x{restored:062x} = { restored.to_bytes(31, 'little').decode() }')
if asInt == restored:
    print(f'\nPASS')
else:
    print(f'\nFAIL')
print()

