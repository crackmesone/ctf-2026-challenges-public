# FlipVM

## Flag

CMO{<-*~-~*~-.1'm++In.-~*~-~*->}


<!---------------------------------------------------------------------------------------------------------->

## Source_Code

### Compiler

The compiler of virtual plaintext code (`.ptf`) into virtual binary code (`.flp`).

To compile: `python3 ./compile.py` while in the Compiler directory

This will create `code.flp`.


### VM

The virtual machine to execute virtual code.

To build, execute `make` while in the VM directory.

This will create `dist/FlipVM`

To run the virtual code using the VM, there are two options:
1. Execute `./FlipVM` while in a directory containing `code.flp`
1. Execute `./FlipVM ./path/to/anything.flp`


### VSCode_Syntax_Highlighter

A simple syntax highlighting extension for VSCode so that the virtual code is easier to read.


<!---------------------------------------------------------------------------------------------------------->

## Solution

An official solution can be found at `Solution/Official_Solution.pdf`.

### patch.py

This is a Python script for the easiest solution. It will patch `code.flp` so that the valid input is stored in the appropriate virtual register just before the input is validated. Furthermore, the entrypoint is modified such that the banner is not printed. This allows the check in the virtual code to immediately pass, thus decrypting the flag during runtime.

To generate a patched virtual code file (named `patched.flp`), execute `python3 ./patch.py ../Handout/code.flp` while in the Solution directory.

To run the patched virtual code, execute `../Handout/FlipVM ./patched.flp` while in the Solution directory.

**IMPORTANT**: Since the compiler includes randomization, this script will only work on the `code.flp` version included in the Handout directory (sha1sum = 130e5d13e04e853178598f844c2c3cd7979e1961)


### unmutate.py

This Python script can be used to recover the valid input.

It is an implementation of the virtual function `FUN_MutateInput` that will also reverse the mutation.

It prints the original string, the mutated string, and the restored string.
The original matches the restored, proving that the mutation is invertible.


### Kuznyechik

**THIS IS NOT NEEDED FOR A SOLUTION. IT IS INCLUDED IN CASE THE FLAG OR DECRYPTION KEY NEED TO BE CHANGED.**

This is a modified version of Kuznyechik, utilizing a non-standard polynomial for GF(256) multiplication and non-standard multiplication vector, which further changes the round constants. The substitution boxes have also been changed, but remain invertible.

It first prints the key that is derived from a modified WHIRLPOOL hash (the valid input discretely maps to the hard coded key).

It the prints the following in order:
1. The key that is derived from the modified WHIRLPOOL hash (the valid input discretely maps to the hard coded key).
2. The plaintext left-half of the flag (`CMO{<-*~-~*~-.1'`) as its little-endian bytes
3. The encryption result of the left-half as its little endian bytes
4. The plaintext right-half of the flag (`m++In.-~*~-~*->}`) as its little-endian bytes
5. The encryption result of the right-half as its little endian bytes
6. The decryption result of the right-half ciphertext as its little endian bytes.

Since (4) and (6) are equal, decryption is possible even after modifying the Kuznyechik constants.
