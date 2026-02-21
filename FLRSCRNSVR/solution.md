# FLRSCRNSVR.SCR Writeup

This document details the process of reverse engineering `FLRSCRNSVR.exe`. The binary is a Windows screensaver that contains a some anti-analysis code. Players need to reverse a custom encoding algorithm to unveil the challenge flag.

## 1. Initial Triage (Static Analysis)

### Interesting Strings

- `/c`, `/p`, `/s`: Command-line arguments for a screensaver.
- `Software\FLRSCRNSVR`: A registry key.
- `Quak`, `Text`
- `Crackmes.one`

### File Type and Entry Point

The binary is a 64-bit Windows executable. Analysis of the command-line parsing logic shows it responds to `/s` (screensaver mode), `/p` (preview mode), and `/c` (configuration mode), confirming its identity as a screensaver.

## 2. Behavioral Analysis (Dynamic Analysis)

Running the executable with different flags reveals its behavior:

- `FLRSCRNSVR.SCR /s`: Runs the screensaver in fullscreen. It shows frogs bouncing around a black screen. A large text is displayed in the center.
- `FLRSCRNSVR.SCR /c`: Opens a configuration dialog box. This dialog allows the user to input a string, which is then saved. This is our primary input vector.
- `FLRSCRNSVR.SCR /p <HWND>`: Runs the screensaver in a small preview window, as seen in Windows display settings.

## 3. Core Challenge Analysis

### Loading the Flag

The most important discovery is in the function that loads the custom text from the registry. This function is triggered when the screensaver starts.

Here is the flow of the function:
1.  It reads the value from `HKEY_CURRENT_USER\Software\FLRSCRNSVR\Text`. This is the string we provide in the configuration dialog.
2.  It checks if the length of this string is exactly 25 characters.
3.  If the length is 25, it passes it to a function we'll name `encode`.
4.  It then compares the output of `encode` with the hardcoded `g_encoded_flag` value.

To get the flag, we must reverse the `encode` function.

#### Reversing `encode`

Analysis of this function reveals a three-stage process.

1.  **Substitution Cipher**: Each character of the input string is substituted using a hardcoded alphabet and substitution string that form a one-to-one mapping.
2.  **Position-Dependent XOR**: The substituted string is then XORed with a key. The key itself is generated from hardcoded characters (`"FLARERALF"`).
3.  **String Reversal**: The entire resulting string is reversed.

To find the original flag, we must apply these steps in reverse to the known `g_encoded_flag`.

## 4. Solution

### Part 1: Finding the Flag

We need to reverse the `encode` function. The steps are:
1.  Take the known `g_encoded_flag`.
2.  Reverse the data.
3.  XOR the data.
4.  Apply the substitution cipher.

The following Python script automates this process:

```python
def solve_flag():
    encoded_flag_data = [
        0x003c, 0x0051, 0x006a, 0x0009, 0x0002, 0x0007, 0x0025, 0x0003,
        0x0030, 0x0008, 0x0004, 0x0029, 0x0068, 0x0024, 0x0001, 0x0024,
        0x0018, 0x006b, 0x0077, 0x000f, 0x0070, 0x0036, 0x0002, 0x000e,
        0x000b
    ]
    xor_key = "FLARERALF"
    
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789}_{=-"
    substitution = "-={_}9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"

    # Reverse data
    s1_reversed_g_encoded_flag = encoded_flag_data[::-1]

    # XOR
    s2_xored_string_chars = []
    for i, char_code in enumerate(s1_reversed_g_encoded_flag):
        key_char_code = ord(xor_key[i % len(xor_key)])
        s2_xored_string_chars.append(chr(char_code ^ (key_char_code + i)))
    s2_xored_string = "".join(s2_xored_string_chars)

    # Substitute
    reverse_sub_map = {substitution[i]: alphabet[i] for i in range(len(alphabet))}

    decoded_chars = [reverse_sub_map.get(c, '?') for c in s2_xored_string]
    new_flag = "".join(decoded_chars)

    print(f"Flag: {new_flag}")

solve_flag()

```

Running this script results in: **`CMO{frogt4s7ic_r3vers1ng}`**.
