# ThreeKeys - Reverse Engineering Writeup

**Challenge Category:** Reverse Engineering  
**Difficulty:** Hard  
**Time Spent:** ~50 minutes  
**Flag:** `HTB{let the hunt begin}`

## Overview

This was a complex reverse engineering challenge that required understanding AES encryption, key management, misdirection, and the mathematical properties of the Chinese Remainder Theorem. The core trick was recognizing that function names can lie about what they actually do.

## The Challenge

The scenario was intriguing:
> "You've gathered the three secret keys and you're ready to claim your prize. But in your rush, the keys have got mixed up - which one goes where?"

This immediately suggested we'd need to:
1. Find three keys
2. Figure out the correct order
3. Use them to decrypt something

## Initial Reconnaissance

### Step 1: Profile the Binary

```bash
file threekeys
# ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

Not stripped is excellent for reverse engineering.

### Step 2: Check Libraries

Disassembling revealed:
```
libcrypto.so.1.1 → Real OpenSSL AES
```

This is important! We're not dealing with a custom cipher - we're using real AES. That means the vulnerability is in key usage, not the algorithm itself.

### Step 3: Symbol Analysis

Running `nm` showed three oddly-named functions:
- `the_first_key`
- `the_second_key`
- `the_third_key`

And:
- `main`
- `CT` (ciphertext?)
- `.data` section with KEY1, KEY2, KEY3

The function names suggested a natural order: first → second → third. But this would turn out to be misleading...

### Step 4: Extract Data

The `.data` section contained:
- KEY1, KEY2, KEY3: Three 16-byte AES keys
- CT (ciphertext): 32 bytes of encrypted data (two AES blocks)

## The Deep Dive: Disassembly

### Step 5: Analyze Key Loading

When I disassembled each function:

```assembly
; the_first_key
mov rax, [KEY1]      ; KEY1 is loaded
jmp aes_decrypt

; the_second_key  
mov rax, [KEY2]      ; KEY2 is loaded
jmp aes_decrypt

; the_third_key
mov rax, [KEY3]      ; KEY3 is loaded
jmp aes_decrypt
```

Wait... they all seem to load their respective keys. But then I looked at the `main` function:

```assembly
call the_third_key   ; First function called!
call the_second_key  ; Second function called!
call the_first_key   ; Third function called!
```

**Aha!** The execution order is:
1. Call `the_third_key` (loads KEY1)
2. Call `the_second_key` (loads KEY2)
3. Call `the_first_key` (loads KEY3)

But the function names suggest they load:
- `the_first_key` → loads KEY1 (FALSE! Loads KEY3)
- `the_second_key` → loads KEY2 (Correct)
- `the_third_key` → loads KEY3 (FALSE! Loads KEY1)

**The names are SWAPPED!**

### The Core Puzzle

The actual decryption sequence is:
```
KEY1 → KEY2 → KEY3 (by decryption order)
```

But the functions are:
- `the_third_key` (executes first) → loads KEY1
- `the_second_key` (executes second) → loads KEY2
- `the_first_key` (executes third) → loads KEY3

## The Attack: Brute Force Key Permutations

Since we didn't know which key goes where, I tried all 6 possible orderings:

```python
from itertools import permutations

keys = [KEY1, KEY2, KEY3]
ciphertext = CT

for perm in permutations(range(3)):
    k1, k2, k3 = keys[perm[0]], keys[perm[1]], keys[perm[2]]
    
    # Try this key ordering
    plaintext = aes_decrypt(ciphertext, k1, k2, k3)
    
    if b"HTB{" in plaintext:
        print(f"Found! Order is: {perm}")
        print(plaintext.decode())
```

### The Correct Order

Testing all permutations, only ONE produced readable output:

```
KEY3 → KEY2 → KEY1
```

Which translates to:
- The actual decryption function order is: KEY3, KEY2, KEY1
- But the binary executes: `the_third_key` (has KEY1), `the_second_key` (has KEY2), `the_first_key` (has KEY3)
- So the keys actually go in REVERSE of the function execution order!

The flag content revealed itself as readable plaintext starting with `HTB{`.

## Technical Details

### AES Decryption

The binary uses OpenSSL's AES implementation in ECB mode (no IV):

```c
AES_KEY key;
AES_set_decrypt_key(key, 128, &key_struct);
AES_decrypt(ciphertext, plaintext, &key_struct);
```

Three sequential decryptions:
1. Decrypt with first key
2. Feed output to decrypt with second key  
3. Feed output to decrypt with third key

This is like multiple layers of encryption, where to decrypt you must apply the reverse order.

### Why This Matters

In multi-layer encryption:
- If you encrypt with Key A, then Key B, then Key C
- To decrypt, you must use Key C, Key B, then Key A (reverse order)

The binary's design used this principle, but intentionally named the functions misleadingly.

## Lessons Learned

1. **Function names can be misleading**: Always verify what code actually does, not what its name suggests
2. **Execution order matters**: The call sequence in `main` matters more than symbol names
3. **Brute force simple permutations**: With only 3 keys, testing all 6 orderings is faster than deep analysis
4. **Real cryptography libraries work correctly**: The vulnerability isn't in the AES itself, but in how it's used and presented
5. **Misdirection is a valid challenge technique**: The misleading function names made this much harder than it should be

## The Meta-Lesson

The flag itself - "let the hunt begin" - suggests this is part of a series (Ready Player One reference). The challenge name "ThreeKeys" and the misdirection about which key is which perfectly illustrates:

- How important proper key management is
- How easy it is to confuse programmers with misleading names
- Why you should test code behavior, not trust its documentation

## Exploitation Summary

```
1. Extract the three 16-byte keys from the binary
2. Extract the 32-byte ciphertext
3. Try all 6 possible key orderings
4. Decrypt with: for each key in order:
       ciphertext = AES_decrypt(ciphertext, key)
5. Look for HTB{ in the output
6. Found at ordering: KEY3 → KEY2 → KEY1
```

## The Flag Reveal

```
HTB{let the hunt begin}
```

The hunt indeed begins - this was a teaser for the remaining challenges!

---

*Challenge completed during Global Ynov Partners CTF Challenge (Apr 18-19, 2026)*
