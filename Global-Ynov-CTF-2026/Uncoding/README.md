# Uncoding - Reverse Engineering Writeup

**Challenge Category:** Reverse Engineering  
**Difficulty:** Medium  
**Time Spent:** ~40 minutes  
**Flag:** `HTB{one time pad, two time pad, three time pad...}`

## Overview

This was a classic reverse engineering challenge that required understanding how cryptographic keys work and the catastrophic failure that occurs when you reuse them. The title "Uncoding" is perfectly descriptive - we're undoing (XORing back) an encoding to reveal the plaintext.

## The Setup

The challenge description was mysterious:
> "Deep in the archives of Halliday's memories, you've come across a secret cabinet - extra layers of protection have been applied to these memories. What secrets could they hide?"

This is a flavor text hint that we're dealing with encrypted data from some kind of storage system.

## Initial Analysis

### Step 1: Inventory the Binary

I started with file inspection:
- **Format:** Single ELF binary, no bundled libc (unlike the Riddle challenge)
- **Category:** Reverse Engineering (not Pwn), so it's about understanding program logic
- **Goal:** Extract encrypted strings and decrypt them

### Step 2: Profile the Binary

```bash
file uncoding_binary
# ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

Not being stripped is great - we have function names.

### Step 3: Symbol Discovery

Running `nm` revealed crucial functions:
- `decrypt_message` - decrypts a single message
- `messages` array - stores encrypted data
- `global` variable holding the encryption key

This immediately suggested: "If I find the key and understand the cipher, I can decrypt all messages."

### Step 4: Extract Strings

Using `strings`, I found the prompt:
```
"0 -> 3"
```

And critically, a hint in the data:
```
"That memory has been locked away!"
```

So index 3 is special - it's locked and needs special handling.

## The Vulnerability

### Understanding the XOR Cipher

Disassembling `decrypt_message`:

```assembly
mov r8b, byte [rdi + r8]      ; Load message[i]
xor r8b, r10b                 ; XOR with key[i % 16]
mov byte [rax], r8b           ; Store result
add r8, 1
jmp loop
```

Two key observations:
1. **16-byte key**: The loop uses `i % 16`, confirming a repeating 16-byte key
2. **Simple XOR cipher**: `plaintext[i] = ciphertext[i] XOR key[i % 16]`

### Finding the Key

The XOR cipher is vulnerable when:
- You have plaintext you know (like "That memory has been locked away!")
- You have corresponding ciphertext

From the .data section, I found:
```
movabs instructions: c6 d4 da 8e 1e af e2 c3 0c 06 d4 c0 48 25 60 ee
```

This is the hardcoded 16-byte key used for every message!

## The Fatal Flaw

This challenge demonstrates **why reusing one-time pads is catastrophic**.

A proper OTP (One-Time Pad) must:
1. Be truly random
2. Be used exactly once
3. Be at least as long as the plaintext

Here, the same 16-byte key is used for all messages. This is the critical vulnerability.

### The Attack

1. **Extract the key**: From the binary's .data section:
   ```
   key = c6 d4 da 8e 1e af e2 c3 0c 06 d4 c0 48 25 60 ee
   ```

2. **Get encrypted messages**: From the .rodata section
   - Message 0: Flavor text (decrypts to "Halliday's memories...")
   - Message 1-2: More flavor
   - Message 3: THE LOCKED ONE - decrypt to get the flag

3. **XOR decrypt**:
   ```python
   key = bytes.fromhex("c6d4da8e1eafe2c30c06d4c04825 60ee")
   ciphertext = bytes.fromhex("...")  # Message 3 from .rodata
   plaintext = bytes([ciphertext[i] ^ key[i % 16] for i in range(len(ciphertext))])
   ```

## Step-by-Step Exploitation

### Step 1: Profile the Binary
- Single ELF, not stripped ✓
- decrypt_message function visible
- Key stored at 0x2128

### Step 2: Identify the Cipher
- XOR-based
- 16-byte repeating key
- Simple: `plaintext = ciphertext XOR key`

### Step 3: Extract the Key
From the movabs instructions in disassembly:
```
c6 d4 da 8e 1e af e2 c3 0c 06 d4 c0 48 25 60 ee
```

### Step 4: Decrypt Message 3
The locked message (index 3) is:
```python
# Pseudocode
encrypted_msg_3 = get_message_bytes(3)
key = [0xc6, 0xd4, 0xda, 0x8e, 0x1e, 0xaf, 0xe2, 0xc3, 
       0x0c, 0x06, 0xd4, 0xc0, 0x48, 0x25, 0x60, 0xee]

decrypted = ""
for i, byte in enumerate(encrypted_msg_3):
    decrypted += chr(byte ^ key[i % 16])
```

### Step 5: Get the Flag
The decrypted text is the flag!

## Key Insights

The flag text itself - "one time pad, two time pad, three time pad..." - is a meta-commentary on the vulnerability. It's pointing directly at the problem: reusing a key breaks the OTP security model.

### Why This Matters

This demonstrates:
1. **XOR is symmetric**: `(plaintext XOR key) XOR key = plaintext`
2. **Reusing keys breaks OTP**: If you XOR the same key multiple times with different plaintexts, you can XOR the ciphertexts together to eliminate the key and compare plaintexts
3. **Key recovery is possible**: With known plaintext or patterns, you can derive the key

## The Cryptographic Lesson

The "OTP" (One-Time Pad) is theoretically unbreakable IF:
- The key is truly random
- The key is never reused
- The key is kept secret

Break any of these assumptions, and the cipher becomes vulnerable. This challenge breaks assumption #2 spectacularly.

## Lessons Learned

1. **Names matter**: "Uncoding" was telling us we need to undo (XOR) an encoding
2. **Reused keys are fatal**: Never use the same encryption key for multiple messages
3. **Pattern recognition works**: Finding locked/special messages hints at where the flag is
4. **XOR is simple but dangerous**: It's fast but only secure in very specific contexts (OTP with proper key management)
5. **Binary analysis is methodical**: Profile → Symbols → Strings → Disassembly → Exploit

---

## Flag

```
HTB{one time pad, two time pad, three time pad...}
```

A clever hint wrapped in the flag itself - this challenge is all about what happens when you abuse the one-time pad concept!

*Challenge completed during Global Ynov Partners CTF Challenge (Apr 18-19, 2026)*
