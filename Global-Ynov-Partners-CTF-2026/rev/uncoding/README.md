# Uncoding

**Category:** Reverse Engineering  
**Competition:** Global Ynov Partners CTF 2026  

---

## Challenge Description

> Deep in the archives of Halliday's memories, you've come across a secret cabinet — extra layers of protection have been applied to these memories. What secrets could they hide?

The Ready Player One theme continues. A "locked" memory, extra layers of protection, and we need to get in statically without running the program.

---

## Step 1: Inventory

Single ELF binary, no bundled libc this time, not stripped. The category is `rev` (reverse engineering), not `pwn` — so the goal is to understand the program logic and extract data, not exploit memory.

```bash
file uncoding
# ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

---

## Step 2: Symbol Table

```bash
nm uncoding
```

Two things immediately caught my eye: a `decrypt_message` function and a global `messages` array. The program holds encrypted strings and decrypts them on demand — a very classic rev structure.

---

## Step 3: Strings and Program Logic

```bash
strings uncoding
```

The prompt says the user can pick an index from `0` to `3`. But index 3 triggers a special branch: *"That memory has been locked away!"*. That's the locked slot we need to crack open — statically, without running the program.

---

## Step 4: Disassemble `decrypt_message`

```bash
objdump -d uncoding | grep -A 80 "<decrypt_message>:"
```

Two critical observations:

**1. The XOR key is hardcoded in the function body:**

Two `movabs` instructions load a 16-byte value into local stack variables. This is the XOR key:

```
c6 d4 da 8e 1e af e2 c3 0c 06 d4 c0 48 25 60 ee
```

**2. The decryption loop is a simple repeating-key XOR:**

```
output[i] = message[i] ^ key[i % 16]
```

Repeating-key XOR — exactly what the challenge name "Uncoding" is hinting at (and the flag text confirms it, as we'll see).

---

## Step 5: Find the Encrypted Data

```bash
objdump -s -j .data uncoding    # find the messages[] array (4 pointers)
objdump -s -j .rodata uncoding  # find the raw encrypted bytes
```

The `.data` section holds 4 pointers in `messages[]`. The `.rodata` section holds the raw encrypted bytes at those addresses. Message index 3 starts at address `0x2128`.

I extracted the null-terminated byte sequence at each pointer by reading the binary directly:

```python
import struct

with open('uncoding', 'rb') as f:
    data = f.read()

# XOR key extracted from movabs instructions
key = bytes([0xc6, 0xd4, 0xda, 0x8e, 0x1e, 0xaf, 0xe2, 0xc3,
             0x0c, 0x06, 0xd4, 0xc0, 0x48, 0x25, 0x60, 0xee])

# File offset for message[3] — calculate from load address and section offset
# 0x2128 virtual addr → file offset (depends on load address, check PT_LOAD)
# For this binary: file_offset = vaddr - 0x2000 + section_file_offset
MSG3_OFFSET = 0x2128 - 0x2000 + <section_file_offset>  # fill from readelf

# Extract null-terminated encrypted bytes
end = data.index(0, MSG3_OFFSET)
encrypted = data[MSG3_OFFSET:end]

# Decrypt
decrypted = bytes(b ^ key[i % 16] for i, b in enumerate(encrypted))
print(decrypted.decode())
```

---

## Step 6: Decrypt

Messages 0–2 turned out to be flavor text (lore about Halliday's memories). Message 3 — the locked one — decrypted to the flag.

The flag text itself is a beautiful meta-hint: **"one time pad, two time pad, three time pad..."** — a nod to the fact that reusing a key (using the same key more than once) completely breaks one-time pad security. The challenge name "Uncoding" points to the same idea: you're literally undoing (XOR-ing back) an encoding.

---

## Key Takeaway

This is a straightforward static decryption challenge once you know what to look for. The `movabs` instruction is the most reliable way to spot hardcoded multi-byte constants in x86-64 disassembly — whenever you see two consecutive `movabs` loading 8 bytes each into local variables right at the start of a function, that's almost certainly a key. From there it's just identifying the loop structure (XOR with repeating key), finding the data in `.rodata`, and writing 10 lines of Python.

The meta-lesson: reusing a key makes XOR cipher completely reversible by anyone with the key — which is encoded right in the binary. Static analysis wins.
