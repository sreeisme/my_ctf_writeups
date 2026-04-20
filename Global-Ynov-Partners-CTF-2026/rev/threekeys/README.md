# ThreeKeys

**Category:** Reverse Engineering  
**Competition:** Global Ynov Partners CTF 2026  
**Flag:** `HTB{l3t_th3_hun7_b3g1n!}`

---

## Challenge Description

> You've gathered the three secret keys and you're ready to claim your prize. But in your rush, the keys have got mixed up — which one goes where?

Right in the description: the keys are mixed up. That's the puzzle. Not "find the keys" — you have them — but "figure out the right order."

---

## Step 1: Profile the Binary

```bash
file threekeys
nm threekeys
ldd threekeys
```

The binary is dynamically linked against `libcrypto.so.1.1` — it's using real OpenSSL AES. The symbol table immediately reveals `KEY1`, `KEY2`, `KEY3`, `CT` (ciphertext), and three oddly-named functions: `the_first_key`, `the_second_key`, `the_third_key`.

---

## Step 2: Spot the Deliberate Misdirection

This is the core puzzle. The function names suggest a natural ordering (first, second, third), but disassembling each one reveals which key it actually loads:

```bash
objdump -d threekeys | grep -A 10 "<the_first_key>:"
objdump -d threekeys | grep -A 10 "<the_second_key>:"
objdump -d threekeys | grep -A 10 "<the_third_key>:"
```

What I found:
- `the_third_key` → loads **KEY1**
- `the_second_key` → loads **KEY2**
- `the_first_key` → loads **KEY3**

**The names are exactly backwards.** That's the "keys got mixed up" from the description — the functions are deliberately mislabeled to mislead you.

---

## Step 3: Trace `main`

```bash
objdump -d threekeys | grep -A 30 "<main>:"
```

`main` calls them in order: `the_third_key` → `the_second_key` → `the_first_key`.

Translating with the reversed labels, the *actual* decryption sequence is:

```
KEY1 → KEY2 → KEY3
```

Each call uses OpenSSL's `AES_decrypt` on 16-byte blocks (raw ECB mode, no IV), operating on the output of the previous step.

---

## Step 4: Extract the Data

```bash
objdump -s -j .data threekeys
```

The `.data` section gives me all three 16-byte keys and the 32-byte ciphertext directly.

```python
KEY1 = bytes.fromhex("...")  # 16 bytes from .data
KEY2 = bytes.fromhex("...")
KEY3 = bytes.fromhex("...")
CT   = bytes.fromhex("...")  # 32 bytes
```

---

## Step 5: Try All Permutations

I initially tried the order `main` *appears* to execute: KEY1→KEY2→KEY3. That produced garbage. So I brute-forced all 6 permutations of the three keys:

```python
from Crypto.Cipher import AES
from itertools import permutations

KEY1 = bytes.fromhex("...")
KEY2 = bytes.fromhex("...")
KEY3 = bytes.fromhex("...")
CT   = bytes.fromhex("...")

keys = [KEY1, KEY2, KEY3]

for perm in permutations(keys):
    result = CT
    for k in perm:
        cipher = AES.new(k, AES.MODE_ECB)
        result = cipher.decrypt(result)
    if result.startswith(b'HTB') or result[:4].isascii():
        print(f"Order: {perm}")
        print(f"Result: {result}")
```

Only one produced plaintext starting with `HTB`: **KEY3 → KEY2 → KEY1** — the *reverse* of `main`'s apparent execution order.

This makes sense: the binary *encrypts* in KEY1→KEY2→KEY3 order (since AES-ECB is its own inverse), so to *decrypt* you reverse the order.

The padding at the end (`\x08\x08\x08...`) is standard PKCS#7, confirming a clean decryption.

---

## Flag

```
HTB{l3t_th3_hun7_b3g1n!}
```

---

## Full Solve Script

```python
from Crypto.Cipher import AES
from itertools import permutations

# Extract from .data section of the binary
KEY1 = bytes.fromhex("INSERT_KEY1_HEX")
KEY2 = bytes.fromhex("INSERT_KEY2_HEX")
KEY3 = bytes.fromhex("INSERT_KEY3_HEX")
CT   = bytes.fromhex("INSERT_CT_HEX")

for perm in permutations([KEY1, KEY2, KEY3]):
    result = CT
    for k in perm:
        result = AES.new(k, AES.MODE_ECB).decrypt(result)
    try:
        decoded = result.rstrip(bytes([result[-1]])).decode('ascii')
        if decoded.startswith('HTB'):
            print(f"[+] Found it!")
            print(f"[+] Key order: {[k.hex() for k in perm]}")
            print(f"[+] Flag: {decoded}")
            break
    except Exception:
        continue
```

---

## Key Takeaway

The trick here was recognizing that the function names are *intentional misdirection*. In CTF reverse engineering, never trust what something is *called* — trust what it *does*. The moment I saw the disassembly of `the_first_key` loading `KEY3`, I knew the whole challenge was about figuring out the actual execution order vs. the apparent one. The brute-force permutation approach is also a good safety net whenever you're unsure of key ordering in multi-step symmetric crypto.

The flag "let the hunt begin" ties back to the Ready Player One theme running through this whole challenge series. A neat bit of storytelling.
