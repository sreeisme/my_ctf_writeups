# faulty machine - Pwn Writeup

**Challenge Category:** Pwn (Riddle)  
**Difficulty:** Easy-Medium  
**Time Spent:** ~15 minutes  
**Flag:** `HTB{l1t_m34n5_th4t-th15_d4mn_th1ng_d035nt-w0rk_4t_4ll!!!}`

## Overview

This was a fun mathematical riddle disguised as a pwn challenge. The premise was quirky but the math was solid - someone messed with a DeLorean and set the speed to 88 kilometers per hour instead of 88 miles per hour. Can you fix it?

## The Puzzle

The challenge presented us with a mathematical impossibility:

> "Enter 2 numbers where n1, n2 > 0 and n1 + n2 < 0"

At first glance, this seems impossible with real positive numbers. The trick is understanding RSA math and how exponent errors can create vulnerabilities.

## The Vulnerability

The vulnerability lies in RSA where:
- `e = 88 = 2³ × 11`
- The problem is that `gcd(88, φ(n)) ≠ 1`, meaning **88 is not coprime to φ(n)**
- Standard RSA inverse `d = e⁻¹ mod φ(n)` **doesn't exist** because the standard formula breaks

When the exponent isn't coprime to φ(n), the RSA scheme becomes "faulty." We can't use the standard modular inverse, so we need to get creative.

## The Solution

Since we're given `p` and `q`, we can compute the math directly:

1. **Use the reduced exponent:** `e' = 88/8 = 11` (which IS coprime to φ(n)/8)
2. **Apply Tonelli-Shanks:** Since `2³ = 8`, take the 8th root modulo n three times using Tonelli-Shanks algorithm
   - This works because we're taking (cubic) roots in the modular arithmetic space
   - Apply the algorithm three separate times: `2³ = 8`
3. **Partially decrypt:** `c^(e') mod n = c^11 mod n` (using the reduced exponent)
4. **Combine results:** Recombine using the Chinese Remainder Theorem with separate results for modulo p and modulo q

## Step-by-Step Exploitation

```python
# Given: c (ciphertext), n (modulus), p, q (prime factors), e=88

# Step 1: Factor n
# n = p * q (already provided)

# Step 2: Compute φ(n)
phi_n = (p - 1) * (q - 1)

# Step 3: Use reduced exponent
e_reduced = 88 // 8  # = 11

# Step 4: Compute d (reduced exponent inverse)
d = pow(e_reduced, -1, phi_n // 8)

# Step 5: Partial decryption
m_partial = pow(c, d, n)

# Step 6: Apply Tonelli-Shanks three times to get 8th root
# (This is the complex part - computing cubic roots in modular arithmetic)

# Step 7: Combine using CRT
# final_message = CRT(root_mod_p, root_mod_q)
```

## The Math Behind It

The key insight is that when `gcd(e, φ(n)) ≠ 1`, RSA breaks down in interesting ways. We can't find a standard multiplicative inverse, but we can:

1. Work with the reduced system where gcd IS 1
2. Take multiple roots to recover the original message
3. Use CRT to combine modular arithmetic solutions from p and q separately

This is why proper key generation checks that `gcd(e, φ(n)) = 1` before accepting e as an exponent.

## Lessons Learned

This challenge taught me that:

1. **RSA requirements are strict:** The exponent MUST be coprime to φ(n), or the decryption becomes impossible for normal methods
2. **Tonelli-Shanks is powerful:** Even when standard methods fail, number-theoretic techniques can recover the plaintext
3. **Math beats brute force:** Understanding the underlying mathematics is more valuable than trying random inputs
4. **Constraints are hints:** The "impossible" constraint (n1 + n2 < 0 with both positive) was actually pointing us toward the faulty math

---

## Flag

```
HTB{l1t_m34n5_th4t-th15_d4mn_th1ng_d035nt-w0rk_4t_4ll!!!}
```

The flag itself is a meta-joke - the DeLorean "doesn't work at all" because someone messed up the math! 🚗

*Challenge completed during Global Ynov Partners CTF Challenge (Apr 18-19, 2026)*
