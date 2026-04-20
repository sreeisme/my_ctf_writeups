# Faulty Machine

**Category:** Cryptography  
**Competition:** Global Ynov Partners CTF 2026  
**Flag:** `HTB{1t_m34n5_th4t-th15_d4mn_th1ng_d035nt-w0rk_4t_4ll!!}`

---

## Challenge Description

> Someone messed with the DeLorean, and now they've switched the speed to 88 kilometers per hour instead of 88 miles per hour! Can you fix it for us?

The theme here is a broken machine — something that *almost* works but doesn't quite. That's a dead giveaway in CTF crypto: look for a broken RSA parameter.

---

## Initial Analysis

We're given standard RSA parameters: `n`, `e`, `p`, `q`, and a ciphertext `c`. The first thing I do with any RSA challenge is check whether the public exponent has any relationship to `φ(n)`:

```python
from math import gcd

e = 88
# e = 2^3 * 11 = 8 * 11

# φ(n) = (p-1)(q-1)
phi_n = (p - 1) * (q - 1)

print(gcd(e, phi_n))
```

Output: `8`

There it is. `gcd(88, φ(n)) = 8 ≠ 1`, which means `e` is **not coprime to φ(n)**. The standard RSA inverse `d = e⁻¹ mod φ(n)` simply doesn't exist. This is the "faulty" part — the exponent isn't valid for normal RSA decryption.

---

## The Attack Path

Since we're given `p` and `q` (so we know the full factorization), we can get creative. The key insight is to factor out the GCD:

```
e = 88 = 8 * 11
e' = 88 / 8 = 11
```

`e' = 11` **is** coprime to `φ(n)/8` (since `gcd(11, φ(n)/8) = 1`). So the attack has two stages:

**Stage 1 — Partial decryption with reduced exponent:**

Compute `d' = e'⁻¹ mod (φ(n)/8)`:

```python
e_prime = 11
phi_reduced = phi_n // 8

d_prime = pow(e_prime, -1, phi_reduced)
intermediate = pow(c, d_prime, n)
```

This gives us `flag^8 mod n`, not `flag` directly — because `e = e' * 8`, so decrypting with `d'` only undoes `e'`, leaving us with the 8th power.

**Stage 2 — Take the 8th root mod n:**

`8 = 2^3`, so I need to take three successive square roots. I used the **Tonelli-Shanks algorithm** to compute modular square roots — once mod `p` and once mod `q`, then combined with CRT.

```python
from sympy.ntheory.residues import nthroot_mod
from sympy.ntheory.modular import crt

def sqrt_mod(a, p):
    """Tonelli-Shanks square root mod prime p"""
    return pow(a, (p + 1) // 4, p)  # works when p ≡ 3 mod 4

def eighth_root_mod_n(val, p, q, n):
    current = val
    for _ in range(3):  # 3 square roots = 8th root
        # Take sqrt mod p and mod q separately
        rp = sqrt_mod(current % p, p)
        rq = sqrt_mod(current % q, q)
        # Recombine with CRT
        current, _ = crt([p, q], [rp, rq])
    return current

flag_int = eighth_root_mod_n(intermediate, p, q, n)
flag = flag_int.to_bytes((flag_int.bit_length() + 7) // 8, 'big')
print(flag.decode())
```

The reason I do the square roots mod `p` and mod `q` separately rather than directly mod `n` is that taking square roots mod a composite is hard (that's the whole basis of RSA!), but mod a prime it's easy with Tonelli-Shanks or the `(p+1)/4` shortcut.

---

## Full Solve Script

```python
from math import gcd
from sympy.ntheory.modular import crt

# RSA parameters (from challenge)
# n, p, q, e, c provided in challenge files

def solve(n, p, q, e, c):
    phi_n = (p - 1) * (q - 1)
    
    assert gcd(e, phi_n) == 8, "Expected gcd = 8"
    
    e_prime = e // 8   # = 11
    phi_reduced = phi_n // 8
    
    d_prime = pow(e_prime, -1, phi_reduced)
    intermediate = pow(c, d_prime, n)  # = flag^8 mod n
    
    # Take 8th root = three square roots
    current = intermediate
    for _ in range(3):
        rp = pow(current % p, (p + 1) // 4, p)
        rq = pow(current % q, (q + 1) // 4, q)
        current, _ = crt([p, q], [rp, rq])
    
    flag_bytes = current.to_bytes((current.bit_length() + 7) // 8, 'big')
    return flag_bytes.decode()

print(solve(n, p, q, e, c))
```

---

## Flag

```
HTB{1t_m34n5_th4t-th15_d4mn_th1ng_d035nt-w0rk_4t_4ll!!}
```

---

## Key Takeaway

This challenge tests whether you know what to do when RSA breaks down. The standard assumption is `gcd(e, φ(n)) = 1` — when that fails, you can't invert normally. But if you have the factorization, you can work around it by reducing the exponent and cleaning up the leftover root. The DeLorean hint (miles vs. kilometers) was pointing at a unit mismatch — the exponent is "off" in the same way 88 km/h is off from 88 mph. Cute theming.
