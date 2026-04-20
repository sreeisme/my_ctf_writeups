# Me is Mey

**Category:** Cryptography  
**Competition:** Global Ynov Partners CTF 2026  
**Server:** `154.57.164.80:30979`  

---

## Challenge Description

> For the concluding challenge, you revisit the creator's final statement: "Only the one who is me can be me". After careful consideration, you deduce that these words refer to the creator's personal signature. The key to unlocking the final challenge lies in accurately reproducing this signature.

This one had a theatrical flair to it. The description is basically a hint that you need to impersonate something — send something that *looks like* the original but isn't.

---

## Initial Recon

When you connect to the server, it presents you with a challenge: prove your identity by sending a hash collision. The server computes a custom hash using a `rotate` function over your input, then checks it against a known value. The twist is that your input must be *different* from the original, but produce the *same* hash.

The original message is `ready_play_one!` in hex: `72656164795f706c61795f6f6e6521`.

---

## Finding the Vulnerability

The server's `rotate` function is defined as:

```python
def rotate(b):
    return ((b >> 4) | (b << 3)) & 0xff
```

In a proper 8-bit rotation, the two shift amounts must sum to 8. Here they sum to **7** — `4 + 3 = 7`. This makes the function **lossy**: it's not a bijection. Multiple input bytes can map to the same output byte.

Let's verify with a quick test:

```python
def rotate(b):
    return ((b >> 4) | (b << 3)) & 0xff

# Check: does 'e' (0x65 = 101) collide with anything?
target = rotate(101)
collisions = [i for i in range(256) if rotate(i) == target and i != 101]
print(f"rotate(0x65) = {target:#x}")
print(f"Collisions: {[hex(x) for x in collisions]}")
```

Output:
```
rotate(0x65) = 0x2e
Collisions: ['0xe4']
```

`0x65` (`'e'`, the second byte of `ready_play_one!`) and `0xe4` both rotate to the same value. So I can swap byte 2 in the original message to get a different input that produces an identical rotated representation — and therefore the same `sha256(rotate(message))`.

---

## Constructing the Collision

The original message bytes: `72 65 61 64 79 5f 70 6c 61 79 5f 6f 6e 65 21`

Replacing the second byte `0x65` with `0xe4`:

```
72 e4 61 64 79 5f 70 6c 61 79 5f 6f 6e 65 21
```

As a hex string: `72e46164795f706c61795f6f6e6521`

Let me double-check this before sending:

```python
import hashlib

def rotate(b):
    return ((b >> 4) | (b << 3)) & 0xff

def hash_msg(msg_bytes):
    rotated = bytes(rotate(b) for b in msg_bytes)
    return hashlib.sha256(rotated).hexdigest()

original = bytes.fromhex("72656164795f706c61795f6f6e6521")
collision = bytes.fromhex("72e46164795f706c61795f6f6e6521")

print(original != collision)                        # True — they're different
print(hash_msg(original) == hash_msg(collision))    # True — same hash
```

Both checks pass. We have our collision.

---

## Sending to the Server

```bash
echo "72e46164795f706c61795f6f6e6521" | nc 154.57.164.80 30979
```

Or with Python for a cleaner interaction:

```python
import socket

s = socket.socket()
s.connect(('154.57.164.80', 30979))
print(s.recv(4096).decode())
s.send(b'72e46164795f706c61795f6f6e6521\n')
print(s.recv(4096).decode())
s.close()
```

The server accepts the collision and responds with the flag.

---

## Key Takeaway

This is a classic **hash collision via lossy transform** challenge. The vulnerability isn't in SHA-256 itself (which is collision-resistant) — it's in the pre-processing step. Any custom function applied before the hash that isn't a bijection creates a potential collision surface. The moment I saw the shift amounts summed to 7 instead of 8, I knew the function was lossy and the rest was just finding which byte had a sibling.

Always check custom crypto implementations for off-by-one errors in bit rotations. They're more common than you'd think.
