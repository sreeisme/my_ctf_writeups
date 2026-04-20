# Me is Mey - Cryptography Writeup

**Challenge Category:** Cryptography  
**Difficulty:** Medium  
**Time Spent:** ~25 minutes  

## Overview

This challenge was about exploiting a poorly implemented SHA-256 hash collision. The scenario presented a signature verification system with a critical vulnerability in the rotation function used for hashing.

## The Challenge

We're told that the creator left a final statement: "Only the one who is me can be me." After careful consideration, we realize this refers to the creator's personal signature. The key to unlocking the challenge lies in accurately reproducing this signature.

The challenge involved a custom `rotate` function that wasn't a proper 8-bit rotation. Instead of the left and right shifts summing to 8, they summed to 7, making it a lossy operation that could produce collisions.

## The Vulnerability

The custom rotate function is implemented as:
```python
((b >> 4) | (b << 3)) & 0xff
```

In a proper 8-bit rotation, the shifts should sum to 8. Here they sum to 7, which means multiple input bytes can produce the same rotated output. This is the collision vector.

## Finding the Collision

The vulnerability allows us to find two different bytes that produce the same rotated value:
- Byte `0x65` ('e') 
- Byte `0xe4` (a different value)

Both rotate to the same result. By replacing just one byte in the original message with its collision partner, we get a valid hash collision.

## Exploitation Steps

1. **Identify the flaw**: Verify that `rotate(0x65) == rotate(0xe4)`
2. **Prepare the collision**: The collision input is the hex string:
   ```
   72e46164795f706c61795f6f6e6521
   ```
   This is "ready_play_one!" with the second byte ('e') replaced by '0xe4'
3. **Send to server**: Connect to the target server and submit the collision payload
4. **Get the flag**: The server validates the hash collision and returns the flag

## The Attack

```bash
# Option 1: Using Python socket
python3 -c "
import socket
s = socket.socket()
s.connect(('154.57.164.80', 30979))
print(s.recv(4096).decode())
s.send(b'72e46164795f706c61795f6f6e6521\n')
print(s.recv(4096).decode())
s.close()
"

# Option 2: Using netcat
echo '72e46164795f706c61795f6f6e6521' | nc 154.57.164.80 30979
```

## Key Insights

This challenge highlights why custom cryptographic implementations are dangerous. Even small deviations from the standard (like summing shifts to 7 instead of 8) can create exploitable vulnerabilities. Always use well-tested cryptographic libraries rather than rolling your own.

The lesson here is: **never implement crypto from scratch unless absolutely necessary**, and if you do, have it audited by security professionals.

## Lessons Learned

1. Lossy transformations (where information is discarded) can create collisions
2. A seemingly small error in bitwise operations can completely break cryptographic schemes
3. Hash functions must be bijective (one-to-one) to prevent collisions
4. This is a practical example of why cryptographic agility and proper implementation matter

---

*Flag obtained during Global Ynov Partners CTF Challenge (Apr 18-19, 2026)*
