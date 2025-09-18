# Shadow Protocol – Writeup (Solution 2: Time Injection + Side-Channel)

This solution sidesteps reversing the Feistel-like cipher and the 3-bit tree. Instead, it exploits two behaviors:

1. Deterministic time seeding with “time dilation”  
   The binary seeds rand() with ((time(NULL) + 5*365*24*60*60)/60)*60, i.e., current time + 5 years, floored to the minute.

2. Intentional side channel  
   Immediately after computing the session key star_key = shadow_protocol(stardust), the program leaks it to 127.0.0.1:47831 as a decimal string.  

Once star_key is known, the printed ciphertext is decrypted with a repeating 8-byte XOR keystream:

enc[i] = flag[i] ^ ((star_key >> (8 * (i % 8))) & 0xFF)  
⇒ flag[i] = enc[i] ^ ((star_key >> (8 * (i % 8))) & 0xFF)

---

## Attack Plan

1. Inject time so the local handout binary uses the same minute-aligned, future seed as the remote.
2. Capture star_key by running the handout binary locally while a TCP listener waits on 127.0.0.1:47831.
3. Fetch ciphertext from the remote service (containerized and exposed via socat).
4. Decrypt with XOR using the recovered star_key.

---

## Steps

1. Run local solver with forced epoch:
   faketime "2025-08-15 22:00:00" ./shadow_protocol

2. Extract star_key from the TCP listener output.

3. Collect ciphertext from remote:
   nc challenge.host 3000 > ciphertext.bin

4. Decrypt:
   ```python
   with open("ciphertext.bin", "rb") as f:
       enc = f.read()

   flag = bytearray()
   for i, b in enumerate(enc):
       flag.append(b ^ ((star_key >> (8 * (i % 8))) & 0xFF))

   print(flag.decode())
   ```

## Result
ResulDecryption yields the flag:

CSAW{pr070c0l5_1n_7h3_5h4d0w5_4r3_h4rd_70_r3v3r53_xxxx}