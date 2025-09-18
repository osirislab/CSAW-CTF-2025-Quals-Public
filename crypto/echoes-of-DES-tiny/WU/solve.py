from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
from hashlib import md5

chirp = bytes.fromhex(
    "ff988a2b2a0f7310bb85abdeea7f7c2482c767ab7edc8d409e3045fb1fb8e19d18afc7b44d7b1882037715b37a117b62"
)
with open("scrambled", "rb") as f:
    scrambled = f.read()

key = b"alien69"  # found by brute-forcing rockyou.txt or similar password wordlist
# know its ECB if we run `strings` on scrambled and decode the appended base64
cipher = DES.new(pad(key, DES.block_size), DES.MODE_ECB)
software = cipher.decrypt(pad(scrambled, DES.block_size))

key = b"proxima centauri b"  # found by following the text hints in the decrypted code
digest = md5(key).digest()[:8]
cipher = DES.new(digest, DES.MODE_ECB)

print(software.decode(errors="ignore"))
print()
print(cipher.decrypt(chirp).decode())
