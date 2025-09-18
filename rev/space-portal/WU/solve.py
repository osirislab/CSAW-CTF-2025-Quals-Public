from Crypto.Cipher import DES
import ctypes
import hashlib
from pwn import *

context.log_level = 'debug'

p = process('./chal')

def zero_pad(data):
    return data+b'\x00'*((8-len(data)%8)%8)

def zero_unpad(data):
    return data.rstrip(b'\x00')

libc = ctypes.CDLL('libc.so.6')
libc.time.argtypes = [ctypes.POINTER(ctypes.c_long)]
libc.srand.argtypes = [ctypes.c_uint]
current_time = ctypes.c_long()
libc.time(ctypes.byref(current_time))
libc.srand(ctypes.c_uint(current_time.value))
libc.rand.restype = ctypes.c_int

spaceship_name = b'csaw2025rev'
access_code = b'csaw2025rev'
msg_cnt = 0
des_key = hashlib.md5(spaceship_name+access_code).digest()[0:8]

p.sendlineafter(b"Please enter your spaceship name: \n", spaceship_name)
p.sendlineafter(b"Please enter your access code: \n", access_code)

p.recvuntil(b"Authenticating your entry...\n")
payload1 = b''
payload1 += b'\x01'
payload1 += b'\x05'
payload1 += b'\x01'
payload1 += msg_cnt.to_bytes(2, 'big')
msg_cnt += 1
payload1 += b'\x00'*2
payload1 += (libc.rand()%256).to_bytes(1, 'big')
payload1 += b'\x00'*16
payload1 += zero_pad(spaceship_name+access_code)
payload1 = payload1[0:5]+len(payload1[24:]).to_bytes(2, 'big')+payload1[7:]
p.send(payload1)

sleep(1)

p.recvuntil(b"Leaking signature...\n")
msg1 = p.recvuntil(b"Signature leaked!\n", drop=True)
msg_cnt += 1
libc.rand()
cipher = DES.new(des_key, DES.MODE_ECB)
wormhole_signature = bytes([b^0xFF for b in cipher.decrypt(msg1[24:])[::-1]])

p.recvuntil(b"Validating signature...\n")
payload2 = b''
payload2 += b'\x02'
payload2 += b'\x4c'
payload2 += b'\x01'
payload2 += msg_cnt.to_bytes(2, 'big')
msg_cnt += 1
payload2 += b'\x00'*2
payload2 += (libc.rand()%256).to_bytes(1, 'big')
payload2 += b'\x00'*16
payload2 += zero_pad(wormhole_signature)
payload2 = payload2[0:5]+len(payload2[24:]).to_bytes(2, 'big')+payload2[7:]
payload2 = payload2[0:24]+bytes([b^payload2[7] for b in payload2[24:]])
payload2 = payload2[0:8]+hashlib.md5(payload2).digest()+cipher.encrypt(payload2[24:])
p.send(payload2)
des_key = wormhole_signature

p.recvuntil(b"Sending coordinate...\n")
msg2 = p.recvuntil(b"Coordinate sent!\n", drop=True)
msg_cnt += 1
libc.rand()
cipher = DES.new(des_key, DES.MODE_ECB)
location = msg2[24:]
flag = zero_unpad(cipher.decrypt(location)).decode()
print(flag)

p.interactive()