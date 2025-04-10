# Tekion-Challenge

This repo has my writeup for the challenge posted on LinkedIn.

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

Looking at the FLAG format, it appears to be base64 encoded, and decoding it gives:

```bash
$ echo "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1lZDI1NTE5IHBVT05LQSBGclNwUEwzNnBzVjZoUGVGdk9SVjFOOVRTd1JqRjdpTi9TaU81ckVudzFZCnl1WmlmV2diY2M2Smt5dFBmRFA4aW5JQ0loQTI0S1R3endlNmdmaTFSWEUKLS0tIE5yK0d3MFg5T0Vac0sxaGFNbUphcm9rbm1PUlRwVEZJNjRTZ0N3MTFFaTAKyJ9jMF/k1r9D3871i1PluzFDSo1kJZENZTI5+9HHPQLDlcTn9+xJmWIsrARtN7IrBzUp2lae9zH1T2xdI0Q1d5EAPBXP1MlNZGSb/X+5mNgPPLQucvWe3APKeGCtVB8BN5UVZREKbO/4iUP+wdgclw==" | base64 -d
age-encryption.org/v1
-> ssh-ed25519 pUONKA FrSpPL36psV6hPeFvORV1N9TSwRjF7iN/SiO5rEnw1Y
yuZifWgbcc6JkytPfDP8inICIhA24KTwzwe6gfi1RXE
--- Nr+Gw0X9OEZsK1haMmJaroknmORTpTFI64SgCw11Ei0
e29���=Õ����I�b,�m7�+5)�V��1�Ol]#D5w�<���Mdd�����<�.r����x`�T7�e

```

It looks like it was encrypted using age-encryption/v1 using SSH ED25519 public key.

This doesnt provide any more context to approach the challenge, so now lets go to the hint.

The hint was:
```
cookn://bdocpw.xjh/ozfdji-nkzzy/cmhn-xjhk-ntnozhn-yphk/omzz/hvdi
```
looking at the hint format, this looks like an encrypted link.

Running it through the dcode cipher identifier, it gives the following possible ciphers:
![](./images/dcode-identify.png)

Now running it through the ROT Cipher Decoder, we get:
![](./images/dcode-rot13.png)

This deciphers the link to: **https://github.com/tekion-speed/hrms-comp-systems-dump/tree/main**

This link points to a github repo **tekion-speed/hrms-comp-systems-dump**
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

So listing the contents of the s3 bucket using aws cli and --no-sign-request flag to run the request as anonymous, we get:

```bash
$ aws s3 ls s3://tekion-hr-system-backup --no-sign-request
                           PRE global-salaries/
2025-03-27 16:23:02     614454 combined_salaries_backup.bin
```

The bucket has a folder named global-salaries and a file named combined_salaries_backup.bin. As we saw in the policies we cannot access the global-salaries folder as an anonymous user, but I was able to download the [combined_salaries_backup.bin](./files/s3-bucket/combined_salaries_backup.bin) file.