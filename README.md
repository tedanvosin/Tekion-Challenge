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

### First look at the FLAG

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

### First look at the hint

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

### To the Github Repo

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

### Anonymous S3 Access

So listing the contents of the s3 bucket using aws cli and --no-sign-request flag to run the request as anonymous, we get:

``` bash
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

### Back to the Github Repo

As the combined_salaries_backup.bin didnt give me any clue to proceed, I went back to the github repo to find any clues I might've missed. Going through the repo, I remembered the challenge text, which mentioned something about git, so I looked at the older commits to the repo.

The previous commits showed 5 file that have been removed in the current repository. These files were:

- [access_store](./files/github_repo/old_commits/access%20store)
- [iam policies](./files/github_repo/old_commits/iam_policies)
- [bucket_policy](./files/github_repo/old_commits/bucket_policy)
- [lambda_policy](./files/github_repo/old_commits/lambda%20policies)
- [lambda trust relation](./files/github_repo/old_commits/lambda%20trust%20relation)

In these files, the access_store file contains AWS credentials such as **access_key_id** and **access_key_secret** which can allow us to access the files which are not publicly accessible on the s3 bucket.Apart from that, the bucket policy seem to be an older version of the test_policy file we currently have, and the lambda_trust_relation file states that both the Lambda service and any AWS account can assume the Lambda service role.

### Authenticated S3 Access
Now since we have the AWS credentials, we can access the global_salaries directory on the s3 bucket. First we have to configure aws:
``` bash
$ aws configure
AWS Access Key ID [None]: AKIARWHD4LUYUJZYDVG3
AWS Secret Access Key [None]: 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
Default region name [us-west-1]: us-west-1
Default output format [json]: json
```


## Final FLAG:

```
almost_there{curious_seeker}
```
