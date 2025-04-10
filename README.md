# Tekion-Challenge

This repo has my writeup for the challenge posted on LinkedIn.

'''
"People lie! Git doesn't. That's the ONLY SSOT. May the master of the key know this!" =>
'''

Stuff given:

HINT:
Julius wants to help. So he left something here:

cookn://bdocpw.xjh/ozfdji-nkzzy/cmhn-xjhk-ntnozhn-yphk/omzz/hvdi

FLAG =>
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1lZDI1NTE5IHBVT05LQSBGclNwUEwzNnBzVjZoUGVGdk9SVjFOOVRTd1JqRjdpTi9TaU81ckVudzFZCnl1WmlmV2diY2M2Smt5dFBmRFA4aW5JQ0loQTI0S1R3endlNmdmaTFSWEUKLS0tIE5yK0d3MFg5T0Vac0sxaGFNbUphcm9rbm1PUlRwVEZJNjRTZ0N3MTFFaTAKyJ9jMF/k1r9D3871i1PluzFDSo1kJZENZTI5+9HHPQLDlcTn9+xJmWIsrARtN7IrBzUp2lae9zH1T2xdI0Q1d5EAPBXP1MlNZGSb/X+5mNgPPLQucvWe3APKeGCtVB8BN5UVZREKbO/4iUP+wdgclw==

Flag format => string{string}

WRITE-UP

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

This 'FLAG' doesnt provide any more context so now lets go to the hint.

The hint was:

cookn://bdocpw.xjh/ozfdji-nkzzy/cmhn-xjhk-ntnozhn-yphk/omzz/hvdi

looking at the '/' and the challenge text which says something about GIT, this looks like an encrypted link.

Running it through the dcode cipher identifier, it gives the following possible ciphers:
![](./images/dcode-identify.png)

