# How to use

First of all, you'll recieve the handshake which will look something like this:
```
14 00 00 01 58 FE 13 89 88 D4 BD B7 13 2A 29 5D
21 CF 1B 07 
```

Decrypt it via `Decrypt(1, data, 4)`.
The result from this is the key which is used afterwards:
`crypto.SetKey(BitConverter.ToInt32(handshake_res, 8));`

Once the key is set, encrypt and decrypt with flag 2:
 `Decrypt(2, data, offset)`
