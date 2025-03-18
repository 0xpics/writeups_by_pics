# Duckware Team - Maps (UTCTF - 2025)

###### This CTF was solved by @0xpics

>This CTF is about Reverse Engineering, cryptography algorithm

## Challenge Overview

This challenge involves reverse engineering a cryptographic algorithm. The goal is to analyze how the encryption process works and then decrypt a given text file to retrieve the flag.

## Challenge Details

* `chal` - a binary executable

* `output.txt` - a plaintext file containing an encrypted string


**Analyzing the Binary**

Before running the binary, we give it execution permissions using:

```
chmod 777 chal
```

Executing the program produces the following message:

**_Transform!_**

When we input a test string, such as `test`, we receive this output:

```
4934949364493464934949265492654926549265492654926549265492654926549265492654926549265492654926549265492654926549265492654926549265492654926549265492654926549265492654926549265`
```

The program then exits.

**Investigating the Output File**

Examining `output.txt`, we find the following content:

```
4934849349493674935749360493664940249346493534935849348493574936549351493644937449348493464936449365493744935349360493464935449364493574935749374493494935349358493594935449404
```

Comparing this string with the output from our test input, we notice a striking similarity. This suggests that the file contains an encrypted version of a message, likely the flag.

## Formulating a Strategy

Since UTCTF flags follow the format `utflag{}`, we can test this assumption by inputting utflag into the binary. The output we receive is:

```
4934849349493674935749360493664926549265492654926549265492654926549265492654926549265492654926549265492654926549265492654926549265492654926549265492654926549265492654926549265
```

Comparing this with the first 24 characters of `output.txt` we see that they match:

```
493484934949367493574936049366
```

From this, we can deduce that each letter is encoded into a 5-digit number. Identifying a few mappings:

```
u -> 49348
t -> 49349
f -> 49367
l -> 49357
a -> 49360
g -> 49366
```

**Confirming the Encoding Pattern**

To verify whether these mappings are position-independent, we input the entire alphabet into the program:

```
abcdefghijklmnopqrstuvwxyz
```

The output we receive:


```
4936049363493624936549364493674936649353493524935549354493574935649359493584934549344493474934649349493484935149350494014940049403492654926549265492654926549265492654926549265
````

Checking against known values (such as `u -> 49348`), we confirm that each letter consistently maps to the same 5-digit number.

## Decrypting the Flag

Since we now have a mapping for all letters, we can decode the flag using the following script:

```
def decode(encoded_string, num_to_char):
    blocks = [encoded_string[i:i + 5] for i in range(0, len(encoded_string), 5)]

    decoded_flag = ''.join([num_to_char.get(block, '?') for block in blocks])
    return decoded_flag


encoded_string = "4934849349493674935749360493664940249346493534935849348493574936549351493644937449348493464936449365493744935349360493464935449364493574935749374493494935349358493594935449404"

num_to_char = {
    '49360': 'a',
    '49363': 'b',
    '49362': 'c',
    '49365': 'd',
    '49364': 'e',
    '49367': 'f',
    '49366': 'g',
    '49353': 'h',
    '49352': 'i',
    '49355': 'j',
    '49354': 'k',
    '49357': 'l',
    '49356': 'm',
    '49359': 'n',
    '49358': 'o',
    '49345': 'p',
    '49344': 'q',
    '49347': 'r',
    '49346': 's',
    '49349': 't',
    '49348': 'u',
    '49351': 'v',
    '49350': 'w',
    '49401': 'x',
    '49400': 'y',
    '49403': 'z',
    '49402': '{',
    '49404': '}'
}

decoded_flag = decode(encoded_string, num_to_char)
print("Flag decodificada:", decoded_flag)
```

**Final Flag**

> utflag{shouldve_used_haskell_thonk}
