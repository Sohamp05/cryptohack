## Structure of AES

```{python}

def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return [chr(i) for j in matrix for i in j]

matrix = [
    [99, 114, 121, 112],
    [116, 111, 123, 105],
    [110, 109, 97, 116],
    [114, 105, 120, 125],
]

print(matrix2bytes(matrix))

```
## Round Keys

```{python}

def add_round_key(s, k):
    ar  = [list(s[i][j]^k[i][j] for j in range(4)) for i in range(4)]
    return ar

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return [chr(i) for j in matrix for i in j]

print(add_round_key(state, round_key))
print(matrix2bytes(add_round_key(state, round_key)))

```

## Confusion through Permutation

```{python}
def sub_bytes(s, sbox=s_box):
   return matrix2bytes[list(int(sbox[s[j][i]]) for i in range(4)) for j in range(4)])

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return [chr(i) for j in matrix for i in j]


print(sub_bytes(state, sbox=inv_s_box))

```

## Diffusion through Permutation

```{python}
def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]
    return s
    


# learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


state = [
    [108, 106, 71, 86],
    [96, 62, 38, 72],
    [42, 184, 92, 209],
    [94, 79, 8, 54],
]

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return [chr(i) for j in matrix for i in j]

inv_mix_columns(state)
inv_shift_rows(state)
print(matrix2bytes(state))
```

## Bringing it All Together

```{python}
def decrypt(key, ciphertext):
    round_keys = expand_key(key) # Remember to start from the last round key and work backwards through them when decrypting

    # Convert ciphertext to state matrix
    text = bytes2matrix(ciphertext)
    # Initial add round key step
    add_round_key(text, round_keys[10])

    for i in range(N_ROUNDS - 1, 0, -1):
        inv_shift_rows(text)
        inv_sub_bytes(text)
        add_round_key(text, round_keys[i])
        inv_mix_columns(text)
    # Run final round (skips the InvMixColumns step)
    inv_shift_rows(text)
    inv_sub_bytes(text)
    add_round_key(text, round_keys[0])
    # Convert state matrix to plaintext

    plaintext = matrix2bytes(text)
    return plaintext

print(decrypt(key, ciphertext))
```
## Modes of Operation Starter

Just get the encrypted ciphertext and put it into decrypt function and then hex decode

## Passwords as Keys

Find the hash by bruteforcing md5 the txt file given and then put the cipher and hash and get the flag

