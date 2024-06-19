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

## ECB Oracle

```{python}
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes, bytes_to_long

def response(byte_string):
	url = "http://aes.cryptohack.org/ecbcbcwtf/decrypt/"
	url += byte_string.hex()
	url += "/"
	r = requests.get(url)
	js = r.json()
	return bytes.fromhex(js["plaintext"])

def encrypt_flag():
	url = "http://aes.cryptohack.org/ecbcbcwtf/encrypt_flag/"
	r = requests.get(url)
	js = r.json()
	return bytes.fromhex(js["ciphertext"])

def xor(a, b):
	return long_to_bytes(bytes_to_long(a) ^ bytes_to_long(b))

enc = encrypt_flag()

iv = enc[:16]
block1 = enc[16:32]
block2 = enc[32:]

decrypt_block1 = xor(response(block1), iv)
decrypt_block2 = xor(response(block2), block1)
print(decrypt_block1 + decrypt_block2)
```

## ECB CBC WTF

```{python}
# ECB CBC WTF
from Crypto.Cipher import AES
from pwn import xor
import requests

def encrypt():
    url = "http://aes.cryptohack.org//ecbcbcwtf/encrypt_flag/"
    response = requests.get(url)
    return response.json()['ciphertext']

flag = encrypt()
f = [flag[i:i+32] for i in [0,32,64]]
vi = f[0:(len(f)-1)]
f = f[1:]
def decrypt(data):
    url = "http://aes.cryptohack.org/ecbcbcwtf/decrypt/"
    response = requests.get(url + data + '/')
    return response.json()['plaintext']

for i in range(len(f)):
    f[i] = decrypt(f[i])

for i in range(len(f)):
    f[i] = xor(bytes.fromhex(f[i]),bytes.fromhex(vi[i]))

flag = ""
for i in f:
    flag += i.decode()

print(flag)
```
## Flipping Cookie

```{python}
def print_blk(hex_blks, sz):
   for i in range(0, len(hex_blks), sz):
       print(hex_blks[i:i+sz], ' ', end='')
   print()

def flip(cookie, plain):
    start = plain.find(b'admin=False')
    cookie = bytes.fromhex(cookie)
    iv = [0xff]*16
    cipher_fake = list(cookie)
    fake = b';admin=True;'
    for i in range(len(fake)):
       cipher_fake[16+i] = plain[16+i] ^ cookie[16+i] ^ fake[i]
       iv[start+i] = plain[start+i] ^ cookie[start+i] ^ fake[i]

    cipher_fake = bytes(cipher_fake).hex()
    iv = bytes(iv).hex()
    return cipher_fake, iv

def request_cookie():
    r = requests.get("http://aes.cryptohack.org/flipping_cookie/get_cookie/")
    return r.json()["cookie"]

def request_check_admin(cookie, iv):
    r = requests.get("http://aes.cryptohack.org/flipping_cookie/check_admin/{}/{}/".format(cookie, iv))
    return r.json()

expires_at = (datetime.today() + timedelta(days=1)).strftime("%s")
plain = f"admin=False;expiry={expires_at}".encode()
cookie = request_cookie()
cookie, iv = flip(cookie, plain)
print(request_check_admin(cookie, iv))
```

## Symmetry

```{python}

from pwn import xor 
import requests 

ciphertext = "9608427a24c18a23003fbe62e6f60f171b8bb41ae480d97ff5476b008e8d04a452311e437f911c333a6343d4a489b3d182"
ciphertext = bytes.fromhex(ciphertext)

iv = ciphertext[:16]
payload = ciphertext[16:]

# flag = "crypto{0fb_15_5ymm37r1c4l_!!!11!}"
flag = ""
plaintext = flag.ljust(len(payload), "=")
target = payload

def encrypt(plaintext, iv): 
    r = requests.get("http://aes.cryptohack.org/symmetry/encrypt/" + plaintext.encode().hex() + "/" + iv.hex())
    return r.text.split(":")[1][1:-3]

for i in range(33):
    print(plaintext)
    for j in range(33, 127): 
        temp = plaintext 
        temp = temp[:i] + chr(j) + temp[i + 1:] 
        temp_c = bytes.fromhex(encrypt(temp, iv))
        print(temp)
        if target[:(i + 1)] == temp_c[:(i + 1)]:
            plaintext = temp 
            break 

print(plaintext)

```
## Bean Counter

```{python}
import requests

def fetch_encrypted_data():
    url = "http://aes.cryptohack.org/bean_counter/encrypt/"
    response = requests.get(url)
    return response.json()['encrypted']

def xor_bytes(byte_array1, byte_array2):
    return bytes(x ^ y for x, y in zip(byte_array1, byte_array2))

def main():
    png_header = bytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52])
    encrypted_data = bytes.fromhex(fetch_encrypted_data())

    keystream = xor_bytes(png_header, encrypted_data[:len(png_header)])

    decrypted_data = xor_bytes(encrypted_data, keystream * (len(encrypted_data) // len(keystream)))

    with open('bean_counter.png', 'wb') as file:
        file.write(decrypted_data)

if __name__ == "__main__":
    main()
```
