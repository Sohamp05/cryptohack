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
