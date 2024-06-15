## Quadratic Residue

```{python}
import math

ints = [14,6,11]
p = 29
b = 0
for i in range(1,29):
    for j in ints:
        if pow(i,2,p) == j:
            print(i)
            print(j)
            b = 1
print(b)
```

## Legendre Symbols

```{python}
for i in ints: 
    if pow(i, (p - 1) // 2, p) == 1:
        print(pow(i, (p + 1) // 4, p))
```
