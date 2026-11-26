def calculate(a, b, c):

    result = 0

    if a > 0 and b > 0:
        result += a

    if c > 0:
        result += c

    for i in range(b):
        if i % 2 == 0:
            result += i

    while result > 100:
        result -= 1

    return result