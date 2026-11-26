int calculate(int a, int b, int c) {

    int result = 0;

    if (a > 0 && b > 0) {
        result += a;
    }

    if (c > 0) {
        result += c;
    }

    for (int i = 0; i < b; i++) {

        if (i % 2 == 0) {
            result += i;
        }
    }

    while (result > 100) {
        result--;
    }

    return result;
}