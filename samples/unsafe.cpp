#include <cstdio>
#include <cstring>
#include <cstdlib>

void unsafeFunction(char* input) {

    char buffer[20];

    gets(buffer);

    strcpy(buffer, input);

    strcat(buffer, input);

    sprintf(buffer, "%s", input);

    system(input);
}