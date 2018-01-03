#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define BUFSIZE 128

#define HASH "THIS_IS_A_TEST_STRING_FOR_HASH"

int main() {
    char buff[BUFSIZE];
    memset(buff, 0, BUFSIZE);
    read(0, buff, BUFSIZE);

    if (!memcmp(buff, HASH, strlen(HASH))) {
        abort();
    }

    return 0;
}
