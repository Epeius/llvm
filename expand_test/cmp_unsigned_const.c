#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define BUFSIZE 128

int main() {
    char buff[BUFSIZE];
    memset(buff, 0, BUFSIZE);
    read(0, buff, BUFSIZE);

    unsigned int value = atoi(buff);
    if (value == 0xdeadbeaf) {
        abort();
    }

    return 0;
}
