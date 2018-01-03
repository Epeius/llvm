#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define BUFSIZE 128

void buggy(char* src)
{
    char buf[16];
    strcpy(buf, src);
}

int main() {
    char buff[BUFSIZE];
    memset(buff, 0, BUFSIZE);
    read(0, buff, BUFSIZE);

    buggy(buff);

    return 0;
}
