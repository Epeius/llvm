#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define BUFSIZE 128

enum LANG {
    C,      // 0
    CXX,    // 1
    Python, // 2
    Matlab  // 3
};

int main() {
    char buff[BUFSIZE];
    memset(buff, 0, BUFSIZE);
    read(0, buff, BUFSIZE);

    unsigned int lang = atoi(buff);
    switch (lang) {
        case C:
            printf("C\n");
            break;
        case CXX:
            printf("CXX\n");
            break;
        case Python:
            printf("Python\n");
            break;
        case Matlab:
            printf("Matlab\n");
            abort();
            break;
        default:
            printf("Unknow\n");
            break;
    }

    return 0;
}
