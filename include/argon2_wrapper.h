#ifndef ARGON2_WRAPPER_H
#define ARGON2_WRAPPER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <termios.h>

static void usage(const char *);
static void print_hex(uint8_t *, size_t);
static size_t getpasswd(char *__restrict, size_t);

void usage(const char *progName) {
    fprintf(stderr,
            "Usage is: %s SALT [-h] [-p THREADS] [-l HASH_LEN] [-m "
            "MEMORY_COST] [-t ITERATIONS]\n",
            progName);

    exit(EXIT_FAILURE);
}

void print_hex(uint8_t *bytes, size_t bytes_len) {
    size_t i;
    for (i = 0; i < bytes_len; ++i) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

size_t getpasswd(char *__restrict passwd_buf, size_t bufsz) {
    int s;
    struct termios old_termios, new_termios;

    if (passwd_buf == NULL)
        return -1;

    tcgetattr(STDIN_FILENO, &old_termios);

    new_termios = old_termios;
    new_termios.c_lflag &= ~(ECHO);

    fprintf(stderr, "Enter password: ");
    tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);

    s = read(STDIN_FILENO, passwd_buf, bufsz);

    if (s < 1)
        return -2;

    tcsetattr(STDIN_FILENO, TCSANOW, &old_termios);
    putchar('\n');

    return strlen(passwd_buf);
}

#endif
