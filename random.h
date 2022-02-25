/*************************************************************************
 * Copyright (c) 2020-2021 Elichai Turkel                                *
 * Distributed under the CC0 software license, see the accompanying file *
 * EXAMPLES_COPYING or https://creativecommons.org/publicdomain/zero/1.0 *
 *************************************************************************/

/*
 * This file is an attempt at collecting best practice methods for obtaining randomness with different operating systems.
 * It may be out-of-date. Consult the documentation of the operating system before considering to use the methods below.
 *
 * Platform randomness sources:
 * Linux   -> `getrandom(2)`(`sys/random.h`), if not available `/dev/urandom` should be used. http://man7.org/linux/man-pages/man2/getrandom.2.html, https://linux.die.net/man/4/urandom
 * macOS   -> `getentropy(2)`(`sys/random.h`), if not available `/dev/urandom` should be used. https://www.unix.com/man-page/mojave/2/getentropy, https://opensource.apple.com/source/xnu/xnu-517.12.7/bsd/man/man4/random.4.auto.html
 * FreeBSD -> `getrandom(2)`(`sys/random.h`), if not available `kern.arandom` should be used. https://www.freebsd.org/cgi/man.cgi?query=getrandom, https://www.freebsd.org/cgi/man.cgi?query=random&sektion=4
 * OpenBSD -> `getentropy(2)`(`unistd.h`), if not available `/dev/urandom` should be used. https://man.openbsd.org/getentropy, https://man.openbsd.org/urandom
 * Windows -> `BCryptGenRandom`(`bcrypt.h`). https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
 */

#if defined(_WIN32)
#include <windows.h>
#include <ntstatus.h>
#include <bcrypt.h>
#elif defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/random.h>
#elif defined(__OpenBSD__)
#include <unistd.h>
#else
#error "Couldn't identify the OS"
#endif

#include <stddef.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>


uint64_t random_state = 12345;

// Pseudo-random 64 bit number, based on xorshift*
uint64_t rand64(void)
{
    random_state ^= random_state >> 12;
    random_state ^= random_state << 25;
    random_state ^= random_state >> 27;
    return random_state * 0x2545F4914F6CDD1D; // magic constant
}


/* Returns 1 on success, and 0 on failure. */
static int fill_random(unsigned char* data, size_t size) {
	size_t i;

    for (i = 0; i < size; i++) {
       data[i] = (uint8_t)rand64();
    }
	return 1;
}

static void print_hex(unsigned char* data, size_t size) {
    size_t i;
    printf("0x");
    for (i = 0; i < size; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}
