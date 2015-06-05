
#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "get_line.h"
#include "helpers.h"

#ifndef TCSAFLUSH
# define TCSAFLUSH 0
#endif

#ifndef VERIFY_ONLY

static void
disable_echo(void)
{
    struct termios p;

    fpurge(stdin);
    fflush(stdout);
    fflush(stderr);
    if (!isatty(0) || tcgetattr(0, &p) != 0) {
        return;
    }
    p.c_lflag &= ~ECHO;
    tcsetattr(0, TCSAFLUSH, &p);
}

static void
enable_echo(void)
{
    struct termios p;

    fpurge(stdin);
    fflush(stdout);
    fflush(stderr);
    if (!isatty(0) || tcgetattr(0, &p) != 0) {
        return;
    }
    p.c_lflag |= ECHO;
    tcsetattr(0, TCSAFLUSH, &p);
}

int
get_line(char *line, size_t max_len, const char *prompt)
{
    memset(line, 0, max_len);
    if (max_len < 2U || max_len > INT_MAX) {
        return -1;
    }
    xfprintf(stderr, "%s", prompt);
    fflush(stderr);
    if (fgets(line, (int) max_len, stdin) == NULL) {
        return -1;
    }
    trim(line);
    if (strlen(line) >= max_len) {
        fprintf(stderr, "(truncated to %u characters)\n", (int) max_len);
    } else if (*line == 0) {
        fprintf(stderr, "(empty)\n");
    } else {
        fprintf(stderr, "\n");
    }
    return 0;
}

int
get_password(char *pwd, size_t max_len, const char *prompt)
{
    int ret;

    disable_echo();
    ret = get_line(pwd, max_len, prompt);
    enable_echo();

    return ret;
}

#endif
