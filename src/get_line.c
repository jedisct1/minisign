
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__)) || defined(__HAIKU__)
#    include <sys/types.h>
#endif

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__)) || defined(__HAIKU__)
#    include <fcntl.h>
#    include <poll.h>
#    include <termios.h>
#    include <unistd.h>
#elif defined(_WIN32)
#    include <windows.h>
#endif

#include "get_line.h"
#include "helpers.h"

#ifndef TCSAFLUSH
#    define TCSAFLUSH 0
#endif

#ifndef VERIFY_ONLY

static void
disable_echo(void)
{
    fflush(stdout);
    fflush(stderr);

#    if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__)) || defined(__HAIKU__)
    {
        struct termios p;

        if (!isatty(0) || tcgetattr(0, &p) != 0) {
            return;
        }
        p.c_lflag &= ~ECHO;
        tcsetattr(0, TCSAFLUSH, &p);
    }
#    elif defined(_WIN32)
    {
        HANDLE handle = GetStdHandle(STD_INPUT_HANDLE);
        DWORD  mode   = 0;

        GetConsoleMode(handle, &mode);
        SetConsoleMode(handle, mode & ~ENABLE_ECHO_INPUT);
    }
#    endif
}

static void
enable_echo(void)
{
    fflush(stdout);
    fflush(stderr);

#    if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__)) || defined(__HAIKU__)
    {
        struct termios p;

        if (!isatty(0) || tcgetattr(0, &p) != 0) {
            return;
        }
        p.c_lflag |= ECHO;
        tcsetattr(0, TCSAFLUSH, &p);
    }
#    elif defined(_WIN32)
    {
        HANDLE handle = GetStdHandle(STD_INPUT_HANDLE);
        DWORD  mode   = 0;

        GetConsoleMode(handle, &mode);
        SetConsoleMode(handle, mode | ENABLE_ECHO_INPUT);
    }
#    endif
}

int
get_line(char *line, size_t max_len, const char *prompt)
{
    int truncated;

    memset(line, 0, max_len);
    if (max_len < 2U || max_len > INT_MAX) {
        return -1;
    }
    xfprintf(stderr, "%s", prompt);
    fflush(stderr);
    if (fgets(line, (int) max_len, stdin) == NULL) {
        return -1;
    }
    truncated = (strchr(line, '\n') == NULL && !feof(stdin));
    trim(line);
    if (truncated) {
        fprintf(stderr, "(truncated to %u characters)\n", (unsigned int) max_len - 1);
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
