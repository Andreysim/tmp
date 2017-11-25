#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

const char* getEnd(const char* str) {
    while (*str) {
        ++str;
    }
    return str;
}

const char* findCh(const char* first, const char* last, const char ch) {
    while (first != last && *first != ch) {
        ++first;
    }
    return first;
}

const char* skipws(const char* first, const char* last) {
    while (first != last && *first == ' ') {
        ++first;
    }
    return first;
}

const char* rdarg(const char* first, const char* last, char** ret) {
    first = skipws(first, last);
    if (first == last) {
        return first;
    }
    last = findCh(first, last, ' ');
    *ret = malloc(last - first + 1);
    char* dst = *ret;
    while (first != last) {
        *dst++ = *first++;
    }
    *dst = 0;
    return first;
}

char** rdargs(const char* first, const char* last) {
    char** ret = malloc(sizeof(char*) * 16);
    memset(ret, 0, sizeof(char*) * 16);
    int i = 0;
    while(1) {
        char *arg = 0;
        first = rdarg(first, last, &arg);
        if (!arg) {
            break;
        }
        ret[i++] = arg;
    }
    if (i == 0) {
        free(ret);
        ret = 0;
    }
    return ret;
}

char*** rdcalls(const char* str, int* ncalls) {
    char*** ret = malloc(sizeof(char**) * 16);
    memset(ret, 0, sizeof(char**) * 16);
    int i = 0;
    const char* first = str;
	const char* last = 0;
    const char* end = getEnd(str);
    while(last != end) {
        last = findCh(first, end, '|');
        if (first == last) {
            break;
        }
        char** args = rdargs(first, last);
        if (!args) {
            break;
        }
        ret[i++] = args;
        first = last + 1;
    }
	*ncalls = i;
    if (i == 0) {
        free(ret);
        ret = 0;
    }
    return ret;
}

void swapargs(char*** args, int argc) {
    char*** end = args + argc - 1;
    while (args < end) {
        char** tmp = *args;
        *args = *end;
        *end = tmp;
        ++args;
        --end;
    }
}

void freecalls(char*** calls) {
	char*** it1;
	char**  it2;
	char*   it3;
	for (it1 = calls; *it1; ++it1) {
		for (it2 = *it1; *it2; ++it2) {
			free(*it2);
		}
		free(*it1);
	}
	free(calls);
}

void replace_fd(int oldfd, int newfd) {
	close(oldfd);
	dup2(newfd, oldfd);
	close(newfd);
}

void printCall(char** call) {
	fprintf(stderr, "Command: \"%s\"\n", *call);
	int i = 0;
	while(*call) {
		fprintf(stderr, "Arg%d: %s\n", i++, *call++);
	}
}

void do_pipe(char*** args, int argc) {
	if (argc == 1) {
		printCall(*args);
		execvp(**args, *args);
	} else {
		int fd[2];
		pipe(fd);
		if (fork()) {
			replace_fd(STDIN_FILENO, fd[0]);
			close(fd[1]);
			printCall(*args);
			execvp(**args, *args);	
		} else {
			replace_fd(STDOUT_FILENO, fd[1]);
			close(fd[0]);
			do_pipe(args + 1, argc - 1);
		}
	}
}
int main() {
    char buff[1024] = {};
    scanf("%[^\n]", buff);
	int nc = 0;
    char*** args = rdcalls(buff, &nc);
    swapargs(args, nc);

    int f = open("result.out", O_RDWR | O_CREAT | O_TRUNC, 0666);
	if (f == -1) {
		fprintf(stderr, "File not opened\n");
	} else {
    close(STDOUT_FILENO);
    dup2(f,STDOUT_FILENO);
    close(f);
	fprintf(stderr, "PID: %u\n", getpid());
    do_pipe(args, nc);
	}
	fprintf(stderr, "PID: %u\n", getpid());
	fprintf(stderr, "Free args\n");
	freecalls(args);
    return 0;
}


