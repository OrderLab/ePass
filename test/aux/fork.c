#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

int main() {
    for (int i = 0; i < 10000; i++) {
        pid_t pid = fork();
        if (pid == 0) { // Child process
            char *args[] = {"./test", "-l", NULL};
            char *env[] = {NULL}; // No environment variables
            if (execve("./test", args, env) == -1) {
                perror("execve failed");
                exit(EXIT_FAILURE);
            }
        } else if (pid < 0) {
            perror("fork failed");
            exit(EXIT_FAILURE);
        }
    }
    // Wait for all child processes to finish
    while (wait(NULL) > 0);
    return 0;
}
