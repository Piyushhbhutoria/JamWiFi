


#import "HelperFunc.h"
#include <fcntl.h>
#include <sys/wait.h>
#include <stdlib.h>

void runAlert(NSString*title, NSString*message) {
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = title;
    alert.informativeText = message;
    [alert addButtonWithTitle:@"OK"];
    [alert runModal];
}

// All operations in the child between fork() and execv() are async-signal-safe
// C calls only — no Swift/ObjC runtime is touched.
int spawnScanSubprocess(const char *execPath, uid_t uid, gid_t gid, pid_t *outPid) {
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        // Child: wire stdout to pipe, drop root, exec scanner.
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        setgid(gid);
        setuid(uid);
        char *scanArg = "--scan-mode";
        char *argv[] = { (char *)execPath, scanArg, NULL };
        execv(execPath, argv);
        _exit(1);
    }
    // Parent: return read end.
    close(pipefd[1]);
    *outPid = pid;
    return pipefd[0];
}
