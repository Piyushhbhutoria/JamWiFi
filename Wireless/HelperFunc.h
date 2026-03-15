


#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <unistd.h>
#include <sys/types.h>

void runAlert(NSString*title, NSString*message);

// Fork a child process that immediately drops to (uid, gid) and exec's the app
// binary at execPath with "--scan-mode" as its sole argument.  The child's
// stdout is wired to a pipe; the returned fd is the read end (-1 on error).
// *outPid is set to the child pid on success.
int spawnScanSubprocess(const char *execPath, uid_t uid, gid_t gid, pid_t *outPid);
