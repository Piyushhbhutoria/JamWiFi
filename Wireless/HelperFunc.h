
#import <Foundation/Foundation.h>
#include <sys/types.h>

// Fork a child that drops to (uid, gid) and exec's the app with "--scan-mode".
// Returns the read end of a pipe connected to the child's stdout, or -1 on error.
int spawnScanSubprocess(const char *execPath, uid_t uid, gid_t gid, pid_t *outPid);
