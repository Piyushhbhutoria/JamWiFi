//
//  main.m
//  JamWiFi
//

#import <Cocoa/Cocoa.h>
#import <CoreWLAN/CoreWLAN.h>

#import "HelperFunc.h"
#import "JamWiFi-Swift.h"

int main(int argc, char *argv[]) {

    @autoreleasepool {

        // Scan mode: invoked as the console user by the root process via
        // fork+setuid+execv so CoreWLAN returns real SSID/BSSID values.
        if (argc >= 2 && strcmp(argv[1], "--scan-mode") == 0) {
            [JWScanModeRunner run];
            return 0;
        }

        NSLog(@"Main.m: Initializing..");

        if (geteuid()) {
            NSString *execPath = [[NSBundle mainBundle] executablePath];
            NSString *script = [NSString stringWithFormat:
                @"do shell script quoted form of \"%@\" with administrator privileges",
                execPath];
            NSAppleScript *appleScript = [[NSAppleScript alloc] initWithSource:script];
            NSDictionary *errorInfo = nil;
            [appleScript executeAndReturnError:&errorInfo];

            if (errorInfo) {
                runAlert(@"Cannot run without admin privileges",
                         @"This program cannot tap into the wireless network stack without administrator access.");
            }
            exit(0);
        }

        return NSApplicationMain(argc, (const char **)argv);
    }
}
