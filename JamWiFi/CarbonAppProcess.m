//
//  CarbonAppProcess.m
//  JamWiFi
//

#import "CarbonAppProcess.h"

@implementation CarbonAppProcess

+ (CarbonAppProcess *)current {
    CarbonAppProcess *p = [[CarbonAppProcess alloc] init];
    p.app = NSRunningApplication.currentApplication;
    return p;
}

+ (CarbonAppProcess *)frontmostProcess {
    CarbonAppProcess *p = [[CarbonAppProcess alloc] init];
    p.app = NSWorkspace.sharedWorkspace.frontmostApplication;
    return p;
}

- (void)makeFrontmost {
    [NSApp activate];
}

- (void)setHidden:(BOOL)hide {
    if (hide) {
        [self.app hide];
    } else {
        [self.app unhide];
    }
}

- (BOOL)isFrontmost {
    return self.app.isActive;
}

@end
