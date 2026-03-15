//
//  CarbonAppProcess.h
//  JamWiFi
//

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>

@interface CarbonAppProcess : NSObject

@property (nonatomic, strong) NSRunningApplication *app;

+ (CarbonAppProcess *)current;
+ (CarbonAppProcess *)frontmostProcess;

- (void)makeFrontmost;
- (void)setHidden:(BOOL)hide;
- (BOOL)isFrontmost;

@end
