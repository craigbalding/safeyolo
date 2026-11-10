/* Owned macOS acceptance helper. Build with Foundation, AppKit and
 * ServiceManagement. The enclosing test bundle supplies unique identities.
 * Registration results are observations, never inferred from exit status.
 */
#import <AppKit/AppKit.h>
#import <ServiceManagement/ServiceManagement.h>
#include <errno.h>
#include <fcntl.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <unistd.h>

static NSDictionary *error_info(NSError *error) {
    if (!error) return @{};
    NSMutableDictionary *result = [@{
        @"domain": error.domain, @"code": @(error.code),
        @"description": error.localizedDescription
    } mutableCopy];
    NSError *underlying = error.userInfo[NSUnderlyingErrorKey];
    if (underlying) result[@"underlying"] = error_info(underlying);
    return result;
}

@interface ProbeReceiver : NSObject
- (void)receive:(NSAppleEventDescriptor *)event reply:(NSAppleEventDescriptor *)reply;
@end
@implementation ProbeReceiver
- (void)receive:(NSAppleEventDescriptor *)event reply:(NSAppleEventDescriptor *)reply {
    (void)event;
    [reply setParamDescriptor:[NSAppleEventDescriptor descriptorWithInt32:0]
                  forKeyword:keyErrorNumber];
}
@end

int main(int argc, const char **argv) {
    @autoreleasepool {
        NSBundle *bundle = NSBundle.mainBundle;
        NSString *action = argc > 1 ? @(argv[1]) : @"mark";
        NSMutableDictionary *result = [@{
            @"action": action, @"pid": @(getpid()), @"ppid": @(getppid()),
            @"uid": @(getuid()), @"bundle": bundle.bundleIdentifier ?: @""
        } mutableCopy];
        if ([action isEqualToString:@"mark"]) {
            NSString *marker = [bundle objectForInfoDictionaryKey:@"ProbeMarker"];
            NSString *canary = [bundle objectForInfoDictionaryKey:@"ProbeCanary"];
            int fd = open(canary.fileSystemRepresentation, O_RDONLY);
            result[@"outside_read"] = @(fd >= 0);
            result[@"errno"] = @(fd < 0 ? errno : 0);
            if (fd >= 0) close(fd);
            NSData *data = [NSJSONSerialization dataWithJSONObject:result options:0 error:NULL];
            if (!marker || ![data writeToFile:marker atomically:YES]) return 2;
        } else if ([action isEqualToString:@"serve"]) {
            [NSApplication sharedApplication];
            ProbeReceiver *receiver = [ProbeReceiver new];
            [NSAppleEventManager.sharedAppleEventManager setEventHandler:receiver
                andSelector:@selector(receive:reply:) forEventClass:kCoreEventClass
                andEventID:kAEOpenApplication];
            [NSApp finishLaunching];
            NSString *ready = [bundle objectForInfoDictionaryKey:@"ProbeReady"];
            if (![@"ready" writeToFile:ready atomically:YES encoding:NSUTF8StringEncoding error:NULL]) return 2;
            [NSApp run];
        } else if ([action isEqualToString:@"open"]) {
            if (argc != 3) return 2;
            FSRef ref;
            OSStatus status = FSPathMakeRef((const UInt8 *)argv[2], &ref, NULL);
            if (status == noErr) status = LSOpenFSRef(&ref, NULL);
            result[@"status"] = @(status);
        } else if ([action isEqualToString:@"appleevent"]) {
            if (argc != 3) return 2;
            /* Address only the owned application. No Finder/System Events script. */
            int pid = atoi(argv[2]);
            if (pid <= 0) return 2;
            NSAppleEventDescriptor *target = [NSAppleEventDescriptor descriptorWithProcessIdentifier:pid];
            mach_port_t port = MACH_PORT_NULL;
            kern_return_t lookup = bootstrap_look_up(bootstrap_port, "com.apple.coreservices.appleevents", &port);
            result[@"appleevents_lookup"] = @(lookup);
            if (lookup == KERN_SUCCESS) mach_port_deallocate(mach_task_self(), port);
            NSAppleEventDescriptor *event = [NSAppleEventDescriptor
                appleEventWithEventClass:kCoreEventClass eventID:kAEOpenApplication
                targetDescriptor:target returnID:kAutoGenerateReturnID
                transactionID:kAnyTransactionID];
            NSError *error = nil;
            NSAppleEventDescriptor *reply = [event sendEventWithOptions:kAEWaitReply
                timeout:3 error:&error];
            result[@"sent"] = @(reply != nil);
            result[@"error"] = error_info(error);
        } else {
            if (argc != 3) return 2;
            NSString *kind = @(argv[2]);
            SMAppService *service;
            if ([kind isEqualToString:@"login"])
                service = [SMAppService loginItemServiceWithIdentifier:
                    [bundle.bundleIdentifier stringByAppendingString:@".login"]];
            else if ([kind isEqualToString:@"agent"])
                service = [SMAppService agentServiceWithPlistName:@"probe-agent.plist"];
            else if ([kind isEqualToString:@"daemon"])
                service = [SMAppService daemonServiceWithPlistName:@"probe-daemon.plist"];
            else return 2;
            result[@"kind"] = kind;
            mach_port_t port = MACH_PORT_NULL;
            kern_return_t lookup = bootstrap_look_up(bootstrap_port, "com.apple.xpc.smd", &port);
            result[@"smd_lookup"] = @(lookup);
            if (lookup == KERN_SUCCESS) mach_port_deallocate(mach_task_self(), port);
            result[@"before"] = @(service.status);
            NSError *error = nil;
            if ([action isEqualToString:@"register"])
                result[@"registered"] = @([service registerAndReturnError:&error]);
            else if ([action isEqualToString:@"unregister"])
                result[@"unregistered"] = @([service unregisterAndReturnError:&error]);
            else if (![action isEqualToString:@"status"]) return 2;
            result[@"after"] = @(service.status);
            result[@"error"] = error_info(error);
        }
        NSData *data = [NSJSONSerialization dataWithJSONObject:result options:0 error:NULL];
        puts([[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding].UTF8String);
    }
    return 0;
}
