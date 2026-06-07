#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <UIKit/UIKit.h>

/*
 * AntiDetectDylib v5 - 最小化保守版本
 * 只 hook NSFileManager 的文件检查方法
 * 不 hook 其他任何东西
 * 
 * ⚠️ 此 dylib 必须是注入列表中【最后一个】加载的
 */

#pragma mark - 越狱路径 & 隐藏关键字

static NSArray *g_jailbreak_paths = nil;
static NSArray *g_hidden_keywords = nil;

static void init_config() {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        g_hidden_keywords = @[
            @"AntiDetect",
            @"LIBTOOL",
            @"CydiaSubstrate",
            @"TrollFools",
            @"TrollStore",
            @"substrate",
            @"SubstrateLoader",
            @"MobileSubstrate",
            @"libhooker",
        ];
    });
}

static BOOL is_jailbreak_path(NSString *path) {
    if (!path || path.length == 0) return NO;
    for (NSString *jp in g_jailbreak_paths) {
        if ([path hasPrefix:jp]) return YES;
    }
    return NO;
}

static BOOL contains_hidden_keyword(NSString *path) {
    if (!path || path.length == 0) return NO;
    NSString *lower = path.lowercaseString;
    for (NSString *kw in g_hidden_keywords) {
        if ([lower containsString:kw.lowercaseString]) return YES;
    }
    return NO;
}

static BOOL should_block(NSString *path) {
    return is_jailbreak_path(path) || contains_hidden_keyword(path);
}

#pragma mark - NSFileManager Hooks (只 hook 读取类方法，不动写入)

static IMP orig_fileExistsAtPath_IMP = NULL;
static IMP orig_fileExistsAtPathIsDir_IMP = NULL;

static BOOL hooked_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (should_block(path)) return NO;
    return ((BOOL(*)(id, SEL, NSString *))orig_fileExistsAtPath_IMP)(self, _cmd, path);
}

static BOOL hooked_fileExistsAtPathIsDir(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (should_block(path)) {
        if (isDir) *isDir = NO;
        return NO;
    }
    return ((BOOL(*)(id, SEL, NSString *, BOOL *))orig_fileExistsAtPathIsDir_IMP)(self, _cmd, path, isDir);
}

#pragma mark - 入口点

__attribute__((constructor))
static void AntiDetectInit() {
    @autoreleasepool {
        init_config();

        g_jailbreak_paths = @[
            @"/Applications/Cydia.app",
            @"/Applications/Sileo.app",
            @"/Applications/Zebra.app",
            @"/Applications/unc0ver.app",
            @"/Applications/Taurine.app",
            @"/Applications/TrollStore.app",
            @"/Applications/TrollFools.app",
            @"/Library/MobileSubstrate",
            @"/usr/lib/substrate",
            @"/usr/lib/ligerness",
            @"/usr/lib/libhooker",
            @"/etc/apt",
            @"/var/lib/apt",
            @"/var/lib/cydia",
            @"/private/var/lib/cydia",
            @"/private/var/mobile/Library/Cydia",
            @"/usr/sbin/sshd",
            @"/usr/bin/sshd",
            @"/bin/bash",
            @"/bin/sh",
            @"/usr/bin/ssh",
            @"/.bootstrapped_evas1on",
            @"/.cydia_no_stash",
            @"/.installed_unc0ver",
            @"/var/jb",
            @"/private/var/jb",
            @"/var/containers/Bundle/Application/",
            @"/var/mobile/Containers/Data/Application/",
        ];

        // 只 hook NSFileManager 的两个文件检查方法
        Class fmClass = objc_getClass("NSFileManager");
        if (fmClass) {
            Method m1 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:));
            if (m1) {
                orig_fileExistsAtPath_IMP = method_getImplementation(m1);
                method_setImplementation(m1, (IMP)hooked_fileExistsAtPath);
            }
            Method m2 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:isDirectory:));
            if (m2) {
                orig_fileExistsAtPathIsDir_IMP = method_getImplementation(m2);
                method_setImplementation(m2, (IMP)hooked_fileExistsAtPathIsDir);
            }
        }

        NSLog(@"[AntiDetect] v5 最小版初始化完成");
    }
}
