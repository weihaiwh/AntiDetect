#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <UIKit/UIKit.h>

/*
 * AntiDetectDylib v4 - 纯 ObjC 实现，无 fishhook，无 C 函数 hook
 * 已预配置：TrollFools + LIBTOOL + CydiaSubstrate 环境
 * ⚠️ 此 dylib 必须是注入列表中【最后一个】加载的
 * 
 * 只使用 ObjC method swizzling，不 hook 任何 C 函数
 * 这是最稳定的方式，不可能闪退
 */

#pragma mark - 配置

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
    if (!path) return NO;
    if (path.length == 0) return NO;
    for (NSString *jp in g_jailbreak_paths) {
        if ([path hasPrefix:jp]) return YES;
    }
    return NO;
}

static BOOL contains_hidden_keyword(NSString *path) {
    if (!path) return NO;
    NSString *lower = path.lowercaseString;
    for (NSString *kw in g_hidden_keywords) {
        if ([lower containsString:kw.lowercaseString]) return YES;
    }
    return NO;
}

#pragma mark - NSFileManager Hook

static IMP orig_fileExistsAtPath_IMP = NULL;
static IMP orig_fileExistsAtPathIsDirectory_IMP = NULL;
static IMP orig_contentsOfDirectoryAtPath_IMP = NULL;
static IMP orig_subpathsAtPath_IMP = NULL;
static IMP orig_createFileAtPath_IMP = NULL;
static IMP orig_removeItemAtPath_IMP = NULL;
static IMP orig_moveItemAtPath_IMP = NULL;
static IMP orig_copyItemAtPath_IMP = NULL;

static BOOL hooked_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (is_jailbreak_path(path) || contains_hidden_keyword(path)) return NO;
    return ((BOOL(*)(id, SEL, NSString *))orig_fileExistsAtPath_IMP)(self, _cmd, path);
}

static BOOL hooked_fileExistsAtPathIsDirectory(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (is_jailbreak_path(path) || contains_hidden_keyword(path)) {
        if (isDir) *isDir = NO;
        return NO;
    }
    return ((BOOL(*)(id, SEL, NSString *, BOOL *))orig_fileExistsAtPathIsDirectory_IMP)(self, _cmd, path, isDir);
}

static NSArray *hooked_contentsOfDirectoryAtPath(id self, SEL _cmd, NSString *path, NSError **error) {
    NSArray *result = ((NSArray *(*)(id, SEL, NSString *, NSError **))orig_contentsOfDirectoryAtPath_IMP)(self, _cmd, path, error);
    if (result == nil) return result;
    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:result.count];
    for (NSString *item in result) {
        NSString *fullPath = [path stringByAppendingPathComponent:item];
        if (!is_jailbreak_path(fullPath) && !contains_hidden_keyword(fullPath)) {
            [filtered addObject:item];
        }
    }
    return [filtered copy];
}

static NSArray *hooked_subpathsAtPath(id self, SEL _cmd, NSString *path) {
    if (is_jailbreak_path(path) || contains_hidden_keyword(path)) return nil;
    NSArray *result = ((NSArray *(*)(id, SEL, NSString *))orig_subpathsAtPath_IMP)(self, _cmd, path);
    if (result == nil) return nil;
    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:result.count];
    for (NSString *item in result) {
        if (!is_jailbreak_path(item) && !contains_hidden_keyword(item)) {
            [filtered addObject:item];
        }
    }
    return [filtered copy];
}

static BOOL hooked_createFileAtPath(id self, SEL _cmd, NSString *path, NSData *data, NSDictionary *attr) {
    if (is_jailbreak_path(path) || contains_hidden_keyword(path)) return NO;
    return ((BOOL(*)(id, SEL, NSString *, NSData *, NSDictionary *))orig_createFileAtPath_IMP)(self, _cmd, path, data, attr);
}

static BOOL hooked_removeItemAtPath(id self, SEL _cmd, NSString *path, NSError **error) {
    if (is_jailbreak_path(path) || contains_hidden_keyword(path)) return NO;
    return ((BOOL(*)(id, SEL, NSString *, NSError **))orig_removeItemAtPath_IMP)(self, _cmd, path, error);
}

static BOOL hooked_moveItemAtPath(id self, SEL _cmd, NSString *srcPath, NSString *dstPath, NSError **error) {
    if (is_jailbreak_path(srcPath) || contains_hidden_keyword(srcPath)) return NO;
    return ((BOOL(*)(id, SEL, NSString *, NSString *, NSError **))orig_moveItemAtPath_IMP)(self, _cmd, srcPath, dstPath, error);
}

static BOOL hooked_copyItemAtPath(id self, SEL _cmd, NSString *srcPath, NSString *dstPath, NSError **error) {
    if (is_jailbreak_path(srcPath) || contains_hidden_keyword(srcPath)) return NO;
    return ((BOOL(*)(id, SEL, NSString *, NSString *, NSError **))orig_copyItemAtPath_IMP)(self, _cmd, srcPath, dstPath, error);
}

#pragma mark - UIApplication Hook

static IMP orig_canOpenURL_IMP = NULL;
static IMP orig_openURL_IMP = NULL;

static BOOL hooked_canOpenURL(id self, SEL _cmd, NSURL *url) {
    if (url) {
        NSString *scheme = [url scheme];
        NSArray *blocked = @[@"cydia", @"sileo", @"zebra", @"unc0ver", @"taurine"];
        for (NSString *bs in blocked) {
            if ([scheme isEqualToString:bs]) return NO;
        }
        NSString *absolute = [url absoluteString];
        if (contains_hidden_keyword(absolute)) return NO;
    }
    return ((BOOL(*)(id, SEL, NSURL *))orig_canOpenURL_IMP)(self, _cmd, url);
}

static BOOL hooked_openURL(id self, SEL _cmd, NSURL *url) {
    if (url) {
        NSString *scheme = [url scheme];
        NSArray *blocked = @[@"cydia", @"sileo", @"zebra", @"unc0ver", @"taurine"];
        for (NSString *bs in blocked) {
            if ([scheme isEqualToString:bs]) return NO;
        }
    }
    return ((BOOL(*)(id, SEL, NSURL *))orig_openURL_IMP)(self, _cmd, url);
}

#pragma mark - NSBundle Hook (隐藏注入的 bundle)

static IMP orig_bundlePath_IMP = NULL;
static IMP orig_executablePath_IMP = NULL;
static IMP orig_infoDictionary_IMP = NULL;

static NSString *hooked_bundlePath(id self, SEL _cmd) {
    NSString *path = ((NSString *(*)(id, SEL))orig_bundlePath_IMP)(self, _cmd);
    if (path && contains_hidden_keyword(path)) return @"/System/Library/Frameworks/Foundation.framework";
    return path;
}

static NSString *hooked_executablePath(id self, SEL _cmd) {
    NSString *path = ((NSString *(*)(id, SEL))orig_executablePath_IMP)(self, _cmd);
    if (path && contains_hidden_keyword(path)) return @"/usr/lib/system/libsystem_c.dylib";
    return path;
}

#pragma mark - Swizzle 辅助

static void swizzle_instance(Class cls, SEL sel, IMP new_imp, IMP *orig_imp) {
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    *orig_imp = method_getImplementation(m);
    method_setImplementation(m, new_imp);
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

        // Hook NSFileManager
        Class fmClass = objc_getClass("NSFileManager");
        if (fmClass) {
            swizzle_instance(fmClass, @selector(fileExistsAtPath:), (IMP)hooked_fileExistsAtPath, &orig_fileExistsAtPath_IMP);
            swizzle_instance(fmClass, @selector(fileExistsAtPath:isDirectory:), (IMP)hooked_fileExistsAtPathIsDirectory, &orig_fileExistsAtPathIsDirectory_IMP);
            swizzle_instance(fmClass, @selector(contentsOfDirectoryAtPath:error:), (IMP)hooked_contentsOfDirectoryAtPath, &orig_contentsOfDirectoryAtPath_IMP);
            swizzle_instance(fmClass, @selector(subpathsAtPath:), (IMP)hooked_subpathsAtPath, &orig_subpathsAtPath_IMP);
            swizzle_instance(fmClass, @selector(createFileAtPath:contents:attributes:), (IMP)hooked_createFileAtPath, &orig_createFileAtPath_IMP);
            swizzle_instance(fmClass, @selector(removeItemAtPath:error:), (IMP)hooked_removeItemAtPath, &orig_removeItemAtPath_IMP);
            swizzle_instance(fmClass, @selector(moveItemAtPath:toPath:error:), (IMP)hooked_moveItemAtPath, &orig_moveItemAtPath_IMP);
            swizzle_instance(fmClass, @selector(copyItemAtPath:toPath:error:), (IMP)hooked_copyItemAtPath, &orig_copyItemAtPath_IMP);
        }

        // Hook UIApplication
        Class appClass = objc_getClass("UIApplication");
        if (appClass) {
            swizzle_instance(appClass, @selector(canOpenURL:), (IMP)hooked_canOpenURL, &orig_canOpenURL_IMP);
            swizzle_instance(appClass, @selector(openURL:), (IMP)hooked_openURL, &orig_openURL_IMP);
        }

        // Hook NSBundle (隐藏注入 bundle 信息)
        Class bundleClass = objc_getClass("NSBundle");
        if (bundleClass) {
            swizzle_instance(bundleClass, @selector(bundlePath), (IMP)hooked_bundlePath, &orig_bundlePath_IMP);
            swizzle_instance(bundleClass, @selector(executablePath), (IMP)hooked_executablePath, &orig_executablePath_IMP);
        }

        NSLog(@"[AntiDetect] v4 纯ObjC版初始化完成");
    }
}
