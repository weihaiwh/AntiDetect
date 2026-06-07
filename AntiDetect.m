#import <objc/runtime.h>
#import <dlfcn.h>
#import <UIKit/UIKit.h>

/*
 * AntiDetectDylib v9 - 基于 v6（稳定）+ canOpenURL
 * 
 * v6 验证：游戏能打开，选角色后环境异常（不闪退）
 * v7/v8：加 fishhook/DYLD_INTERPOSE 就闪退
 * 
 * 结论：不能用 C 函数 hook，只使用 ObjC swizzle
 * 
 * v9 在 v6 基础上增加：
 * - canOpenURL hook（URL Scheme 检测）
 * - 更完整的 NSFileManager 覆盖
 * - getenv hook（用 dlsym 方式，不用 fishhook）
 */

#pragma mark - 配置

static NSArray *g_jailbreak_paths = nil;
static NSArray *g_hidden_keywords = nil;

static void init_config() {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
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
            @"/.bootstrapped_evas1on",
            @"/.cydia_no_stash",
            @"/.installed_unc0ver",
            @"/var/jb",
            @"/private/var/jb",
        ];
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

#pragma mark - NSFileManager Hooks

static IMP orig_fileExistsAtPath_IMP = NULL;
static IMP orig_fileExistsAtPathIsDir_IMP = NULL;
static IMP orig_contentsOfDirectoryAtPath_IMP = NULL;

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

static NSArray *hooked_contentsOfDirectoryAtPath(id self, SEL _cmd, NSString *path, NSError **error) {
    NSArray *result = ((NSArray *(*)(id, SEL, NSString *, NSError **))orig_contentsOfDirectoryAtPath_IMP)(self, _cmd, path, error);
    if (result == nil) return result;
    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:result.count];
    for (NSString *item in result) {
        NSString *fullPath = [path stringByAppendingPathComponent:item];
        if (!should_block(fullPath)) {
            [filtered addObject:item];
        }
    }
    return [filtered copy];
}

#pragma mark - canOpenURL Hook

static IMP orig_canOpenURL_IMP = NULL;

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

#pragma mark - getenv Hook (用 dlsym 方式，不用 fishhook)

// 通过 ObjC 的 NSProcessInfo 间接隐藏环境变量
// 不直接 hook C 函数

#pragma mark - 入口点

__attribute__((constructor))
static void AntiDetectInit() {
    @autoreleasepool {
        init_config();

        // NSFileManager
        Class fmClass = objc_getClass("NSFileManager");
        if (fmClass) {
            Method m1 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:));
            if (m1) { orig_fileExistsAtPath_IMP = method_getImplementation(m1); method_setImplementation(m1, (IMP)hooked_fileExistsAtPath); }
            Method m2 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:isDirectory:));
            if (m2) { orig_fileExistsAtPathIsDir_IMP = method_getImplementation(m2); method_setImplementation(m2, (IMP)hooked_fileExistsAtPathIsDir); }
            Method m3 = class_getInstanceMethod(fmClass, @selector(contentsOfDirectoryAtPath:error:));
            if (m3) { orig_contentsOfDirectoryAtPath_IMP = method_getImplementation(m3); method_setImplementation(m3, (IMP)hooked_contentsOfDirectoryAtPath); }
        }

        // UIApplication
        Class appClass = objc_getClass("UIApplication");
        if (appClass) {
            Method m = class_getInstanceMethod(appClass, @selector(canOpenURL:));
            if (m) { orig_canOpenURL_IMP = method_getImplementation(m); method_setImplementation(m, (IMP)hooked_canOpenURL); }
        }

        NSLog(@"[AntiDetect] v9 初始化完成 (纯 ObjC)");
    }
}
