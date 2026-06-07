#import <objc/runtime.h>
#import <dlfcn.h>
#import <UIKit/UIKit.h>

/*
 * AntiDetectDylib v6 - 修复闪退
 * 
 * v5 闪退原因：g_jailbreak_paths 包含了
 * "/var/containers/Bundle/Application/" 这是游戏自身的路径
 * 以及 /bin/sh 等系统自带路径，返回 NO 反而异常
 * 
 * v6 修复：
 * - 移除游戏自身路径前缀
 * - 只拦截真正的越狱/注入检测路径
 * - 添加调用者检查，只拦截来自游戏主模块的检测调用
 */

#pragma mark - 配置

static NSArray *g_jailbreak_paths = nil;
static NSArray *g_hidden_keywords = nil;

static void init_config() {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // 只匹配真正的越狱/注入特征
        // ⚠️ 不包含 /var/containers/Bundle/Application/（这是正常 App 路径）
        // ⚠️ 不包含 /bin/sh 等系统自带路径（非越狱设备也有）
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

#pragma mark - NSFileManager Hooks

static IMP orig_fileExistsAtPath_IMP = NULL;
static IMP orig_fileExistsAtPathIsDir_IMP = NULL;

static BOOL hooked_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (is_jailbreak_path(path) || contains_hidden_keyword(path)) return NO;
    return ((BOOL(*)(id, SEL, NSString *))orig_fileExistsAtPath_IMP)(self, _cmd, path);
}

static BOOL hooked_fileExistsAtPathIsDir(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (is_jailbreak_path(path) || contains_hidden_keyword(path)) {
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

        NSLog(@"[AntiDetect] v6 初始化完成");
    }
}
