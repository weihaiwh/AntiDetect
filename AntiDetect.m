#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <UIKit/UIKit.h>
#import <string.h>

/*
 * AntiDetectDylib v19 - 仅dladdr隐藏版
 *
 * v18卡住原因：hook了_dyld_get_image_name返回空字符串
 *   → 游戏遍历image列表时index错位/空名 → 死循环/卡死
 *   → 这个函数不能hook！它影响整个image枚举逻辑
 *
 * v19策略：只hook dladdr，不碰_dyld_get_image_name
 *   - dladdr只查询特定地址的dylib信息，不影响枚举
 *   - 隐藏方式：将注入dylib的地址映射伪装为游戏主程序
 *   - 不返回空/0（会导致崩溃），而是替换为游戏自身路径
 *
 * 完全不hook的函数（避免卡顿/闪退）：
 *   _dyld_get_image_name, stat, access, fopen, opendir,
 *   getenv, sysctl, lstat, dlopen, dlsym
 */

#pragma mark - CydiaSubstrate

typedef void (*MSHookFunction_t)(void *symbol, void *replace, void **result);
static MSHookFunction_t g_MSHookFunction = NULL;

static BOOL load_MSHookFunction() {
    if (g_MSHookFunction) return YES;
    g_MSHookFunction = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (g_MSHookFunction) return YES;
    void *h = dlopen("@executable_path/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_LAZY);
    if (!h) h = dlopen("/usr/lib/libsubstrate.dylib", RTLD_LAZY);
    if (h) g_MSHookFunction = (MSHookFunction_t)dlsym(h, "MSHookFunction");
    return (g_MSHookFunction != NULL);
}

#pragma mark - 需要隐藏的dylib关键词

static const char *g_hide_dylib_kw[] = {
    "CydiaSubstrate",
    "SubstrateLoader",
    "MobileSubstrate",
    "TrollFools",
    "TrollStore",
    "AntiDetect",
    "LIBTOOL",
    "libhooker",
    NULL
};

static inline BOOL should_hide_dylib(const char *name) {
    if (!name) return NO;
    for (int i = 0; g_hide_dylib_kw[i]; i++) {
        if (strstr(name, g_hide_dylib_kw[i])) return YES;
    }
    return NO;
}

#pragma mark - dladdr Hook（唯一需要的C函数hook）

static int (*orig_dladdr)(const void *, Dl_info *) = NULL;

// 缓存游戏主程序的路径，避免每次调用都查询
static char g_main_exec_path[1024] = {0};
static void *g_main_exec_base = NULL;

static void cache_main_exec_info() {
    // 获取主程序路径和基地址
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "Application/") && !strstr(name, "Framework") && !strstr(name, "dylib")) {
            // 这是主程序的路径（在Application目录下但不是Framework/dylib）
            strncpy(g_main_exec_path, name, sizeof(g_main_exec_path) - 1);
            g_main_exec_base = (void *)_dyld_get_image_header(i);
            break;
        }
    }
    if (g_main_exec_path[0] == '\0') {
        // 回退：用第一个image
        const char *name = _dyld_get_image_name(0);
        if (name) strncpy(g_main_exec_path, name, sizeof(g_main_exec_path) - 1);
        g_main_exec_base = (void *)_dyld_get_image_header(0);
    }
}

static int hook_dladdr(const void *addr, Dl_info *info) {
    int ret = orig_dladdr(addr, info);
    if (ret && info && info->dli_fname && should_hide_dylib(info->dli_fname)) {
        // 关键：不清空info！把注入dylib的信息伪装成游戏主程序
        // 这样易盾查到的地址都属于"游戏本身"，不会发现注入
        if (g_main_exec_path[0]) {
            info->dli_fname = g_main_exec_path;
        }
        if (g_main_exec_base) {
            info->dli_saddr = g_main_exec_base;
        }
        info->dli_sname = NULL; // 清除符号名
    }
    return ret;
}

#pragma mark - ObjC Hook

static NSArray *g_jb_paths_ns = nil;
static NSArray *g_hide_kw_ns = nil;

static BOOL should_block_ns(NSString *path) {
    if (!path || path.length == 0) return NO;
    for (NSString *jp in g_jb_paths_ns) {
        if ([path hasPrefix:jp]) return YES;
    }
    NSString *lower = path.lowercaseString;
    for (NSString *kw in g_hide_kw_ns) {
        if ([lower containsString:kw.lowercaseString]) return YES;
    }
    return NO;
}

static IMP orig_fileExistsAtPath_IMP = NULL;
static IMP orig_fileExistsAtPathIsDir_IMP = NULL;
static IMP orig_contentsOfDirectoryAtPath_IMP = NULL;
static IMP orig_canOpenURL_IMP = NULL;
static IMP orig_presentViewController_IMP = NULL;

static BOOL hooked_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (should_block_ns(path)) return NO;
    return ((BOOL(*)(id, SEL, NSString *))orig_fileExistsAtPath_IMP)(self, _cmd, path);
}

static BOOL hooked_fileExistsAtPathIsDir(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (should_block_ns(path)) { if (isDir) *isDir = NO; return NO; }
    return ((BOOL(*)(id, SEL, NSString *, BOOL *))orig_fileExistsAtPathIsDir_IMP)(self, _cmd, path, isDir);
}

static NSArray *hooked_contentsOfDirectoryAtPath(id self, SEL _cmd, NSString *path, NSError **error) {
    NSArray *result = ((NSArray *(*)(id, SEL, NSString *, NSError **))orig_contentsOfDirectoryAtPath_IMP)(self, _cmd, path, error);
    if (!result) return result;
    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:result.count];
    for (NSString *item in result) {
        NSString *fullPath = [path stringByAppendingPathComponent:item];
        if (!should_block_ns(fullPath)) [filtered addObject:item];
    }
    return [filtered copy];
}

static BOOL hooked_canOpenURL(id self, SEL _cmd, NSURL *url) {
    if (url) {
        NSString *scheme = [url scheme];
        NSArray *blocked = @[@"cydia", @"sileo", @"zebra", @"unc0ver", @"taurine"];
        for (NSString *bs in blocked) {
            if ([scheme isEqualToString:bs]) return NO;
        }
    }
    return ((BOOL(*)(id, SEL, NSURL *))orig_canOpenURL_IMP)(self, _cmd, url);
}

static void hooked_presentViewController(id self, SEL _cmd, UIViewController *vc, BOOL animated, id completion) {
    if ([vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *alert = (UIAlertController *)vc;
        NSString *combined = [NSString stringWithFormat:@"%@%@", alert.title ?: @"", alert.message ?: @""];
        if ([combined containsString:@"环境异常"] || [combined containsString:@"800180933"] || [combined containsString:@"QQ公众号"]) {
            NSLog(@"[AntiDetect] 拦截弹窗");
            return;
        }
    }
    ((void(*)(id, SEL, UIViewController *, BOOL, id))orig_presentViewController_IMP)(self, _cmd, vc, animated, completion);
}

#pragma mark - NSUserDefaults清理

static void clean_anticheat_defaults() {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSDictionary *dict = [defaults dictionaryRepresentation];
    NSMutableArray *remove = [NSMutableArray array];
    for (NSString *key in dict) {
        NSString *lower = key.lowercaseString;
        if ([lower containsString:@"htp"] || [lower containsString:@"ntes"] ||
            [lower containsString:@"anticheat"] || [lower containsString:@"risksec"])
            [remove addObject:key];
    }
    for (NSString *key in remove) [defaults removeObjectForKey:key];
    if (remove.count > 0) [defaults synchronize];
}

#pragma mark - 入口点

__attribute__((constructor))
static void AntiDetectInit() {
    @autoreleasepool {
        g_jb_paths_ns = @[
            @"/Applications/Cydia.app", @"/Applications/Sileo.app",
            @"/Applications/Zebra.app", @"/Applications/unc0ver.app",
            @"/Applications/Taurine.app", @"/Applications/TrollStore.app",
            @"/Applications/TrollFools.app", @"/Library/MobileSubstrate",
            @"/usr/lib/substrate", @"/usr/lib/ligerness",
            @"/usr/lib/libhooker", @"/etc/apt", @"/var/lib/apt",
            @"/var/lib/cydia", @"/private/var/lib/cydia",
            @"/private/var/mobile/Library/Cydia", @"/.bootstrapped_evas1on",
            @"/.cydia_no_stash", @"/.installed_unc0ver",
            @"/var/jb", @"/private/var/jb",
        ];
        g_hide_kw_ns = @[
            @"AntiDetect", @"LIBTOOL", @"CydiaSubstrate",
            @"TrollFools", @"TrollStore", @"substrate",
            @"SubstrateLoader", @"MobileSubstrate", @"libhooker",
        ];

        NSLog(@"[AntiDetect] v19 初始化...");

        // 缓存游戏主程序信息（constructor中可用，不需要hook）
        cache_main_exec_info();
        NSLog(@"[AntiDetect] 主程序路径: %s", g_main_exec_path);

        // ===== ObjC Hook（constructor中立即执行，稳定）=====
        Class fmClass = objc_getClass("NSFileManager");
        if (fmClass) {
            Method m1 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:));
            if (m1) { orig_fileExistsAtPath_IMP = method_getImplementation(m1); method_setImplementation(m1, (IMP)hooked_fileExistsAtPath); }
            Method m2 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:isDirectory:));
            if (m2) { orig_fileExistsAtPathIsDir_IMP = method_getImplementation(m2); method_setImplementation(m2, (IMP)hooked_fileExistsAtPathIsDir); }
            Method m3 = class_getInstanceMethod(fmClass, @selector(contentsOfDirectoryAtPath:error:));
            if (m3) { orig_contentsOfDirectoryAtPath_IMP = method_getImplementation(m3); method_setImplementation(m3, (IMP)hooked_contentsOfDirectoryAtPath); }
        }

        Class appClass = objc_getClass("UIApplication");
        if (appClass) {
            Method m = class_getInstanceMethod(appClass, @selector(canOpenURL:));
            if (m) { orig_canOpenURL_IMP = method_getImplementation(m); method_setImplementation(m, (IMP)hooked_canOpenURL); }
        }

        Class vcClass = objc_getClass("UIViewController");
        if (vcClass) {
            Method m = class_getInstanceMethod(vcClass, @selector(presentViewController:animated:completion:));
            if (m) { orig_presentViewController_IMP = method_getImplementation(m); method_setImplementation(m, (IMP)hooked_presentViewController); }
        }

        clean_anticheat_defaults();

        // ===== dladdr Hook（延迟1秒，唯一需要的C函数hook）=====
        // 不hook: _dyld_get_image_name(会卡死), stat/access/fopen(会卡顿)
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            if (load_MSHookFunction()) {
                g_MSHookFunction((void *)dladdr, (void *)hook_dladdr, (void **)&orig_dladdr);
                NSLog(@"[AntiDetect] ★ dladdr hook安装完成 ★");
            } else {
                NSLog(@"[AntiDetect] MSHookFunction不可用");
            }
        });

        NSLog(@"[AntiDetect] v19 ObjC完成，+1s安装dladdr hook");
    }
}
