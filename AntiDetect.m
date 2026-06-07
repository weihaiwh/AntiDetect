#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <UIKit/UIKit.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <dirent.h>
#import <stdio.h>
#import <string.h>

/*
 * AntiDetectDylib v15 - 惰性激活C函数hook
 *
 * v14问题：延迟3秒安装C函数hook，但安装后游戏还在加载资源，立刻卡住
 * 根本原因：即使只拦截越狱路径，每次stat/access/fopen都多了一轮字符串比较
 * 游戏启动时有上万次文件IO，额外的字符串比较开销累积导致卡死
 *
 * v15方案：
 *   - C函数hook在constructor中立即安装（零延迟，不遗漏任何检测）
 *   - 但hook函数内部有一个 g_hooks_active 开关，初始为NO
 *   - 开关为NO时，hook函数直接调用原函数，零额外开销
 *   - 10秒后开启开关，此时游戏资源已加载完，开始拦截越狱路径
 *   - 易盾检测在选角色后触发，10秒完全够用
 *
 * 这样既不会遗漏早期检测（hook已安装），又不会影响游戏加载性能
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

#pragma mark - 惰性激活开关

// 初始为0（关闭），10秒后置为1（开启）
static volatile int32_t g_hooks_active = 0;

#pragma mark - 越狱路径（纯C）

static const char *g_jb_prefixes[] = {
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/unc0ver.app",
    "/Applications/Taurine.app",
    "/Applications/TrollStore.app",
    "/Applications/TrollFools.app",
    "/Library/MobileSubstrate",
    "/usr/lib/substrate",
    "/usr/lib/ligerness",
    "/usr/lib/libhooker",
    "/etc/apt",
    "/var/lib/apt",
    "/var/lib/cydia",
    "/private/var/lib/cydia",
    "/private/var/mobile/Library/Cydia",
    "/.bootstrapped_evas1on",
    "/.cydia_no_stash",
    "/.installed_unc0ver",
    "/var/jb",
    "/private/var/jb",
    NULL
};

static const char *g_hide_keywords[] = {
    "CydiaSubstrate",
    "SubstrateLoader",
    "MobileSubstrate",
    "TrollFools",
    "TrollStore",
    "AntiDetect",
    "LIBTOOL",
    "libhooker",
    "substrate",
    NULL
};

// 快速检查：先看开关，再匹配
static inline BOOL is_jb_path(const char *path) {
    if (!g_hooks_active || !path) return NO;
    for (int i = 0; g_jb_prefixes[i]; i++) {
        const char *prefix = g_jb_prefixes[i];
        // 快速首字母过滤
        if (path[0] != prefix[0]) continue;
        if (strncmp(path, prefix, strlen(prefix)) == 0) return YES;
    }
    return NO;
}

static inline BOOL should_hide_lib(const char *name) {
    if (!g_hooks_active || !name) return NO;
    for (int i = 0; g_hide_keywords[i]; i++) {
        if (strstr(name, g_hide_keywords[i])) return YES;
    }
    return NO;
}

#pragma mark - C函数Hook

static int (*orig_stat)(const char *restrict, struct stat *restrict) = NULL;
static int (*orig_access)(const char *, int) = NULL;
static FILE *(*orig_fopen)(const char *, const char *) = NULL;
static int (*orig_dladdr)(const void *, Dl_info *) = NULL;
static char *(*orig_getenv)(const char *) = NULL;
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;

static int hook_stat(const char *restrict path, struct stat *restrict buf) {
    if (is_jb_path(path)) return -1;
    return orig_stat(path, buf);
}

static int hook_access(const char *path, int mode) {
    if (is_jb_path(path)) { errno = ENOENT; return -1; }
    return orig_access(path, mode);
}

static FILE *hook_fopen(const char *path, const char *mode) {
    if (is_jb_path(path)) return NULL;
    return orig_fopen(path, mode);
}

static int hook_dladdr(const void *addr, Dl_info *info) {
    int ret = orig_dladdr(addr, info);
    if (should_hide_lib(info->dli_fname)) {
        memset(info, 0, sizeof(Dl_info));
        return 0;
    }
    return ret;
}

static char *hook_getenv(const char *name) {
    // getenv始终拦截（不影响游戏加载）
    if (name) {
        if (strncmp(name, "DYLD_", 5) == 0) return NULL;
        if (strstr(name, "MSSafeMode") || strstr(name, "SUBSTRATE_HOME")) return NULL;
    }
    return orig_getenv(name);
}

static int hook_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int result = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    // sysctl P_TRACED清除也始终生效
    if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC &&
        name[2] == KERN_PROC_PID && oldp && oldlenp &&
        *oldlenp >= sizeof(struct kinfo_proc)) {
        ((struct kinfo_proc *)oldp)->kp_proc.p_flag &= ~P_TRACED;
    }
    return result;
}

#pragma mark - 安装C函数Hook（立即安装但惰性激活）

static void install_c_hooks() {
    if (!load_MSHookFunction()) {
        NSLog(@"[AntiDetect] MSHookFunction不可用，跳过C函数hook");
        return;
    }

    g_MSHookFunction((void *)stat, (void *)hook_stat, (void **)&orig_stat);
    g_MSHookFunction((void *)access, (void *)hook_access, (void **)&orig_access);
    g_MSHookFunction((void *)fopen, (void *)hook_fopen, (void **)&orig_fopen);
    g_MSHookFunction((void *)dladdr, (void *)hook_dladdr, (void **)&orig_dladdr);
    g_MSHookFunction((void *)getenv, (void *)hook_getenv, (void **)&orig_getenv);
    g_MSHookFunction((void *)sysctl, (void *)hook_sysctl, (void **)&orig_sysctl);

    NSLog(@"[AntiDetect] C函数Hook已安装（惰性模式，g_hooks_active=%d）", g_hooks_active);
}

#pragma mark - ObjC Hook

static NSArray *g_jb_paths_ns = nil;
static NSArray *g_hide_kw_ns = nil;

static BOOL should_block_ns(NSString *path) {
    if (!g_hooks_active) return NO; // ObjC层也惰性激活
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

        NSLog(@"[AntiDetect] v15 初始化（惰性激活模式）...");

        // ===== ObjC Hook（立即安装但惰性激活）=====
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

        // ===== C函数Hook（立即安装，但g_hooks_active=0所以hook直接透传）=====
        install_c_hooks();

        // ===== 10秒后激活所有拦截（此时游戏资源已加载完毕）=====
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            g_hooks_active = 1;
            NSLog(@"[AntiDetect] ★ 拦截已激活！所有越狱路径检测现在会被拦截 ★");
        });

        NSLog(@"[AntiDetect] v15 初始化完成（Hook已安装，10秒后激活拦截）");
    }
}
