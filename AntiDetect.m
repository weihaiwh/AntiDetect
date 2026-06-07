#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <UIKit/UIKit.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <dirent.h>
#import <stdio.h>

/*
 * AntiDetectDylib v13 - 延迟MSHookFunction
 *
 * v12闪退原因：在dylib constructor中直接调用MSHookFunction
 * 此时CydiaSubstrate可能还没初始化完成，或hook的函数在启动早期被高频调用
 *
 * v13策略：
 *   - constructor中只做ObjC hook（已验证稳定）
 *   - C函数hook延迟到主线程runloop启动后执行（dispatch_after 1秒）
 *   - 这样所有framework都已初始化，MSHookFunction安全可用
 *   - 易盾检测在选角色后触发，延迟1秒hook完全来得及
 *
 * 额外安全措施：
 *   - hook函数中检查orig指针是否为NULL，防止空指针调用
 *   - 对_dyld_get_image_name不hook（避免递归），改用dladdr即可
 */

#pragma mark - CydiaSubstrate MSHookFunction

typedef void (*MSHookFunction_t)(void *symbol, void *replace, void **result);
static MSHookFunction_t g_MSHookFunction = NULL;

static BOOL load_MSHookFunction() {
    if (g_MSHookFunction) return YES;
    g_MSHookFunction = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (g_MSHookFunction) {
        NSLog(@"[AntiDetect] MSHookFunction loaded");
        return YES;
    }
    // 尝试显式加载
    void *h = dlopen("@executable_path/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_LAZY);
    if (!h) h = dlopen("/usr/lib/libsubstrate.dylib", RTLD_LAZY);
    if (h) g_MSHookFunction = (MSHookFunction_t)dlsym(h, "MSHookFunction");
    if (g_MSHookFunction) {
        NSLog(@"[AntiDetect] MSHookFunction loaded via dlopen");
        return YES;
    }
    NSLog(@"[AntiDetect] MSHookFunction NOT available");
    return NO;
}

#pragma mark - 配置

static NSArray *g_jailbreak_paths = nil;
static NSArray *g_hidden_keywords = nil;
static NSArray *g_hidden_dylib_keywords = nil;

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
        g_hidden_dylib_keywords = @[
            @"CydiaSubstrate",
            @"SubstrateLoader",
            @"MobileSubstrate",
            @"libsubstrate",
            @"TrollFools",
            @"TrollStore",
            @"AntiDetect",
            @"LIBTOOL",
            @"libhooker",
        ];
    });
}

static BOOL is_jailbreak_path_c(const char *path) {
    if (!path) return NO;
    NSString *nsPath = [NSString stringWithUTF8String:path];
    for (NSString *jp in g_jailbreak_paths) {
        if ([nsPath hasPrefix:jp]) return YES;
    }
    return NO;
}

static BOOL should_block_ns(NSString *path) {
    if (!path || path.length == 0) return NO;
    for (NSString *jp in g_jailbreak_paths) {
        if ([path hasPrefix:jp]) return YES;
    }
    NSString *lower = path.lowercaseString;
    for (NSString *kw in g_hidden_keywords) {
        if ([lower containsString:kw.lowercaseString]) return YES;
    }
    return NO;
}

static BOOL should_hide_dylib(const char *name) {
    if (!name) return NO;
    NSString *nsName = [NSString stringWithUTF8String:name].lowercaseString;
    for (NSString *kw in g_hidden_dylib_keywords) {
        if ([nsName containsString:kw.lowercaseString]) return YES;
    }
    return NO;
}

#pragma mark - C函数Hook定义

// --- 文件系统 ---
static int (*orig_stat)(const char *restrict, struct stat *restrict) = NULL;
static int (*orig_access)(const char *, int) = NULL;
static FILE *(*orig_fopen)(const char *, const char *) = NULL;
static DIR *(*orig_opendir)(const char *) = NULL;

static int hook_stat(const char *restrict path, struct stat *restrict buf) {
    if (!orig_stat) return -1;
    if (is_jailbreak_path_c(path)) return -1;
    return orig_stat(path, buf);
}

static int hook_access(const char *path, int mode) {
    if (!orig_access) return -1;
    if (is_jailbreak_path_c(path)) { errno = ENOENT; return -1; }
    return orig_access(path, mode);
}

static FILE *hook_fopen(const char *path, const char *mode) {
    if (!orig_fopen) return NULL;
    if (is_jailbreak_path_c(path)) return NULL;
    return orig_fopen(path, mode);
}

static DIR *hook_opendir(const char *path) {
    if (!orig_opendir) return NULL;
    if (is_jailbreak_path_c(path)) return NULL;
    return orig_opendir(path);
}

// --- 动态库 ---
static int (*orig_dladdr)(const void *, Dl_info *) = NULL;

static int hook_dladdr(const void *addr, Dl_info *info) {
    if (!orig_dladdr) return 0;
    int ret = orig_dladdr(addr, info);
    if (ret && info && info->dli_fname && should_hide_dylib(info->dli_fname)) {
        memset(info, 0, sizeof(Dl_info));
        return 0;
    }
    return ret;
}

// --- 环境变量 ---
static char *(*orig_getenv)(const char *) = NULL;

static char *hook_getenv(const char *name) {
    if (!orig_getenv) return NULL;
    if (name) {
        if (strstr(name, "DYLD_") == name) return NULL;
        if (strstr(name, "MSSafeMode") || strstr(name, "_MSSafeMode") ||
            strstr(name, "SUBSTRATE_HOME")) return NULL;
    }
    return orig_getenv(name);
}

// --- sysctl ---
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;

static int hook_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!orig_sysctl) return -1;
    int result = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    // 清除P_TRACED标志
    if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC &&
        name[2] == KERN_PROC_PID && oldp && oldlenp &&
        *oldlenp >= sizeof(struct kinfo_proc)) {
        ((struct kinfo_proc *)oldp)->kp_proc.p_flag &= ~P_TRACED;
    }
    return result;
}

#pragma mark - 延迟安装C函数Hook

static void install_c_function_hooks() {
    NSLog(@"[AntiDetect] 开始安装C函数Hook（延迟）...");

    if (!load_MSHookFunction()) {
        NSLog(@"[AntiDetect] MSHookFunction不可用，跳过C函数hook");
        return;
    }

    // 文件系统
    g_MSHookFunction((void *)stat, (void *)hook_stat, (void **)&orig_stat);
    g_MSHookFunction((void *)access, (void *)hook_access, (void **)&orig_access);
    g_MSHookFunction((void *)fopen, (void *)hook_fopen, (void **)&orig_fopen);
    g_MSHookFunction((void *)opendir, (void *)hook_opendir, (void **)&orig_opendir);

    // 动态库（只hook dladdr，不hook _dyld_image_count/_dyld_get_image_name避免递归）
    g_MSHookFunction((void *)dladdr, (void *)hook_dladdr, (void **)&orig_dladdr);

    // 环境变量
    g_MSHookFunction((void *)getenv, (void *)hook_getenv, (void **)&orig_getenv);

    // sysctl
    g_MSHookFunction((void *)sysctl, (void *)hook_sysctl, (void **)&orig_sysctl);

    NSLog(@"[AntiDetect] C函数Hook安装完成！stat/access/fopen/opendir/dladdr/getenv/sysctl");
}

#pragma mark - ObjC Hook

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
            NSLog(@"[AntiDetect] 拦截弹窗: %@ %@", alert.title, alert.message);
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
        init_config();

        NSLog(@"[AntiDetect] v13 初始化...");

        // ===== ObjC Hook（constructor中立即执行，已验证稳定）=====
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

        // ===== C函数Hook（延迟执行，等runloop启动后）=====
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            install_c_function_hooks();
        });

        NSLog(@"[AntiDetect] v13 ObjC Hook完成，C函数Hook将在1秒后安装");
    }
}
