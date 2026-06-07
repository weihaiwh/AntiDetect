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
 * AntiDetectDylib v14 - 优化C函数hook性能
 *
 * v13问题：游戏卡在logo加载阶段
 * 原因：hook函数中用NSString做字符串匹配太慢，导致游戏的文件IO阻塞
 *
 * v14修复：
 *   1. C函数hook延迟3秒（等游戏资源加载完）
 *   2. hook函数内部用纯C字符串操作（strstr/strncmp），不用NSString
 *   3. 越狱路径检查用前缀快速匹配，避免字符串分配
 *   4. 只hook必要的函数，减少拦截范围
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

#pragma mark - 越狱路径配置（纯C字符串，高性能）

// 越狱路径前缀 - 用纯C字符串避免NSString开销
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

// 越狱路径中包含的关键词（用于dladdr检查）
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

// 纯C函数：检查路径是否为越狱路径
static BOOL is_jb_path(const char *path) {
    if (!path) return NO;
    for (int i = 0; g_jb_prefixes[i]; i++) {
        if (strncmp(path, g_jb_prefixes[i], strlen(g_jb_prefixes[i])) == 0)
            return YES;
    }
    return NO;
}

// 纯C函数：检查dylib名是否要隐藏
static BOOL should_hide_lib(const char *name) {
    if (!name) return NO;
    for (int i = 0; g_hide_keywords[i]; i++) {
        if (strstr(name, g_hide_keywords[i]))
            return YES;
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
    if (ret && info && info->dli_fname && should_hide_lib(info->dli_fname)) {
        memset(info, 0, sizeof(Dl_info));
        return 0;
    }
    return ret;
}

static char *hook_getenv(const char *name) {
    if (name) {
        if (strncmp(name, "DYLD_", 5) == 0) return NULL;
        if (strstr(name, "MSSafeMode") || strstr(name, "SUBSTRATE_HOME")) return NULL;
    }
    return orig_getenv(name);
}

static int hook_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int result = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC &&
        name[2] == KERN_PROC_PID && oldp && oldlenp &&
        *oldlenp >= sizeof(struct kinfo_proc)) {
        ((struct kinfo_proc *)oldp)->kp_proc.p_flag &= ~P_TRACED;
    }
    return result;
}

#pragma mark - 安装C函数Hook

static void install_c_hooks() {
    if (!load_MSHookFunction()) {
        NSLog(@"[AntiDetect] MSHookFunction不可用");
        return;
    }

    g_MSHookFunction((void *)stat, (void *)hook_stat, (void **)&orig_stat);
    g_MSHookFunction((void *)access, (void *)hook_access, (void **)&orig_access);
    g_MSHookFunction((void *)fopen, (void *)hook_fopen, (void **)&orig_fopen);
    g_MSHookFunction((void *)dladdr, (void *)hook_dladdr, (void **)&orig_dladdr);
    g_MSHookFunction((void *)getenv, (void *)hook_getenv, (void **)&orig_getenv);
    g_MSHookFunction((void *)sysctl, (void *)hook_sysctl, (void **)&orig_sysctl);

    NSLog(@"[AntiDetect] C函数Hook安装完成 (stat/access/fopen/dladdr/getenv/sysctl)");
}

#pragma mark - ObjC Hook

static IMP orig_fileExistsAtPath_IMP = NULL;
static IMP orig_fileExistsAtPathIsDir_IMP = NULL;
static IMP orig_contentsOfDirectoryAtPath_IMP = NULL;
static IMP orig_canOpenURL_IMP = NULL;
static IMP orig_presentViewController_IMP = NULL;

// ObjC层用的路径检查（NSString）
static NSArray *g_jb_paths_ns = nil;
static NSArray *g_hide_kw_ns = nil;

static BOOL should_block_ns(NSString *path) {
    if (!path || path.length == 0) return NO;
    if (!g_jb_paths_ns) return NO;
    for (NSString *jp in g_jb_paths_ns) {
        if ([path hasPrefix:jp]) return YES;
    }
    NSString *lower = path.lowercaseString;
    for (NSString *kw in g_hide_kw_ns) {
        if ([lower containsString:kw.lowercaseString]) return YES;
    }
    return NO;
}

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
        // 初始化ObjC配置
        g_jb_paths_ns = @[
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
        g_hide_kw_ns = @[
            @"AntiDetect", @"LIBTOOL", @"CydiaSubstrate",
            @"TrollFools", @"TrollStore", @"substrate",
            @"SubstrateLoader", @"MobileSubstrate", @"libhooker",
        ];

        NSLog(@"[AntiDetect] v14 初始化...");

        // ===== ObjC Hook（立即执行）=====
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

        // ===== C函数Hook（延迟3秒，等游戏资源加载完毕）=====
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            install_c_hooks();
        });

        NSLog(@"[AntiDetect] v14 ObjC Hook完成，C函数Hook将在3秒后安装");
    }
}
