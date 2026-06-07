#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <UIKit/UIKit.h>
#import <sys/stat.h>
#import <dirent.h>
#import <string.h>
#import <stdio.h>
#import <stdlib.h>
#import "fishhook.h"

/*
 * AntiDetectDylib v22 - fishhook原版 + ObjC Hook
 *
 * 核心发现：
 *   - MSHookFunction在非越狱下不可用 → 需要修改__TEXT段（W^X禁止）
 *   - fishhook只修改__DATA段 → 不受W^X限制 → 非越狱可用
 *   - 之前v7 fishhook闪退可能是因为hook了不安全的函数或编译问题
 *
 * v22使用Facebook原版fishhook库：
 *   - 只hook动态链接的C函数（stat, access, fopen, opendir, dladdr）
 *   - 不hook dyld函数（_dyld_image_count等不能用fishhook！）
 *   - 不hook静态链接的函数
 *   - dispatch_after 1秒安装
 *
 * ObjC Hook（constructor中立即执行）：
 *   - NSFileManager: fileExistsAtPath等
 *   - NSBundle: bundleWithPath, allBundles, allFrameworks
 *   - UIApplication: canOpenURL
 *   - UIViewController: presentViewController（拦截弹窗）
 */

#pragma mark - 越狱路径判断（纯C）

static const char *g_jb_A[] = { "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app", "/Applications/unc0ver.app", "/Applications/Taurine.app", "/Applications/TrollStore.app", "/Applications/TrollFools.app", NULL };
static const char *g_jb_other[] = { "/Library/MobileSubstrate", "/usr/lib/substrate", "/usr/lib/ligerness", "/usr/lib/libhooker", "/etc/apt", "/var/lib/apt", "/var/lib/cydia", "/var/jb", "/private/var/lib/cydia", "/private/var/mobile/Library/Cydia", "/private/var/jb", "/.bootstrapped_evas1on", "/.cydia_no_stash", "/.installed_unc0ver", NULL };

static const char *g_hide_dylib_kw[] = { "CydiaSubstrate", "SubstrateLoader", "MobileSubstrate", "TrollFools", "TrollStore", "AntiDetect", "LIBTOOL", "libhooker", "substrate", NULL };

static inline BOOL is_jb_path(const char *path) {
    if (!path) return NO;
    char c = path[0];
    if (c == '/') {
        char c2 = path[1];
        if (c2 == 'A') {
            for (int i = 0; g_jb_A[i]; i++)
                if (strncmp(path, g_jb_A[i], strlen(g_jb_A[i])) == 0) return YES;
        } else {
            for (int i = 0; g_jb_other[i]; i++)
                if (strncmp(path, g_jb_other[i], strlen(g_jb_other[i])) == 0) return YES;
        }
    }
    return NO;
}

static inline BOOL should_hide_dylib(const char *name) {
    if (!name) return NO;
    for (int i = 0; g_hide_dylib_kw[i]; i++)
        if (strstr(name, g_hide_dylib_kw[i])) return YES;
    return NO;
}

#pragma mark - C函数Hook（fishhook）

static int (*orig_stat)(const char *restrict, struct stat *restrict) = NULL;
static int (*orig_access)(const char *, int) = NULL;
static FILE *(*orig_fopen)(const char *restrict, const char *restrict) = NULL;
static DIR *(*orig_opendir)(const char *) = NULL;
static int (*orig_dladdr)(const void *, Dl_info *) = NULL;

static char g_main_exec_path[1024] = {0};

static int hook_stat(const char *restrict path, struct stat *restrict buf) {
    if (is_jb_path(path)) return -1;
    return orig_stat(path, buf);
}

static int hook_access(const char *path, int mode) {
    if (is_jb_path(path)) { errno = ENOENT; return -1; }
    return orig_access(path, mode);
}

static FILE *hook_fopen(const char *restrict path, const char *restrict mode) {
    if (is_jb_path(path)) { errno = ENOENT; return NULL; }
    return orig_fopen(path, mode);
}

static DIR *hook_opendir(const char *path) {
    if (is_jb_path(path)) { errno = ENOENT; return NULL; }
    return orig_opendir(path);
}

static int hook_dladdr(const void *addr, Dl_info *info) {
    int ret = orig_dladdr(addr, info);
    if (ret && info && info->dli_fname && should_hide_dylib(info->dli_fname)) {
        if (g_main_exec_path[0]) {
            info->dli_fname = g_main_exec_path;
        }
        info->dli_sname = NULL;
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
static IMP orig_bundleWithPath_IMP = NULL;
static IMP orig_bundleForClass_IMP = NULL;
static IMP orig_allBundles_IMP = NULL;
static IMP orig_allFrameworks_IMP = NULL;

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

static id hooked_bundleWithPath(id self, SEL _cmd, NSString *path) {
    if (should_block_ns(path)) return nil;
    return ((id(*)(id, SEL, NSString *))orig_bundleWithPath_IMP)(self, _cmd, path);
}

static id hooked_bundleForClass(id self, SEL _cmd, Class cls) {
    id result = ((id(*)(id, SEL, Class))orig_bundleForClass_IMP)(self, _cmd, cls);
    if (result) {
        NSString *bPath = [(NSBundle *)result bundlePath];
        if (should_block_ns(bPath)) return nil;
    }
    return result;
}

static NSArray *hooked_allBundles(id self, SEL _cmd) {
    NSArray *result = ((NSArray *(*)(id, SEL))orig_allBundles_IMP)(self, _cmd);
    if (!result) return result;
    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:result.count];
    for (NSBundle *bundle in result) {
        if (!should_block_ns([bundle bundlePath])) [filtered addObject:bundle];
    }
    return [filtered copy];
}

static NSArray *hooked_allFrameworks(id self, SEL _cmd) {
    NSArray *result = ((NSArray *(*)(id, SEL))orig_allFrameworks_IMP)(self, _cmd);
    if (!result) return result;
    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:result.count];
    for (NSBundle *bundle in result) {
        if (!should_block_ns([bundle bundlePath])) [filtered addObject:bundle];
    }
    return [filtered copy];
}

#pragma mark - 安装fishhook

static void install_fishhooks() {
    NSLog(@"[AntiDetect] 安装fishhook...");

    // 缓存游戏主程序路径
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "/Application/") && !strstr(name, "/Applications/") &&
            !strstr(name, ".dylib") && !strstr(name, ".framework/")) {
            strncpy(g_main_exec_path, name, sizeof(g_main_exec_path) - 1);
            break;
        }
    }
    if (g_main_exec_path[0] == '\0') {
        const char *name = _dyld_get_image_name(0);
        if (name) strncpy(g_main_exec_path, name, sizeof(g_main_exec_path) - 1);
    }
    NSLog(@"[AntiDetect] 主程序: %s", g_main_exec_path);

    // 使用Facebook fishhook重绑定符号
    struct rebinding rebindings[] = {
        {"stat",       (void *)hook_stat,       (void **)&orig_stat},
        {"access",     (void *)hook_access,     (void **)&orig_access},
        {"fopen",      (void *)hook_fopen,      (void **)&orig_fopen},
        {"opendir",    (void *)hook_opendir,    (void **)&orig_opendir},
        {"dladdr",     (void *)hook_dladdr,     (void **)&orig_dladdr},
    };

    int ret = rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
    NSLog(@"[AntiDetect] fishhook rebind_symbols 返回: %d", ret);

    if (orig_stat && orig_access && orig_fopen && orig_opendir && orig_dladdr) {
        NSLog(@"[AntiDetect] ★ fishhook安装完成 ★ 所有原始函数指针已获取");
    } else {
        NSLog(@"[AntiDetect] ⚠ fishhook部分失败: stat=%p access=%p fopen=%p opendir=%p dladdr=%p",
              orig_stat, orig_access, orig_fopen, orig_opendir, orig_dladdr);
    }
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

        NSLog(@"[AntiDetect] v22 初始化（fishhook原版）...");

        // ===== ObjC Hook（constructor中立即执行）=====
        Class fmClass = objc_getClass("NSFileManager");
        if (fmClass) {
            Method m1 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:));
            if (m1) { orig_fileExistsAtPath_IMP = method_getImplementation(m1); method_setImplementation(m1, (IMP)hooked_fileExistsAtPath); }
            Method m2 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:isDirectory:));
            if (m2) { orig_fileExistsAtPathIsDir_IMP = method_getImplementation(m2); method_setImplementation(m2, (IMP)hooked_fileExistsAtPathIsDir); }
            Method m3 = class_getInstanceMethod(fmClass, @selector(contentsOfDirectoryAtPath:error:));
            if (m3) { orig_contentsOfDirectoryAtPath_IMP = method_getImplementation(m3); method_setImplementation(m3, (IMP)hooked_contentsOfDirectoryAtPath); }
        }

        Class bundleClass = objc_getClass("NSBundle");
        if (bundleClass) {
            Class metaClass = object_getClass(bundleClass);
            Method mb1 = class_getInstanceMethod(metaClass, @selector(bundleWithPath:));
            if (mb1) { orig_bundleWithPath_IMP = method_getImplementation(mb1); method_setImplementation(mb1, (IMP)hooked_bundleWithPath); }
            Method mb2 = class_getInstanceMethod(metaClass, @selector(bundleForClass:));
            if (mb2) { orig_bundleForClass_IMP = method_getImplementation(mb2); method_setImplementation(mb2, (IMP)hooked_bundleForClass); }
            Method mb3 = class_getInstanceMethod(metaClass, @selector(allBundles));
            if (mb3) { orig_allBundles_IMP = method_getImplementation(mb3); method_setImplementation(mb3, (IMP)hooked_allBundles); }
            Method mb4 = class_getInstanceMethod(metaClass, @selector(allFrameworks));
            if (mb4) { orig_allFrameworks_IMP = method_getImplementation(mb4); method_setImplementation(mb4, (IMP)hooked_allFrameworks); }
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

        // ===== fishhook（延迟1秒）=====
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            install_fishhooks();
        });

        NSLog(@"[AntiDetect] v22 ObjC完成，+1s fishhook");
    }
}
