#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <UIKit/UIKit.h>
#import <string.h>

/*
 * AntiDetectDylib v18 - 精准动态库隐藏版
 *
 * 关键发现：Shadow插件只需要"动态库"一项hook就能过检测！
 * 说明网易易盾的检测核心就是扫描注入的动态库，不是文件系统/环境变量。
 *
 * v17卡住原因：hook了stat/access等IO函数，MSHookFunction修改IO路径导致游戏卡死
 *
 * v18策略：只hook动态库相关函数，完全不碰IO函数！
 *   1. _dyld_get_image_name - 隐藏越狱/注入的dylib名称
 *   2. dladdr - 隐藏注入dylib的地址映射
 *   3. ObjC: NSFileManager隐藏越狱路径（保险，稳定不卡）
 *   4. ObjC: canOpenURL屏蔽越狱URL Scheme
 *   5. 弹窗拦截
 *
 * 不hook的函数：stat, access, fopen, opendir, getenv, sysctl
 * → 这些全是IO/系统函数，hook会导致卡顿或闪退，而且易盾不靠它们检测
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
    "substrate",
    "Substrate",
    NULL
};

static inline BOOL should_hide_dylib(const char *name) {
    if (!name) return NO;
    for (int i = 0; g_hide_dylib_kw[i]; i++) {
        if (strstr(name, g_hide_dylib_kw[i])) return YES;
    }
    return NO;
}

#pragma mark - _dyld_get_image_name Hook

static const char *(*orig_dyld_get_image_name)(uint32_t) = NULL;

static const char *hook_dyld_get_image_name(uint32_t index) {
    const char *name = orig_dyld_get_image_name(index);
    if (should_hide_dylib(name)) {
        // 返回一个空路径，假装这个image不存在
        return "";
    }
    return name;
}

#pragma mark - dladdr Hook

static int (*orig_dladdr)(const void *, Dl_info *) = NULL;

static int hook_dladdr(const void *addr, Dl_info *info) {
    int ret = orig_dladdr(addr, info);
    if (ret && info && info->dli_fname && should_hide_dylib(info->dli_fname)) {
        // 清空info，假装这个地址不属于任何dylib
        memset(info, 0, sizeof(Dl_info));
        return 0;
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

#pragma mark - 安装C函数Hook（动态库相关，延迟1秒）

static void install_dylib_hooks() {
    NSLog(@"[AntiDetect] 安装动态库Hook...");
    if (!load_MSHookFunction()) {
        NSLog(@"[AntiDetect] MSHookFunction不可用，尝试直接加载");
        return;
    }

    // 只hook动态库相关的两个函数
    g_MSHookFunction((void *)_dyld_get_image_name, (void *)hook_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    g_MSHookFunction((void *)dladdr, (void *)hook_dladdr, (void **)&orig_dladdr);

    NSLog(@"[AntiDetect] ★ 动态库Hook安装完成 ★ _dyld_get_image_name + dladdr");
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

        NSLog(@"[AntiDetect] v18 初始化...");

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

        // ===== 动态库Hook（延迟1秒，只hook _dyld_get_image_name + dladdr）=====
        // 不hook任何IO函数（stat/access/fopen/opendir/getenv/sysctl）！
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            install_dylib_hooks();
        });

        NSLog(@"[AntiDetect] v18 ObjC完成，+1s安装动态库Hook");
    }
}
