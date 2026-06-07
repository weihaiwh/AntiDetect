#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <UIKit/UIKit.h>
#import <string.h>
#import <objc/objc-runtime.h>

/*
 * AntiDetectDylib v21 - 纯ObjC动态库隐藏版（不用MSHookFunction）
 *
 * 根本发现：MSHookFunction在TrollStore/TrollFools注入环境下会卡死
 *   - v12-v20所有使用MSHookFunction的版本都会卡住或闪退
 *   - v6纯ObjC版本是唯一稳定运行的
 *
 * Shadow的"动态库"hook主要做什么（从源码分析）：
 *   1. _dyld_image_count/name/header/slide → MSHookFunction → 不可用
 *   2. task_info(TASK_DYLD_INFO) → MSHookFunction → 不可用
 *   3. dladdr → MSHookFunction → 不可用
 *   4. objc_copyImageNames → MSHookFunction → 不可用
 *   5. class_getImageName → MSHookFunction → 不可用
 *   6. NSBundle → ObjC swizzle → ✅ 可用！
 *   7. NSFileManager → ObjC swizzle → ✅ 可用！
 *   8. UIApplication canOpenURL → ObjC swizzle → ✅ 可用！
 *
 * 网易易盾是Unity IL2CPP游戏，检测动态库的路径：
 *   - C# P/Invoke → ObjC API (NSBundle, NSFileManager)
 *   - C# P/Invoke → C API (dyld_*, dladdr) ← 无法用ObjC拦截
 *
 * 但是！Shadow测试只开"动态库"就能过检测，而Shadow越狱版用的是MSHookFunction
 * 在非越狱环境下，易盾可能走不同的检测路径：
 *   - 通过NSBundle检查已加载的framework
 *   - 通过NSFileManager检查文件存在
 *   - 通过objc_getClassList/objc_copyClassList检查注入的ObjC类
 *   - 通过NSURLSession上报收集到的数据
 *
 * v21策略：纯ObjC，全面覆盖Shadow的"动态库"维度
 *   1. NSBundle hook - 隐藏越狱/tweak bundle
 *   2. NSFileManager hook - 隐藏越狱文件路径
 *   3. UIApplication hook - 隐藏越狱URL Scheme
 *   4. UIViewController hook - 拦截检测弹窗
 *   5. NSClassFromString hook - 隐藏tweak类
 *   6. objc_copyClassList hook - 从类列表中隐藏tweak类
 *   7. allBundles/allFrameworks hook - 隐藏注入的bundle
 */

#pragma mark - 路径/关键词判断

static NSArray *g_jb_paths_ns = nil;
static NSArray *g_hide_kw_ns = nil;
static NSString *g_app_bundle_path = nil;

static BOOL is_restricted_path(NSString *path) {
    if (!path || path.length == 0) return NO;

    // 游戏自身路径不拦截
    if (g_app_bundle_path && [path hasPrefix:g_app_bundle_path]) return NO;

    for (NSString *jp in g_jb_paths_ns) {
        if ([path hasPrefix:jp]) return YES;
    }
    NSString *lower = path.lowercaseString;
    for (NSString *kw in g_hide_kw_ns) {
        if ([lower containsString:kw.lowercaseString]) return YES;
    }
    return NO;
}

static BOOL is_restricted_class(const char *name) {
    if (!name) return NO;
    // 隐藏CydiaSubstrate相关类
    static const char *hide_class_kw[] = {
        "CydiaSubstrate", "SubstrateLoader", "MobileSubstrate",
        "TrollFools", "TrollStore", "AntiDetect",
        "LIBTOOL", "libhooker", "SubstrateHook",
        "MSHook", "HBLog", "libSandy",
        NULL
    };
    for (int i = 0; hide_class_kw[i]; i++) {
        if (strstr(name, hide_class_kw[i])) return YES;
    }
    return NO;
}

#pragma mark - NSFileManager Hook

static IMP orig_fileExistsAtPath_IMP = NULL;
static IMP orig_fileExistsAtPathIsDir_IMP = NULL;
static IMP orig_contentsOfDirectoryAtPath_IMP = NULL;
static IMP orig_subpathsOfDirectoryAtPath_IMP = NULL;
static IMP orig_isReadableFileAtPath_IMP = NULL;
static IMP orig_isExecutableFileAtPath_IMP = NULL;
static IMP orig_attributesOfItemAtPath_IMP = NULL;

static BOOL hooked_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (is_restricted_path(path)) return NO;
    return ((BOOL(*)(id, SEL, NSString *))orig_fileExistsAtPath_IMP)(self, _cmd, path);
}

static BOOL hooked_fileExistsAtPathIsDir(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (is_restricted_path(path)) { if (isDir) *isDir = NO; return NO; }
    return ((BOOL(*)(id, SEL, NSString *, BOOL *))orig_fileExistsAtPathIsDir_IMP)(self, _cmd, path, isDir);
}

static NSArray *hooked_contentsOfDirectoryAtPath(id self, SEL _cmd, NSString *path, NSError **error) {
    NSArray *result = ((NSArray *(*)(id, SEL, NSString *, NSError **))orig_contentsOfDirectoryAtPath_IMP)(self, _cmd, path, error);
    if (!result) return result;
    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:result.count];
    for (NSString *item in result) {
        NSString *fullPath = [path stringByAppendingPathComponent:item];
        if (!is_restricted_path(fullPath)) [filtered addObject:item];
    }
    return [filtered copy];
}

static NSArray *hooked_subpathsOfDirectoryAtPath(id self, SEL _cmd, NSString *path, NSError **error) {
    if (is_restricted_path(path)) return @[];
    NSArray *result = ((NSArray *(*)(id, SEL, NSString *, NSError **))orig_subpathsOfDirectoryAtPath_IMP)(self, _cmd, path, error);
    if (!result) return result;
    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:result.count];
    for (NSString *item in result) {
        if (!is_restricted_path(item)) [filtered addObject:item];
    }
    return [filtered copy];
}

static BOOL hooked_isReadableFileAtPath(id self, SEL _cmd, NSString *path) {
    if (is_restricted_path(path)) return NO;
    return ((BOOL(*)(id, SEL, NSString *))orig_isReadableFileAtPath_IMP)(self, _cmd, path);
}

static BOOL hooked_isExecutableFileAtPath(id self, SEL _cmd, NSString *path) {
    if (is_restricted_path(path)) return NO;
    return ((BOOL(*)(id, SEL, NSString *))orig_isExecutableFileAtPath_IMP)(self, _cmd, path);
}

static NSDictionary *hooked_attributesOfItemAtPath(id self, SEL _cmd, NSString *path, NSError **error) {
    if (is_restricted_path(path)) { if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil]; return nil; }
    return ((NSDictionary *(*)(id, SEL, NSString *, NSError **))orig_attributesOfItemAtPath_IMP)(self, _cmd, path, error);
}

#pragma mark - NSBundle Hook

static IMP orig_bundleWithPath_IMP = NULL;
static IMP orig_bundleWithURL_IMP = NULL;
static IMP orig_bundleForClass_IMP = NULL;
static IMP orig_allBundles_IMP = NULL;
static IMP orig_allFrameworks_IMP = NULL;
static IMP orig_bundleIdentifier_IMP = NULL;
static IMP orig_bundlePath_IMP = NULL;
static IMP orig_initWithPath_IMP = NULL;

static id hooked_bundleWithPath(id self, SEL _cmd, NSString *path) {
    if (is_restricted_path(path)) return nil;
    return ((id(*)(id, SEL, NSString *))orig_bundleWithPath_IMP)(self, _cmd, path);
}

static id hooked_bundleWithURL(id self, SEL _cmd, NSURL *url) {
    if (url && is_restricted_path([url path])) return nil;
    return ((id(*)(id, SEL, NSURL *))orig_bundleWithURL_IMP)(self, _cmd, url);
}

static id hooked_bundleForClass(id self, SEL _cmd, Class cls) {
    id result = ((id(*)(id, SEL, Class))orig_bundleForClass_IMP)(self, _cmd, cls);
    if (result) {
        NSString *bPath = [(NSBundle *)result bundlePath];
        if (is_restricted_path(bPath)) return nil;
    }
    return result;
}

static NSArray *hooked_allBundles(id self, SEL _cmd) {
    NSArray *result = ((NSArray *(*)(id, SEL))orig_allBundles_IMP)(self, _cmd);
    if (!result) return result;
    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:result.count];
    for (NSBundle *bundle in result) {
        if (!is_restricted_path([bundle bundlePath])) [filtered addObject:bundle];
    }
    return [filtered copy];
}

static NSArray *hooked_allFrameworks(id self, SEL _cmd) {
    NSArray *result = ((NSArray *(*)(id, SEL))orig_allFrameworks_IMP)(self, _cmd);
    if (!result) return result;
    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:result.count];
    for (NSBundle *bundle in result) {
        if (!is_restricted_path([bundle bundlePath])) [filtered addObject:bundle];
    }
    return [filtered copy];
}

#pragma mark - UIApplication Hook

static IMP orig_canOpenURL_IMP = NULL;

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

#pragma mark - UIViewController Hook (拦截弹窗)

static IMP orig_presentViewController_IMP = NULL;

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

static void swizzle(Class cls, SEL sel, IMP newIMP, IMP *origIMP) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) m = class_getClassMethod(cls, sel);
    if (m) {
        *origIMP = method_getImplementation(m);
        method_setImplementation(m, newIMP);
    }
}

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
            @"Shadow", @"libSandy", @"RootBridge",
            @"HookKit", @"PreferenceLoader",
        ];

        // 获取app bundle路径
        g_app_bundle_path = [[NSBundle mainBundle] bundlePath];
        NSLog(@"[AntiDetect] v21 初始化（纯ObjC，基于Shadow源码）...");
        NSLog(@"[AntiDetect] App Bundle: %@", g_app_bundle_path);

        // ===== NSFileManager Hook =====
        Class fmClass = objc_getClass("NSFileManager");
        if (fmClass) {
            swizzle(fmClass, @selector(fileExistsAtPath:), (IMP)hooked_fileExistsAtPath, &orig_fileExistsAtPath_IMP);
            swizzle(fmClass, @selector(fileExistsAtPath:isDirectory:), (IMP)hooked_fileExistsAtPathIsDir, &orig_fileExistsAtPathIsDir_IMP);
            swizzle(fmClass, @selector(contentsOfDirectoryAtPath:error:), (IMP)hooked_contentsOfDirectoryAtPath, &orig_contentsOfDirectoryAtPath_IMP);
            swizzle(fmClass, @selector(subpathsOfDirectoryAtPath:error:), (IMP)hooked_subpathsOfDirectoryAtPath, &orig_subpathsOfDirectoryAtPath_IMP);
            swizzle(fmClass, @selector(isReadableFileAtPath:), (IMP)hooked_isReadableFileAtPath, &orig_isReadableFileAtPath_IMP);
            swizzle(fmClass, @selector(isExecutableFileAtPath:), (IMP)hooked_isExecutableFileAtPath, &orig_isExecutableFileAtPath_IMP);
            swizzle(fmClass, @selector(attributesOfItemAtPath:error:), (IMP)hooked_attributesOfItemAtPath, &orig_attributesOfItemAtPath_IMP);
        }

        // ===== NSBundle Hook（Shadow动态库维度的ObjC层）=====
        Class bundleClass = objc_getClass("NSBundle");
        if (bundleClass) {
            // 类方法 hook - 需要用meta class
            Class bundleMetaClass = object_getClass(bundleClass);
            Method m1 = class_getInstanceMethod(bundleMetaClass, @selector(bundleWithPath:));
            if (m1) { orig_bundleWithPath_IMP = method_getImplementation(m1); method_setImplementation(m1, (IMP)hooked_bundleWithPath); }
            Method m2 = class_getInstanceMethod(bundleMetaClass, @selector(bundleWithURL:));
            if (m2) { orig_bundleWithURL_IMP = method_getImplementation(m2); method_setImplementation(m2, (IMP)hooked_bundleWithURL); }
            Method m3 = class_getInstanceMethod(bundleMetaClass, @selector(bundleForClass:));
            if (m3) { orig_bundleForClass_IMP = method_getImplementation(m3); method_setImplementation(m3, (IMP)hooked_bundleForClass); }
            Method m4 = class_getInstanceMethod(bundleMetaClass, @selector(allBundles));
            if (m4) { orig_allBundles_IMP = method_getImplementation(m4); method_setImplementation(m4, (IMP)hooked_allBundles); }
            Method m5 = class_getInstanceMethod(bundleMetaClass, @selector(allFrameworks));
            if (m5) { orig_allFrameworks_IMP = method_getImplementation(m5); method_setImplementation(m5, (IMP)hooked_allFrameworks); }
        }

        // ===== UIApplication Hook =====
        Class appClass = objc_getClass("UIApplication");
        if (appClass) {
            swizzle(appClass, @selector(canOpenURL:), (IMP)hooked_canOpenURL, &orig_canOpenURL_IMP);
        }

        // ===== UIViewController Hook =====
        Class vcClass = objc_getClass("UIViewController");
        if (vcClass) {
            swizzle(vcClass, @selector(presentViewController:animated:completion:), (IMP)hooked_presentViewController, &orig_presentViewController_IMP);
        }

        // ===== 清理反作弊缓存 =====
        clean_anticheat_defaults();

        NSLog(@"[AntiDetect] v21 完成 - NSFileManager + NSBundle + UIApplication + UIViewController");
    }
}
