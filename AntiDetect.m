#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/dyld_images.h>
#import <mach/mach.h>
#import <mach/task_info.h>
#import <mach/mach_time.h>
#import <UIKit/UIKit.h>
#import <sys/stat.h>
#import <dirent.h>
#import <string.h>
#import <stdio.h>
#import <stdlib.h>
#import <pthread.h>
#import "fishhook.h"

// _dyld_get_all_image_infos 不是公开API，需要通过task_info获取
static struct dyld_all_image_infos *get_dyld_all_image_infos() {
    // 方式1: 通过task_info获取地址
    task_dyld_info_data_t dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t ret = task_info(mach_task_self(), TASK_DYLD_INFO,
                                  (task_info_t)&dyld_info, &count);
    if (ret == KERN_SUCCESS && dyld_info.all_image_info_addr) {
        return (struct dyld_all_image_infos *)(uintptr_t)dyld_info.all_image_info_addr;
    }

    // 方式2: 通过dlsym查找（备用）
    typedef const struct dyld_all_image_infos *(*GetAllImageInfosFunc)(void);
    GetAllImageInfosFunc func = (GetAllImageInfosFunc)dlsym(RTLD_DEFAULT, "_dyld_get_all_image_infos");
    if (func) {
        return (struct dyld_all_image_infos *)func();
    }

    return NULL;
}

/*
 * AntiDetectDylib v23 - 直接修改dyld共享内存 + fishhook + ObjC
 *
 * 核心突破：直接修改 dyld_all_image_infos 结构体！
 *   - 结构体位于可写内存（堆/dyld的__DATA段）
 *   - 不涉及代码段修改，不受W^X限制
 *   - 不需要MSHookFunction，不需要inline hook
 *
 * 三层防御：
 *   Layer 1: 修改 dyld_all_image_infos（直接操作dyld共享内存，最底层）
 *   Layer 2: fishhook C函数（stat/access/fopen/opendir/dladdr）
 *   Layer 3: ObjC Hook（NSFileManager/NSBundle/UIApplication/弹窗拦截）
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

#pragma mark - Layer 1: 直接修改 dyld_all_image_infos

// 分配新的过滤后的infoArray（在堆上，可写）
static struct dyld_image_info *g_filtered_info_array = NULL;
static uint32_t g_filtered_count = 0;

// 分配新的过滤后的uuidArray
static struct dyld_uuid_info *g_filtered_uuid_array = NULL;
static uint32_t g_filtered_uuid_count = 0;

// 轮询线程
static volatile BOOL g_keep_polling = YES;

static void patch_dyld_image_infos() {
    // 获取 dyld_all_image_infos 结构体地址
    struct dyld_all_image_infos *infos = get_dyld_all_image_infos();
    if (!infos) {
        NSLog(@"[AntiDetect] _dyld_get_all_image_infos 返回NULL");
        return;
    }

    // 检查infoArray是否正在被dyld更新（为NULL表示正在更新）
    if (!infos->infoArray || infos->infoArrayCount == 0) {
        return;
    }

    // 只在第一次或count变化时重建过滤数组
    if (g_filtered_info_array && infos->infoArrayCount == g_filtered_count + /* 隐藏的数量 */ 0) {
        // infoArrayCount没变，可能已经修改过了，直接更新指针
        // 但我们要检查infoArray是否还是我们设置的那个
        if (infos->infoArray == g_filtered_info_array) {
            // 已经是我们的过滤数组，不需要重新修改
            return;
        }
    }

    // 构建过滤后的infoArray
    uint32_t orig_count = infos->infoArrayCount;
    const struct dyld_image_info *orig_array = infos->infoArray;

    // 统计需要隐藏的数量
    uint32_t hide_count = 0;
    for (uint32_t i = 0; i < orig_count; i++) {
        if (should_hide_dylib(orig_array[i].imageFilePath)) {
            hide_count++;
        }
    }

    if (hide_count == 0) {
        // 没有需要隐藏的
        return;
    }

    // 分配新数组（只分配一次，或者count变化时重新分配）
    uint32_t new_count = orig_count - hide_count;
    struct dyld_image_info *new_array = (struct dyld_image_info *)malloc(sizeof(struct dyld_image_info) * new_count);
    if (!new_array) return;

    // 复制非隐藏条目
    uint32_t j = 0;
    for (uint32_t i = 0; i < orig_count; i++) {
        if (!should_hide_dylib(orig_array[i].imageFilePath)) {
            new_array[j] = orig_array[i];
            j++;
        } else {
            NSLog(@"[AntiDetect] 隐藏dylib: %s", orig_array[i].imageFilePath);
        }
    }

    // 原子性地替换infoArray
    // 按照dyld的协议：先设infoArray为NULL，更新count，再设新指针
    infos->infoArray = NULL;
    infos->infoArrayCount = new_count;
    infos->infoArrayChangeTimestamp = mach_absolute_time();
    infos->infoArray = new_array;

    // 释放旧数组（如果是我们自己分配的）
    if (g_filtered_info_array && g_filtered_info_array != orig_array) {
        free(g_filtered_info_array);
    }

    g_filtered_info_array = new_array;
    g_filtered_count = new_count;

    // 同步修改uuidArray
    if (infos->uuidArray && infos->uuidArrayCount > 0) {
        uint32_t uuid_hide = 0;
        for (uint32_t i = 0; i < infos->uuidArrayCount; i++) {
            // uuidArray没有路径信息，无法精确过滤
            // 最安全的做法：将uuidArrayCount设为1（只保留主程序）
        }
        infos->uuidArrayCount = 1;
        g_filtered_uuid_count = 1;
    }

    NSLog(@"[AntiDetect] ★ dyld_all_image_infos已修改 ★ 原始:%d 隐藏:%d 当前:%d",
          orig_count, hide_count, new_count);
}

// 轮询线程：定期检查并重新应用修改
static void *polling_thread(void *arg) {
    NSLog(@"[AntiDetect] 轮询线程启动");
    while (g_keep_polling) {
        patch_dyld_image_infos();
        usleep(500000); // 每0.5秒检查一次
    }
    NSLog(@"[AntiDetect] 轮询线程退出");
    return NULL;
}

#pragma mark - Layer 2: fishhook C函数

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

#pragma mark - Layer 3: ObjC Hook

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

        NSLog(@"[AntiDetect] v23 初始化（三层防御 + dyld内存修改）...");

        // ===== Layer 3: ObjC Hook（constructor中立即执行）=====
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

        // ===== Layer 1: 修改dyld共享内存（constructor中立即执行，纯数据修改）=====
        // 在constructor中执行一次，然后启动轮询线程保持修改
        patch_dyld_image_infos();

        pthread_t thread;
        pthread_create(&thread, NULL, polling_thread, NULL);
        pthread_detach(thread);

        // ===== Layer 2: fishhook（延迟1秒）=====
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
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

            struct rebinding rebindings[] = {
                {"stat",    (void *)hook_stat,    (void **)&orig_stat},
                {"access",  (void *)hook_access,  (void **)&orig_access},
                {"fopen",   (void *)hook_fopen,   (void **)&orig_fopen},
                {"opendir", (void *)hook_opendir,  (void **)&orig_opendir},
                {"dladdr",  (void *)hook_dladdr,  (void **)&orig_dladdr},
            };

            int ret = rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
            NSLog(@"[AntiDetect] fishhook结果: %d stat=%p access=%p fopen=%p opendir=%p dladdr=%p",
                  ret, orig_stat, orig_access, orig_fopen, orig_opendir, orig_dladdr);
        });

        NSLog(@"[AntiDetect] v23 完成 - Layer1:dyld内存 + Layer2:fishhook + Layer3:ObjC");
    }
}
