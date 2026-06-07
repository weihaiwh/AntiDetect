#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <UIKit/UIKit.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <dirent.h>
#import <stdio.h>

/*
 * AntiDetectDylib v12 - 使用CydiaSubstrate MSHookFunction
 *
 * 关键发现：Shadow插件在越狱设备上用CydiaSubstrate的MSHookFunction hook C函数
 * TrollFools注入环境已有CydiaSubstrate.framework，可以直接使用！
 * 之前v1-v8用fishhook闪退是因为fishhook的符号表重绑定机制在TrollStore下不兼容
 * MSHookFunction使用inline hook（直接修改函数入口指令），完全不同的机制
 *
 * 覆盖Shadow的所有检测维度：
 *   1. 文件系统 → hook stat/access/fopen/opendir
 *   2. 动态库   → hook _dyld_image_count/_dyld_get_image_name/dladdr
 *   3. URL处理   → ObjC hook canOpenURL
 *   4. 环境变量 → hook getenv
 *   5. 检测框架 → 隐藏CydiaSubstrate等
 *   6. Foundation → ObjC hook NSFileManager
 *   7. M1 Mac伪装 → hook sysctl
 */

#pragma mark - CydiaSubstrate MSHookFunction 声明

// 方式1：直接extern声明（需要链接-lCydiaSubstrate）
// 方式2：运行时dlsym查找（更安全，不依赖链接时符号可用）

typedef void (*MSHookFunction_t)(void *symbol, void *replace, void **result);

static MSHookFunction_t g_MSHookFunction = NULL;

static BOOL load_MSHookFunction() {
    if (g_MSHookFunction) return YES;

    // 优先用dlsym在RTLD_DEFAULT中查找
    g_MSHookFunction = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (g_MSHookFunction) {
        NSLog(@"[AntiDetect] MSHookFunction 通过 dlsym(RTLD_DEFAULT) 加载成功");
        return YES;
    }

    // 尝试显式加载CydiaSubstrate
    void *handle = dlopen("CydiaSubstrate", RTLD_LAZY);
    if (!handle) handle = dlopen("@executable_path/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_LAZY);
    if (handle) {
        g_MSHookFunction = (MSHookFunction_t)dlsym(handle, "MSHookFunction");
        if (g_MSHookFunction) {
            NSLog(@"[AntiDetect] MSHookFunction 通过 dlopen 加载成功");
            return YES;
        }
    }

    NSLog(@"[AntiDetect] ❌ MSHookFunction 加载失败！CydiaSubstrate不可用");
    return NO;
}

// 安全的hook宏
#define SAFE_HOOK(func, replace, orig) do { \
    if (g_MSHookFunction) { \
        g_MSHookFunction((void *)func, (void *)replace, (void **)orig); \
        NSLog(@"[AntiDetect] Hooked %s", #func); \
    } else { \
        NSLog(@"[AntiDetect] ⚠️ Skip hook %s (MSHookFunction unavailable)", #func); \
    } \
} while(0)

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
        // 动态库文件名中要隐藏的关键词
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

static BOOL is_jailbreak_path(const char *path) {
    if (!path) return NO;
    NSString *nsPath = [NSString stringWithUTF8String:path];
    for (NSString *jp in g_jailbreak_paths) {
        if ([nsPath hasPrefix:jp]) return YES;
    }
    return NO;
}

static BOOL is_jailbreak_path_ns(NSString *path) {
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
    return is_jailbreak_path_ns(path) || contains_hidden_keyword(path);
}

static BOOL should_hide_dylib(const char *name) {
    if (!name) return NO;
    NSString *nsName = [NSString stringWithUTF8String:name].lowercaseString;
    for (NSString *kw in g_hidden_dylib_keywords) {
        if ([nsName containsString:kw.lowercaseString]) return YES;
    }
    return NO;
}

#pragma mark - 1. 文件系统 Hook (stat/access/fopen/opendir)

static int (*orig_stat)(const char *restrict, struct stat *restrict);
static int (*orig_access)(const char *, int);
static FILE *(*orig_fopen)(const char *, const char *);
static DIR *(*orig_opendir)(const char *);
static int (*orig_lstat)(const char *restrict, struct stat *restrict);

static int hook_stat(const char *restrict path, struct stat *restrict buf) {
    if (is_jailbreak_path(path)) {
        return -1; // 文件不存在
    }
    return orig_stat(path, buf);
}

static int hook_lstat(const char *restrict path, struct stat *restrict buf) {
    if (is_jailbreak_path(path)) {
        return -1;
    }
    return orig_lstat(path, buf);
}

static int hook_access(const char *path, int mode) {
    if (is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_access(path, mode);
}

static FILE *hook_fopen(const char *path, const char *mode) {
    if (is_jailbreak_path(path)) {
        return NULL;
    }
    return orig_fopen(path, mode);
}

static DIR *hook_opendir(const char *path) {
    if (is_jailbreak_path(path)) {
        return NULL;
    }
    return orig_opendir(path);
}

#pragma mark - 2. 动态库 Hook (_dyld_image_count/_dyld_get_image_name/dladdr)

// 动态库隐藏策略：让注入的dylib在dyld枚举中不可见
// 不hook _dyld_image_count（避免递归问题）
// 只hook _dyld_get_image_name 和 dladdr

static const char *(*orig_dyld_get_image_name)(uint32_t);
static int (*orig_dladdr)(const void *, Dl_info *);

// 记录需要隐藏的image索引
static int32_t g_hidden_image_count = 0;
static int32_t *g_hidden_image_indices = NULL;
static BOOL g_image_map_built = NO;

static void build_hidden_image_map() {
    if (g_image_map_built) return;

    uint32_t count = _dyld_image_count();
    int32_t *hidden = (int32_t *)malloc(count * sizeof(int32_t));
    int32_t hcount = 0;

    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (should_hide_dylib(name)) {
            hidden[hcount++] = (int32_t)i;
        }
    }

    g_hidden_image_indices = (int32_t *)malloc(hcount * sizeof(int32_t));
    memcpy(g_hidden_image_indices, hidden, hcount * sizeof(int32_t));
    g_hidden_image_count = hcount;
    free(hidden);
    g_image_map_built = YES;

    NSLog(@"[AntiDetect] 隐藏了 %d 个动态库", hcount);
}

static BOOL is_hidden_image_index(uint32_t index) {
    for (int32_t i = 0; i < g_hidden_image_count; i++) {
        if (g_hidden_image_indices[i] == (int32_t)index) return YES;
    }
    return NO;
}

static const char *hook_dyld_get_image_name(uint32_t index) {
    if (is_hidden_image_index(index)) {
        return ""; // 返回空字符串
    }
    return orig_dyld_get_image_name(index);
}

static int hook_dladdr(const void *addr, Dl_info *info) {
    int ret = orig_dladdr(addr, info);
    if (ret && info && info->dli_fname) {
        if (should_hide_dylib(info->dli_fname)) {
            memset(info, 0, sizeof(Dl_info));
            return 0;
        }
    }
    return ret;
}

#pragma mark - 3. 环境变量 Hook (getenv)

static char *(*orig_getenv)(const char *);

static char *hook_getenv(const char *name) {
    if (name) {
        // 隐藏DYLD相关环境变量
        if (strstr(name, "DYLD_") == name) return NULL;
        // 隐藏Substrate相关
        if (strstr(name, "MSSafeMode") || strstr(name, "_MSSafeMode") ||
            strstr(name, "SUBSTRATE_HOME")) return NULL;
    }
    return orig_getenv(name);
}

#pragma mark - 4. M1 Mac伪装 / sysctl Hook

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);

static int hook_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int result = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);

    // 清除P_TRACED标志（反调试检测）
    if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC &&
        name[2] == KERN_PROC_PID) {
        if (oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
            struct kinfo_proc *info = (struct kinfo_proc *)oldp;
            info->kp_proc.p_flag &= ~P_TRACED;
        }
    }

    // KERN_SYSNAME: 伪装为iPhone而非Mac
    if (namelen == 2 && name[0] == CTL_KERN && name[1] == KERN_SYSNAME) {
        if (oldp && oldlenp) {
            const char *iphone = "iPhoneOS";
            size_t len = strlen(iphone) + 1;
            if (*oldlenp >= len) {
                memcpy(oldp, iphone, len);
                *oldlenp = len;
            }
        }
    }

    // KERN_OSTYPE: 伪装
    if (namelen == 2 && name[0] == CTL_KERN && name[1] == KERN_OSTYPE) {
        if (oldp && oldlenp) {
            const char *os = "Darwin";
            size_t len = strlen(os) + 1;
            if (*oldlenp >= len) {
                memcpy(oldp, os, len);
                *oldlenp = len;
            }
        }
    }

    return result;
}

#pragma mark - 5. ObjC层 Hook (NSFileManager/canOpenURL/UIAlertController)

static IMP orig_fileExistsAtPath_IMP = NULL;
static IMP orig_fileExistsAtPathIsDir_IMP = NULL;
static IMP orig_contentsOfDirectoryAtPath_IMP = NULL;
static IMP orig_canOpenURL_IMP = NULL;
static IMP orig_presentViewController_IMP = NULL;

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
        NSString *msg = alert.message ?: @"";
        NSString *title = alert.title ?: @"";
        NSString *combined = [NSString stringWithFormat:@"%@%@", title, msg];
        if ([combined containsString:@"环境异常"] ||
            [combined containsString:@"800180933"] ||
            [combined containsString:@"QQ公众号"]) {
            NSLog(@"[AntiDetect] 拦截环境异常弹窗: title=%@ msg=%@", title, msg);
            return;
        }
    }
    ((void(*)(id, SEL, UIViewController *, BOOL, id))orig_presentViewController_IMP)(self, _cmd, vc, animated, completion);
}

#pragma mark - NSUserDefaults清理

static void clean_anticheat_defaults() {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSDictionary *dict = [defaults dictionaryRepresentation];
    NSMutableArray *keysToRemove = [NSMutableArray array];
    for (NSString *key in dict) {
        NSString *lower = key.lowercaseString;
        if ([lower containsString:@"htp"] || [lower containsString:@"ntes"] ||
            [lower containsString:@"anticheat"] || [lower containsString:@"risksec"]) {
            [keysToRemove addObject:key];
        }
    }
    for (NSString *key in keysToRemove) {
        [defaults removeObjectForKey:key];
    }
    if (keysToRemove.count > 0) [defaults synchronize];
}

#pragma mark - il2cpp Runtime (简化版，仅关键操作)

typedef void* (*il2cpp_domain_get_t)(void);
typedef void* (*il2cpp_domain_get_assemblies_t)(void* domain, size_t* size);
typedef void* (*il2cpp_assembly_get_image_t)(void* assembly);
typedef void* (*il2cpp_class_from_name_t)(void* image, const char* ns, const char* name);
typedef void* (*il2cpp_class_get_field_from_name_t)(void* klass, const char* name);
typedef void  (*il2cpp_field_static_set_value_t)(void* field, void* value);

static il2cpp_domain_get_t                 p_il2cpp_domain_get = NULL;
static il2cpp_domain_get_assemblies_t      p_il2cpp_domain_get_assemblies = NULL;
static il2cpp_assembly_get_image_t         p_il2cpp_assembly_get_image = NULL;
static il2cpp_class_from_name_t           p_il2cpp_class_from_name = NULL;
static il2cpp_class_get_field_from_name_t p_il2cpp_class_get_field_from_name = NULL;
static il2cpp_field_static_set_value_t    p_il2cpp_field_static_set_value = NULL;

static void load_il2cpp_api() {
    p_il2cpp_domain_get = (il2cpp_domain_get_t)dlsym(RTLD_DEFAULT, "il2cpp_domain_get");
    p_il2cpp_domain_get_assemblies = (il2cpp_domain_get_assemblies_t)dlsym(RTLD_DEFAULT, "il2cpp_domain_get_assemblies");
    p_il2cpp_assembly_get_image = (il2cpp_assembly_get_image_t)dlsym(RTLD_DEFAULT, "il2cpp_assembly_get_image");
    p_il2cpp_class_from_name = (il2cpp_class_from_name_t)dlsym(RTLD_DEFAULT, "il2cpp_class_from_name");
    p_il2cpp_class_get_field_from_name = (il2cpp_class_get_field_from_name_t)dlsym(RTLD_DEFAULT, "il2cpp_class_get_field_from_name");
    p_il2cpp_field_static_set_value = (il2cpp_field_static_set_value_t)dlsym(RTLD_DEFAULT, "il2cpp_field_static_set_value");
}

static void patch_netease_il2cpp() {
    if (!p_il2cpp_domain_get || !p_il2cpp_class_from_name) return;

    void *domain = p_il2cpp_domain_get();
    if (!domain) return;

    size_t count = 0;
    void **assemblies = (void **)p_il2cpp_domain_get_assemblies(domain, &count);
    if (!assemblies) return;

    for (size_t i = 0; i < count; i++) {
        void *image = p_il2cpp_assembly_get_image(assemblies[i]);
        if (!image) continue;

        // 修改NetEaseRuntime的NetEaseEnable
        void *neRuntime = p_il2cpp_class_from_name(image, "Main.Runtime", "NetEaseRuntime");
        if (neRuntime && p_il2cpp_class_get_field_from_name && p_il2cpp_field_static_set_value) {
            void *enableField = p_il2cpp_class_get_field_from_name(neRuntime, "NetEaseEnable");
            if (enableField) {
                int32_t val = 1;
                p_il2cpp_field_static_set_value(enableField, &val);
                NSLog(@"[AntiDetect] il2cpp: NetEaseEnable=1");
            }
        }
    }
}

#pragma mark - 入口点

__attribute__((constructor))
static void AntiDetectInit() {
    @autoreleasepool {
        init_config();

        NSLog(@"[AntiDetect] v12 初始化开始...");

        // ========== 加载 MSHookFunction ==========
        BOOL msAvailable = load_MSHookFunction();

        if (msAvailable) {
            // ========== C函数Hook (使用MSHookFunction) ==========

            // 1. 文件系统Hook (对应Shadow的"文件系统"开关)
            SAFE_HOOK(stat, hook_stat, &orig_stat);
            SAFE_HOOK(lstat, hook_lstat, &orig_lstat);
            SAFE_HOOK(access, hook_access, &orig_access);
            SAFE_HOOK(fopen, hook_fopen, &orig_fopen);
            SAFE_HOOK(opendir, hook_opendir, &orig_opendir);

            // 2. 动态库Hook (对应Shadow的"动态库"开关)
            // 先构建隐藏映射表
            build_hidden_image_map();
            SAFE_HOOK(_dyld_get_image_name, hook_dyld_get_image_name, &orig_dyld_get_image_name);
            SAFE_HOOK(dladdr, hook_dladdr, &orig_dladdr);

            // 3. 环境变量Hook (对应Shadow的"环境变量"开关)
            SAFE_HOOK(getenv, hook_getenv, &orig_getenv);

            // 4. sysctl Hook (对应Shadow的"M1 Mac伪装"开关 + 反调试)
            SAFE_HOOK(sysctl, hook_sysctl, &orig_sysctl);

            NSLog(@"[AntiDetect] C函数Hook全部完成 (stat/access/fopen/opendir/dyld/dladdr/getenv/sysctl)");
        } else {
            NSLog(@"[AntiDetect] ⚠️ MSHookFunction不可用，仅使用ObjC Hook");
        }

        // ========== ObjC Hook (一直稳定) ==========

        // 5. NSFileManager (对应Shadow的"Foundation框架"开关)
        Class fmClass = objc_getClass("NSFileManager");
        if (fmClass) {
            Method m1 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:));
            if (m1) { orig_fileExistsAtPath_IMP = method_getImplementation(m1); method_setImplementation(m1, (IMP)hooked_fileExistsAtPath); }
            Method m2 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:isDirectory:));
            if (m2) { orig_fileExistsAtPathIsDir_IMP = method_getImplementation(m2); method_setImplementation(m2, (IMP)hooked_fileExistsAtPathIsDir); }
            Method m3 = class_getInstanceMethod(fmClass, @selector(contentsOfDirectoryAtPath:error:));
            if (m3) { orig_contentsOfDirectoryAtPath_IMP = method_getImplementation(m3); method_setImplementation(m3, (IMP)hooked_contentsOfDirectoryAtPath); }
        }

        // 6. canOpenURL (对应Shadow的"URL处理"开关)
        Class appClass = objc_getClass("UIApplication");
        if (appClass) {
            Method m = class_getInstanceMethod(appClass, @selector(canOpenURL:));
            if (m) { orig_canOpenURL_IMP = method_getImplementation(m); method_setImplementation(m, (IMP)hooked_canOpenURL); }
        }

        // 7. UIAlertController拦截
        Class vcClass = objc_getClass("UIViewController");
        if (vcClass) {
            Method m = class_getInstanceMethod(vcClass, @selector(presentViewController:animated:completion:));
            if (m) { orig_presentViewController_IMP = method_getImplementation(m); method_setImplementation(m, (IMP)hooked_presentViewController); }
        }

        // 8. NSUserDefaults清理
        clean_anticheat_defaults();

        // 9. il2cpp patch (延迟执行)
        load_il2cpp_api();
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            patch_netease_il2cpp();
        });

        NSLog(@"[AntiDetect] v12 初始化完成！覆盖维度：文件系统/动态库/URL处理/环境变量/检测框架/Foundation/sysctl");
    }
}
