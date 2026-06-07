#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <sys/sysctl.h>
#import <UIKit/UIKit.h>

/*
 * AntiDetectDylib - iOS 环境检测绕过
 * 已预配置：TrollFools + LIBTOOL + CydiaSubstrate 环境
 * ⚠️ 此 dylib 必须是注入列表中【最后一个】加载的
 */

#pragma mark - 配置

static NSArray *g_hidden_keywords = nil;
static NSArray *g_system_prefixes = nil;

static void init_config() {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
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
        g_system_prefixes = @[
            @"/System/",
            @"/usr/lib/",
            @"/Developer/",
            @"/AppleInternal/",
        ];
    });
}

#pragma mark - 工具函数

static BOOL should_hide_image(const char *name) {
    if (!name) return NO;
    for (NSString *prefix in g_system_prefixes) {
        if (strstr(name, [prefix UTF8String]) == name) return NO;
    }
    NSString *nameStr = [NSString stringWithUTF8String:name].lowercaseString;
    for (NSString *keyword in g_hidden_keywords) {
        if ([nameStr containsString:keyword.lowercaseString]) return YES;
    }
    return NO;
}

typedef struct {
    int real_count;
    int visible_count;
    int *index_map;
} ImageMap;

static ImageMap build_image_map() {
    ImageMap map = {0};
    int real_count = (int)_dyld_image_count();
    map.real_count = real_count;
    BOOL *hidden = (BOOL *)malloc(real_count * sizeof(BOOL));
    memset(hidden, 0, real_count * sizeof(BOOL));
    for (int i = 0; i < real_count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (should_hide_image(name)) hidden[i] = YES;
    }
    map.visible_count = 0;
    for (int i = 0; i < real_count; i++) {
        if (!hidden[i]) map.visible_count++;
    }
    map.index_map = (int *)malloc(map.visible_count * sizeof(int));
    int vis_idx = 0;
    for (int i = 0; i < real_count; i++) {
        if (!hidden[i]) map.index_map[vis_idx++] = i;
    }
    free(hidden);
    return map;
}

static void free_image_map(ImageMap *map) {
    if (map->index_map) { free(map->index_map); map->index_map = NULL; }
}

#pragma mark - Hook: dyld 镜像枚举

static uint32_t (*orig_dyld_image_count)(void) = NULL;
static const char *(*orig_dyld_get_image_name)(uint32_t) = NULL;
static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t) = NULL;
static intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t) = NULL;

static uint32_t hooked_dyld_image_count() {
    ImageMap map = build_image_map();
    uint32_t count = (uint32_t)map.visible_count;
    free_image_map(&map);
    return count;
}

static const char *hooked_dyld_get_image_name(uint32_t index) {
    ImageMap map = build_image_map();
    const char *result = NULL;
    if (index < (uint32_t)map.visible_count)
        result = _dyld_get_image_name(map.index_map[index]);
    free_image_map(&map);
    return result;
}

static const struct mach_header *hooked_dyld_get_image_header(uint32_t index) {
    ImageMap map = build_image_map();
    const struct mach_header *result = NULL;
    if (index < (uint32_t)map.visible_count)
        result = _dyld_get_image_header(map.index_map[index]);
    free_image_map(&map);
    return result;
}

static intptr_t hooked_dyld_get_image_vmaddr_slide(uint32_t index) {
    ImageMap map = build_image_map();
    intptr_t result = 0;
    if (index < (uint32_t)map.visible_count)
        result = _dyld_get_image_vmaddr_slide(map.index_map[index]);
    free_image_map(&map);
    return result;
}

#pragma mark - Hook: dladdr

typedef struct { const char *dli_fname; void *dli_fbase; const char *dli_sname; void *dli_saddr; } Dl_info_type;
static int (*orig_dladdr)(const void *, Dl_info_type *) = NULL;

static int hooked_dladdr(const void *addr, Dl_info_type *info) {
    int ret = orig_dladdr(addr, info);
    if (ret && info && info->dli_fname && should_hide_image(info->dli_fname)) {
        memset(info, 0, sizeof(Dl_info_type));
        return 0;
    }
    return ret;
}

#pragma mark - Hook: getenv

static char *(*orig_getenv)(const char *) = NULL;

static char *hooked_getenv(const char *name) {
    if (name && (strstr(name, "DYLD_") == name || strstr(name, "MSSafeMode") || strstr(name, "_MSSafeMode") || strstr(name, "SUBSTRATE_HOME")))
        return NULL;
    return orig_getenv(name);
}

#pragma mark - Hook: sysctl

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;

static int hooked_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int result = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        if (oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
            struct kinfo_proc *info = (struct kinfo_proc *)oldp;
            info->kp_proc.p_flag &= ~P_TRACED;
        }
    }
    return result;
}

#pragma mark - Hook: NSFileManager

static NSArray *g_jailbreak_paths = nil;
static BOOL (*orig_fileExistsAtPath)(id, SEL, NSString *) = NULL;
static BOOL (*orig_fileExistsAtPathIsDirectory)(id, SEL, NSString *, BOOL *) = NULL;

static BOOL is_jailbreak_path(NSString *path) {
    if (!path) return NO;
    for (NSString *jp in g_jailbreak_paths) {
        if ([path hasPrefix:jp]) return YES;
    }
    return NO;
}

static BOOL hooked_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (is_jailbreak_path(path)) return NO;
    return orig_fileExistsAtPath(self, _cmd, path);
}

static BOOL hooked_fileExistsAtPathIsDirectory(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (is_jailbreak_path(path)) { if (isDir) *isDir = NO; return NO; }
    return orig_fileExistsAtPathIsDirectory(self, _cmd, path, isDir);
}

#pragma mark - Hook: canOpenURL

static BOOL (*orig_canOpenURL)(id, SEL, NSURL *) = NULL;

static BOOL hooked_canOpenURL(id self, SEL _cmd, NSURL *url) {
    NSString *scheme = [url scheme];
    NSArray *blocked = @[@"cydia", @"sileo", @"zebra", @"unc0ver", @"taurine"];
    for (NSString *bs in blocked) {
        if ([scheme isEqualToString:bs]) return NO;
    }
    return orig_canOpenURL(self, _cmd, url);
}

#pragma mark - fishhook 风格 rebind 实现

typedef struct { const char *name; void *replacement; void **original; } Rebinding;
static Rebinding g_rebindings[32];
static int g_rebinding_count = 0;

static void add_rebinding(const char *name, void *replacement, void **original) {
    if (g_rebinding_count >= 32) return;
    g_rebindings[g_rebinding_count++] = (Rebinding){name, replacement, original};
}

static void rebind_symbols_for_image(struct mach_header_64 *header, intptr_t slide) {
    uint8_t *base = (uint8_t *)header;
    struct segment_command_64 *linkedit_seg = NULL;
    struct dysymtab_command *dysymtab = NULL;

    struct load_command *cmd = (struct load_command *)(base + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
            if (strcmp(seg->segname, "__LINKEDIT") == 0) linkedit_seg = seg;
        } else if (cmd->cmd == LC_DYSYMTAB) {
            dysymtab = (struct dysymtab_command *)cmd;
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }
    if (!linkedit_seg || !dysymtab) return;

    uintptr_t linkedit_base = slide + linkedit_seg->vmaddr;
    const char *strtab = (const char *)(linkedit_base + dysymtab->strtaboff - linkedit_seg->fileoff);
    struct nlist_64 *symtab = (struct nlist_64 *)(linkedit_base + dysymtab->symoff - linkedit_seg->fileoff);

    cmd = (struct load_command *)(base + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
            struct section_64 *sect = (struct section_64 *)((uint8_t *)seg + sizeof(struct segment_command_64));
            for (uint32_t j = 0; j < seg->nsects; j++) {
                if (strcmp(sect->sectname, "__la_symbol_ptr") == 0 || strcmp(sect->sectname, "__nl_symbol_ptr") == 0) {
                    uint32_t *indirect_sym = (uint32_t *)(linkedit_base + dysymtab->indirectsymoff - linkedit_seg->fileoff);
                    void **symbol_ptr = (void **)(slide + sect->addr);
                    for (uint32_t k = 0; k < sect->size / sizeof(void *); k++) {
                        uint32_t sym_idx = indirect_sym[sect->reserved1 + k];
                        if (sym_idx == INDIRECT_SYMBOL_ABS || sym_idx == INDIRECT_SYMBOL_LOCAL) continue;
                        const char *sym_name = strtab + symtab[sym_idx].n_un.n_strx;
                        for (int r = 0; r < g_rebinding_count; r++) {
                            if (strcmp(sym_name + 1, g_rebindings[r].name) == 0) {
                                if (g_rebindings[r].original) *(g_rebindings[r].original) = symbol_ptr[k];
                                symbol_ptr[k] = g_rebindings[r].replacement;
                            }
                        }
                    }
                }
                sect++;
            }
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }
}

static void rebind_all_symbols() {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (strstr(name, "/Application/") || strstr(name, "/var/containers/")) {
            rebind_symbols_for_image((struct mach_header_64 *)_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
        }
    }
}

#pragma mark - 入口点

__attribute__((constructor))
static void AntiDetectInit() {
    init_config();

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
        @"/usr/sbin/sshd",
        @"/usr/bin/sshd",
        @"/bin/bash",
        @"/bin/sh",
        @"/usr/bin/ssh",
        @"/.bootstrapped_evas1on",
        @"/.cydia_no_stash",
        @"/.installed_unc0ver",
        @"/var/jb",
        @"/private/var/jb",
        @"/var/containers/Bundle/Application/",
        @"/var/mobile/Containers/Data/Application/",
    ];

    add_rebinding("_dyld_image_count", hooked_dyld_image_count, (void **)&orig_dyld_image_count);
    add_rebinding("_dyld_get_image_name", hooked_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    add_rebinding("_dyld_get_image_header", hooked_dyld_get_image_header, (void **)&orig_dyld_get_image_header);
    add_rebinding("_dyld_get_image_vmaddr_slide", hooked_dyld_get_image_vmaddr_slide, (void **)&orig_dyld_get_image_vmaddr_slide);
    add_rebinding("dladdr", hooked_dladdr, (void **)&orig_dladdr);
    add_rebinding("getenv", hooked_getenv, (void **)&orig_getenv);
    add_rebinding("sysctl", hooked_sysctl, (void **)&orig_sysctl);

    rebind_all_symbols();

    Class fmClass = objc_getClass("NSFileManager");
    if (fmClass) {
        orig_fileExistsAtPath = (void *)class_replaceMethod(fmClass, @selector(fileExistsAtPath:), (IMP)hooked_fileExistsAtPath, "B@:@");
        orig_fileExistsAtPathIsDirectory = (void *)class_replaceMethod(fmClass, @selector(fileExistsAtPath:isDirectory:), (IMP)hooked_fileExistsAtPathIsDirectory, "B@:@^B");
    }

    Class appClass = objc_getClass("UIApplication");
    if (appClass) {
        Method m = class_getInstanceMethod(appClass, @selector(canOpenURL:));
        if (m) { orig_canOpenURL = (void *)method_getImplementation(m); method_setImplementation(m, (IMP)hooked_canOpenURL); }
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        NSLog(@"[AntiDetect] 初始化完成 - 隐藏关键字: %@", g_hidden_keywords);
        uint32_t count = _dyld_image_count();
        NSLog(@"[AntiDetect] 可见镜像数量: %u", count);
        for (uint32_t i = 0; i < count; i++) NSLog(@"[AntiDetect]   [%u] %s", i, _dyld_get_image_name(i));
    });
}
