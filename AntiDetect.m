#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <sys/sysctl.h>
#import <UIKit/UIKit.h>

/*
 * AntiDetectDylib - iOS 环境检测绕过
 * 已预配置：TrollFools + LIBTOOL + CydiaSubstrate 环境
 * 兼容 iOS 14.0 - 18.x
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

// 用 dlsym 获取原始函数，不依赖 fishhook 的 rebind
static uint32_t (*orig_dyld_image_count)(void) = NULL;
static const char *(*orig_dyld_get_image_name)(uint32_t) = NULL;
static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t) = NULL;
static intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t) = NULL;
static int (*orig_dladdr)(const void *, Dl_info *) = NULL;
static char *(*orig_getenv)(const char *) = NULL;
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;

static void load_orig_functions() {
    orig_dyld_image_count = dlsym(RTLD_DEFAULT, "_dyld_image_count");
    orig_dyld_get_image_name = dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
    orig_dyld_get_image_header = dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
    orig_dyld_get_image_vmaddr_slide = dlsym(RTLD_DEFAULT, "_dyld_get_image_vmaddr_slide");
    orig_dladdr = dlsym(RTLD_DEFAULT, "dladdr");
    orig_getenv = dlsym(RTLD_DEFAULT, "getenv");
    orig_sysctl = dlsym(RTLD_DEFAULT, "sysctl");
}

// 构建镜像映射表 - 使用原始函数（绕过 hook）
static ImageMap build_image_map() {
    ImageMap map = {0};
    uint32_t real_count = orig_dyld_image_count ? orig_dyld_image_count() : _dyld_image_count();
    map.real_count = (int)real_count;
    BOOL *hidden = (BOOL *)malloc(real_count * sizeof(BOOL));
    memset(hidden, 0, real_count * sizeof(BOOL));
    for (uint32_t i = 0; i < real_count; i++) {
        const char *name = orig_dyld_get_image_name ? orig_dyld_get_image_name(i) : _dyld_get_image_name(i);
        if (should_hide_image(name)) hidden[i] = YES;
    }
    map.visible_count = 0;
    for (int i = 0; i < map.real_count; i++) {
        if (!hidden[i]) map.visible_count++;
    }
    map.index_map = (int *)malloc(map.visible_count * sizeof(int));
    int vis_idx = 0;
    for (int i = 0; i < map.real_count; i++) {
        if (!hidden[i]) map.index_map[vis_idx++] = i;
    }
    free(hidden);
    return map;
}

static void free_image_map(ImageMap *map) {
    if (map->index_map) { free(map->index_map); map->index_map = NULL; }
}

#pragma mark - Hook: dyld 镜像枚举

static uint32_t hooked_dyld_image_count() {
    ImageMap map = build_image_map();
    uint32_t count = (uint32_t)map.visible_count;
    free_image_map(&map);
    return count;
}

static const char *hooked_dyld_get_image_name(uint32_t index) {
    ImageMap map = build_image_map();
    const char *result = NULL;
    if (index < (uint32_t)map.visible_count) {
        uint32_t real_idx = (uint32_t)map.index_map[index];
        result = orig_dyld_get_image_name ? orig_dyld_get_image_name(real_idx) : _dyld_get_image_name(real_idx);
    }
    free_image_map(&map);
    return result;
}

static const struct mach_header *hooked_dyld_get_image_header(uint32_t index) {
    ImageMap map = build_image_map();
    const struct mach_header *result = NULL;
    if (index < (uint32_t)map.visible_count) {
        uint32_t real_idx = (uint32_t)map.index_map[index];
        result = orig_dyld_get_image_header ? orig_dyld_get_image_header(real_idx) : _dyld_get_image_header(real_idx);
    }
    free_image_map(&map);
    return result;
}

static intptr_t hooked_dyld_get_image_vmaddr_slide(uint32_t index) {
    ImageMap map = build_image_map();
    intptr_t result = 0;
    if (index < (uint32_t)map.visible_count) {
        uint32_t real_idx = (uint32_t)map.index_map[index];
        result = orig_dyld_get_image_vmaddr_slide ? orig_dyld_get_image_vmaddr_slide(real_idx) : _dyld_get_image_vmaddr_slide(real_idx);
    }
    free_image_map(&map);
    return result;
}

#pragma mark - Hook: dladdr

static int hooked_dladdr(const void *addr, Dl_info *info) {
    if (!orig_dladdr) return dladdr(addr, info);
    int ret = orig_dladdr(addr, info);
    if (ret && info && info->dli_fname && should_hide_image(info->dli_fname)) {
        memset(info, 0, sizeof(Dl_info));
        return 0;
    }
    return ret;
}

#pragma mark - Hook: getenv

static char *hooked_getenv(const char *name) {
    if (name && (strstr(name, "DYLD_") == name || strstr(name, "MSSafeMode") || strstr(name, "_MSSafeMode") || strstr(name, "SUBSTRATE_HOME")))
        return NULL;
    return orig_getenv ? orig_getenv(name) : getenv(name);
}

#pragma mark - Hook: sysctl

static int hooked_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int result = orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : sysctl(name, namelen, oldp, oldlenp, newp, newlen);
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
static IMP orig_fileExistsAtPath_IMP = NULL;
static IMP orig_fileExistsAtPathIsDirectory_IMP = NULL;

static BOOL is_jailbreak_path(NSString *path) {
    if (!path) return NO;
    for (NSString *jp in g_jailbreak_paths) {
        if ([path hasPrefix:jp]) return YES;
    }
    return NO;
}

static BOOL hooked_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (is_jailbreak_path(path)) return NO;
    if (orig_fileExistsAtPath_IMP) {
        return ((BOOL(*)(id, SEL, NSString *))orig_fileExistsAtPath_IMP)(self, _cmd, path);
    }
    return NO;
}

static BOOL hooked_fileExistsAtPathIsDirectory(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (is_jailbreak_path(path)) { if (isDir) *isDir = NO; return NO; }
    if (orig_fileExistsAtPathIsDirectory_IMP) {
        return ((BOOL(*)(id, SEL, NSString *, BOOL *))orig_fileExistsAtPathIsDirectory_IMP)(self, _cmd, path, isDir);
    }
    return NO;
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

#pragma mark - fishhook (Facebook) 内嵌实现 - 全部使用显式 64 位类型
// 来源: https://github.com/facebook/fishhook
// BSD License - Copyright (c) Meta Platforms, Inc.
// 已将 section_t/nlist_t/segment_command_t 全部替换为显式的 _64 类型

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

typedef struct {
    const char *name;
    void *replacement;
    void **replaced;
} fh_rebinding_t;

static int fh_rebind_symbols(fh_rebinding_t rebindings[], size_t rebindings_nel);

struct fh_rebindings_entry {
    fh_rebinding_t *rebindings;
    size_t rebindings_nel;
    struct fh_rebindings_entry *next;
};

static struct fh_rebindings_entry *_fh_rebindings_head;

static int fh_prepend_rebindings(fh_rebinding_t rebindings[], size_t nel) {
    struct fh_rebindings_entry *new_entry =
        (struct fh_rebindings_entry *)malloc(sizeof(struct fh_rebindings_entry));
    if (!new_entry) return -1;
    new_entry->rebindings = rebindings;
    new_entry->rebindings_nel = nel;
    new_entry->next = _fh_rebindings_head;
    _fh_rebindings_head = new_entry;
    return 0;
}

static void fh_perform_rebinding_with_section(struct fh_rebindings_entry *rebindings,
                                              struct section_64 *section,
                                              intptr_t slide,
                                              struct nlist_64 *symtab,
                                              char *strtab,
                                              uint32_t *indirect_symtab) {
    uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
    void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);
    for (uint i = 0; i < section->size / sizeof(void *); i++) {
        uint32_t symtab_index = indirect_symbol_indices[i];
        if (symtab_index == INDIRECT_SYMBOL_ABS ||
            symtab_index == INDIRECT_SYMBOL_LOCAL ||
            symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) {
            continue;
        }
        uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
        char *symbol_name = strtab + strtab_offset;
        bool symbol_name_longer_than_1 = symbol_name[0] && symbol_name[1];
        struct fh_rebindings_entry *cur = rebindings;
        while (cur) {
            for (uint j = 0; j < cur->rebindings_nel; j++) {
                if (symbol_name_longer_than_1 &&
                    strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
                    if (cur->rebindings[j].replaced != NULL &&
                        indirect_symbol_bindings[i] != cur->rebindings[j].replacement) {
                        *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
                    }
                    indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
                    goto symbol_loop;
                }
            }
            cur = cur->next;
        }
    symbol_loop:;
    }
}

static void fh_rebind_symbols_for_image(struct fh_rebindings_entry *rebindings,
                                         const struct mach_header *header,
                                         intptr_t slide) {
    Dl_info info;
    if (dladdr(header, &info) == 0) return;

    struct segment_command_64 *cur_seg_cmd;
    struct segment_command_64 *linkedit_segment = NULL;
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;

    uintptr_t cur = (uintptr_t)header + sizeof(struct mach_header_64);
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (struct segment_command_64 *)cur;
        if (cur_seg_cmd->cmd == LC_SEGMENT_64) {
            if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
                linkedit_segment = cur_seg_cmd;
            }
        } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cur_seg_cmd;
        } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (struct dysymtab_command *)cur_seg_cmd;
        }
    }

    if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment) return;

    uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr;
    struct nlist_64 *symtab = (struct nlist_64 *)(linkedit_base + symtab_cmd->symoff);
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

    cur = (uintptr_t)header + sizeof(struct mach_header_64);
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (struct segment_command_64 *)cur;
        if (cur_seg_cmd->cmd != LC_SEGMENT_64) continue;
        if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
            strcmp(cur_seg_cmd->segname, "__DATA_CONST") != 0) continue;
        for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
            struct section_64 *sect =
                (struct section_64 *)((uintptr_t)cur_seg_cmd + sizeof(struct segment_command_64)) + j;
            if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
                fh_perform_rebinding_with_section(rebindings, sect, slide,
                                                   symtab, strtab, indirect_symtab);
            }
            if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
                fh_perform_rebinding_with_section(rebindings, sect, slide,
                                                   symtab, strtab, indirect_symtab);
            }
        }
    }
}

static void _fh_rebind_symbols_for_image(const struct mach_header *header,
                                          intptr_t slide) {
    fh_rebind_symbols_for_image(_fh_rebindings_head, header, slide);
}

static int fh_rebind_symbols(fh_rebinding_t rebindings[], size_t rebindings_nel) {
    int retval = fh_prepend_rebindings(rebindings, rebindings_nel);
    if (retval < 0) return retval;

    if (_fh_rebindings_head->next == NULL) {
        _dyld_register_func_for_add_image(_fh_rebind_symbols_for_image);
    } else {
        uint32_t c = _dyld_image_count();
        for (uint32_t i = 0; i < c; i++) {
            fh_rebind_symbols_for_image(_fh_rebindings_head,
                                         _dyld_get_image_header(i),
                                         _dyld_get_image_vmaddr_slide(i));
        }
    }
    return retval;
}

#pragma mark - 入口点

__attribute__((constructor))
static void AntiDetectInit() {
    // 先加载原始函数指针（用 dlsym 作为 fallback）
    load_orig_functions();

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

    // 使用 fishhook rebind 符号（覆盖 dlsym 获取的指针）
    fh_rebinding_t rebindings[] = {
        {"_dyld_image_count", hooked_dyld_image_count, (void **)&orig_dyld_image_count},
        {"_dyld_get_image_name", hooked_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
        {"_dyld_get_image_header", hooked_dyld_get_image_header, (void **)&orig_dyld_get_image_header},
        {"_dyld_get_image_vmaddr_slide", hooked_dyld_get_image_vmaddr_slide, (void **)&orig_dyld_get_image_vmaddr_slide},
        {"dladdr", hooked_dladdr, (void **)&orig_dladdr},
        {"getenv", hooked_getenv, (void **)&orig_getenv},
        {"sysctl", hooked_sysctl, (void **)&orig_sysctl},
    };
    fh_rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));

    // ObjC Method Swizzling
    Class fmClass = objc_getClass("NSFileManager");
    if (fmClass) {
        Method m1 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:));
        if (m1) {
            orig_fileExistsAtPath_IMP = method_getImplementation(m1);
            method_setImplementation(m1, (IMP)hooked_fileExistsAtPath);
        }
        Method m2 = class_getInstanceMethod(fmClass, @selector(fileExistsAtPath:isDirectory:));
        if (m2) {
            orig_fileExistsAtPathIsDirectory_IMP = method_getImplementation(m2);
            method_setImplementation(m2, (IMP)hooked_fileExistsAtPathIsDirectory);
        }
    }

    Class appClass = objc_getClass("UIApplication");
    if (appClass) {
        Method m = class_getInstanceMethod(appClass, @selector(canOpenURL:));
        if (m) {
            orig_canOpenURL = (void *)method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_canOpenURL);
        }
    }

    NSLog(@"[AntiDetect] 初始化完成 - 隐藏关键字: %@", g_hidden_keywords);
}
