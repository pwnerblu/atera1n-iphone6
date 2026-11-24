#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static const char *target_vars[] = {
    "com.apple.System.sep.art",
    "com.apple.System.boot-nonce",
};
#define NUM_TARGETS (sizeof(target_vars) / sizeof(target_vars[0]))

#define PERM_KERNEL_ONLY 3
#define PERM_ROOT_ONLY   0

struct mach_header_64 {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

struct segment_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

static uint64_t find_text_vmaddr(const uint8_t *buf, size_t size) {
    if (size < sizeof(struct mach_header_64)) return 0;
    const struct mach_header_64 *hdr = (const struct mach_header_64 *)buf;
    if (hdr->magic != 0xFEEDFACF) return 0;

    size_t off = sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < hdr->ncmds && off + 8 <= size; i++) {
        uint32_t cmd = *(uint32_t *)(buf + off);
        uint32_t cmdsize = *(uint32_t *)(buf + off + 4);
        if (cmd == 0x19 && off + sizeof(struct segment_command_64) <= size) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)(buf + off);
            if (memcmp(seg->segname, "__TEXT", 6) == 0 && seg->segname[6] == '\0')
                return seg->vmaddr;
        }
        off += cmdsize;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_kernel> <output_kernel>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("open input"); return 1; }
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(size);
    if (!buf) { perror("malloc"); return 1; }
    if (fread(buf, 1, size, f) != size) { perror("read"); return 1; }
    fclose(f);

    uint64_t text_vmaddr = find_text_vmaddr(buf, size);
    if (!text_vmaddr) {
        fprintf(stderr, "Error: not a valid arm64 Mach-O kernel\n");
        return 1;
    }
    printf("__TEXT vmaddr: 0x%llx\n", (unsigned long long)text_vmaddr);

    int patched = 0;

    for (int t = 0; t < NUM_TARGETS; t++) {
        const char *varname = target_vars[t];
        size_t varlen = strlen(varname);

        size_t str_fileoff = 0;
        int found_str = 0;
        for (size_t i = 0; i + varlen < size; i++) {
            if (memcmp(buf + i, varname, varlen) == 0 && buf[i + varlen] == '\0') {
                str_fileoff = i;
                found_str = 1;
                break;
            }
        }
        if (!found_str) {
            fprintf(stderr, "Warning: string \"%s\" not found\n", varname);
            continue;
        }

        uint64_t str_va = text_vmaddr + str_fileoff;
        uint32_t str_va_low32 = (uint32_t)(str_va & 0xFFFFFFFF);
        printf("Found \"%s\" at fileoff 0x%zx (VA low32 0x%08x)\n",
               varname, str_fileoff, str_va_low32);

        for (size_t i = 0; i + 24 <= size; i += 4) {
            uint32_t ptr_low32 = *(uint32_t *)(buf + i);
            if (ptr_low32 != str_va_low32) continue;

            uint32_t type = *(uint32_t *)(buf + i + 8);
            uint32_t perm = *(uint32_t *)(buf + i + 12);
            int32_t  offset = *(int32_t *)(buf + i + 16);

            if (type > 5) continue;
            if (offset != -1 && offset < -1) continue;

            if (perm == PERM_KERNEL_ONLY) {
                printf("  Patching perm at fileoff 0x%zx: KernelOnly(3) -> RootOnly(0)\n",
                       i + 12);
                *(uint32_t *)(buf + i + 12) = PERM_ROOT_ONLY;
                patched++;
            } else {
                printf("  Found entry at fileoff 0x%zx but perm=%u (not KernelOnly)\n",
                       i, perm);
            }
        }
    }

    if (patched == 0) {
        fprintf(stderr, "Error: no patches applied\n");
        free(buf);
        return 1;
    }

    printf("Applied %d patch(es)\n", patched);

    f = fopen(argv[2], "wb");
    if (!f) { perror("open output"); return 1; }
    if (fwrite(buf, 1, size, f) != size) { perror("write"); return 1; }
    fclose(f);
    free(buf);

    printf("Wrote patched kernel to %s\n", argv[2]);
    return 0;
}
