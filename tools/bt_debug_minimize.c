// SPDX-License-Identifier: LGPL-3.0-or-later

#define _GNU_SOURCE

#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char *keep_exact[] = {
    ".ARM.exidx",
    ".ARM.extab",
    ".dynamic",
    ".dynstr",
    ".dynsym",
    ".eh_frame",
    ".eh_frame_hdr",
    ".gnu.hash",
    ".gnu.version",
    ".gnu.version_d",
    ".gnu.version_r",
    ".gnu_debuglink",
    ".hash",
    ".interp",
    ".note.ABI-tag",
    ".note.gnu.build-id",
    ".note.go.buildid",
    ".rela.dyn",
    ".rela.plt",
    ".rel.dyn",
    ".rel.plt",
    ".shstrtab",
    ".strtab",
    ".symtab",
    ".symtab_shndx",
    ".zdebug_frame",
    ".zdebug_frame_hdr",
    ".debug_frame",
    ".debug_frame_hdr",
    ".sframe",
};

static const char *keep_prefixes[] = {
    ".fini",
    ".got",
    ".init",
    ".note.",
    ".plt",
    ".rela.",
    ".rel.",
    ".text",
};

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s --dump-dir DIR --out-dir DIR\n"
            "  %s --elf FILE --out FILE\n",
            argv0, argv0);
}

static bool has_prefix(const char *str, const char *prefix)
{
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

static bool should_keep_section(const char *name)
{
    size_t i;

    if (!name)
        return true;
    for (i = 0; i < sizeof(keep_exact) / sizeof(keep_exact[0]); i++) {
        if (strcmp(name, keep_exact[i]) == 0)
            return true;
    }
    for (i = 0; i < sizeof(keep_prefixes) / sizeof(keep_prefixes[0]); i++) {
        if (has_prefix(name, keep_prefixes[i]))
            return true;
    }
    return false;
}

static int mkdir_p(const char *path, mode_t mode)
{
    char tmp[PATH_MAX];
    char *p;
    size_t len;

    if (snprintf(tmp, sizeof(tmp), "%s", path) >= (int)sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    len = strlen(tmp);
    if (len == 0)
        return 0;
    if (tmp[len - 1] == '/')
        tmp[len - 1] = '\0';
    for (p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(tmp, mode) < 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    if (mkdir(tmp, mode) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int parent_mkdir_p(const char *path)
{
    char tmp[PATH_MAX];
    char *slash;

    if (snprintf(tmp, sizeof(tmp), "%s", path) >= (int)sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    slash = strrchr(tmp, '/');
    if (!slash)
        return 0;
    if (slash == tmp)
        return 0;
    *slash = '\0';
    return mkdir_p(tmp, 0755);
}

static int join_path(char *dst, size_t dst_len, const char *left, const char *right)
{
    int ret;

    if (left[0] == '\0')
        ret = snprintf(dst, dst_len, "%s", right);
    else if (left[strlen(left) - 1] == '/')
        ret = snprintf(dst, dst_len, "%s%s", left, right);
    else
        ret = snprintf(dst, dst_len, "%s/%s", left, right);
    if (ret < 0 || (size_t)ret >= dst_len) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int copy_file(const char *src, const char *dst, mode_t mode)
{
    char buf[131072];
    int in_fd = -1;
    int out_fd = -1;
    ssize_t nr;
    int ret = -1;

    if (parent_mkdir_p(dst) < 0)
        return -1;
    in_fd = open(src, O_RDONLY | O_CLOEXEC);
    if (in_fd < 0)
        goto out;
    out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode & 07777);
    if (out_fd < 0)
        goto out;
    while ((nr = read(in_fd, buf, sizeof(buf))) > 0) {
        char *p = buf;
        while (nr > 0) {
            ssize_t nw = write(out_fd, p, (size_t)nr);
            if (nw < 0)
                goto out;
            p += nw;
            nr -= nw;
        }
    }
    if (nr < 0)
        goto out;
    if (fchmod(out_fd, mode & 07777) < 0)
        goto out;
    ret = 0;
out:
    if (in_fd >= 0)
        close(in_fd);
    if (out_fd >= 0)
        close(out_fd);
    return ret;
}

static bool is_elf_file(const char *path)
{
    unsigned char magic[4];
    int fd;
    ssize_t nr;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    nr = read(fd, magic, sizeof(magic));
    close(fd);
    return nr == (ssize_t)sizeof(magic) && magic[0] == 0x7f &&
           magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F';
}

static int zero_section(Elf_Scn *scn, GElf_Shdr *shdr)
{
    Elf_Data *data = NULL;

    while ((data = elf_getdata(scn, data)) != NULL) {
        data->d_buf = NULL;
        data->d_size = 0;
        if (elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY) == 0)
            return -1;
    }
    shdr->sh_type = SHT_NOBITS;
    shdr->sh_offset = 0;
    shdr->sh_size = 0;
    if (!gelf_update_shdr(scn, shdr))
        return -1;
    if (elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY) == 0)
        return -1;
    return 0;
}

static int minimize_elf_in_place(const char *path)
{
    int fd = -1;
    Elf *elf = NULL;
    Elf_Scn *scn = NULL;
    size_t shstrndx = 0;
    off_t new_size;
    int ret = -1;

    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "libelf init failed: %s\n", elf_errmsg(-1));
        return -1;
    }

    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return -1;
    elf = elf_begin(fd, ELF_C_RDWR, NULL);
    if (!elf) {
        fprintf(stderr, "%s: elf_begin failed: %s\n", path, elf_errmsg(-1));
        goto out;
    }
    if (elf_kind(elf) != ELF_K_ELF) {
        ret = 0;
        goto out;
    }
    if (elf_getshdrstrndx(elf, &shstrndx) < 0) {
        fprintf(stderr, "%s: elf_getshdrstrndx failed: %s\n", path, elf_errmsg(-1));
        goto out;
    }

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        char *name;

        if (!gelf_getshdr(scn, &shdr)) {
            fprintf(stderr, "%s: gelf_getshdr failed: %s\n", path, elf_errmsg(-1));
            goto out;
        }
        name = elf_strptr(elf, shstrndx, shdr.sh_name);
        if (should_keep_section(name))
            continue;
        if (zero_section(scn, &shdr) < 0) {
            fprintf(stderr, "%s: failed to drop section %s: %s\n",
                    path, name ? name : "<unnamed>", elf_errmsg(-1));
            goto out;
        }
    }

    if (elf_flagelf(elf, ELF_C_SET, ELF_F_DIRTY) == 0)
        goto out;
    new_size = elf_update(elf, ELF_C_WRITE);
    if (new_size < 0) {
        fprintf(stderr, "%s: elf_update failed: %s\n", path, elf_errmsg(-1));
        goto out;
    }
    if (ftruncate(fd, new_size) < 0)
        goto out;
    ret = 0;
out:
    if (elf)
        elf_end(elf);
    if (fd >= 0)
        close(fd);
    return ret;
}

static int minimize_elf_file(const char *src, const char *dst, mode_t mode)
{
    char tmp[PATH_MAX];

    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", dst, (long)getpid()) >= (int)sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (copy_file(src, tmp, mode) < 0)
        return -1;
    if (minimize_elf_in_place(tmp) < 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, dst) < 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static int copy_symlink(const char *src, const char *dst)
{
    char target[PATH_MAX];
    ssize_t len;

    if (parent_mkdir_p(dst) < 0)
        return -1;
    len = readlink(src, target, sizeof(target) - 1);
    if (len < 0)
        return -1;
    target[len] = '\0';
    unlink(dst);
    return symlink(target, dst);
}

static int mirror_path(const char *src, const char *dst)
{
    struct stat st;

    if (lstat(src, &st) < 0)
        return -1;
    if (S_ISDIR(st.st_mode)) {
        DIR *dir;
        struct dirent *ent;

        if (mkdir_p(dst, st.st_mode & 07777) < 0)
            return -1;
        dir = opendir(src);
        if (!dir)
            return -1;
        while ((ent = readdir(dir)) != NULL) {
            char child_src[PATH_MAX];
            char child_dst[PATH_MAX];

            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
                continue;
            if (join_path(child_src, sizeof(child_src), src, ent->d_name) < 0 ||
                join_path(child_dst, sizeof(child_dst), dst, ent->d_name) < 0) {
                closedir(dir);
                return -1;
            }
            if (mirror_path(child_src, child_dst) < 0) {
                fprintf(stderr, "failed to process %s: %s\n", child_src, strerror(errno));
                closedir(dir);
                return -1;
            }
        }
        closedir(dir);
        chmod(dst, st.st_mode & 07777);
        return 0;
    }
    if (S_ISLNK(st.st_mode))
        return copy_symlink(src, dst);
    if (!S_ISREG(st.st_mode))
        return 0;
    if (is_elf_file(src))
        return minimize_elf_file(src, dst, st.st_mode);
    return copy_file(src, dst, st.st_mode);
}

int main(int argc, char **argv)
{
    const char *dump_dir = NULL;
    const char *out_dir = NULL;
    const char *elf_src = NULL;
    const char *elf_out = NULL;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dump-dir") == 0 && i + 1 < argc) {
            dump_dir = argv[++i];
        } else if (strcmp(argv[i], "--out-dir") == 0 && i + 1 < argc) {
            out_dir = argv[++i];
        } else if (strcmp(argv[i], "--elf") == 0 && i + 1 < argc) {
            elf_src = argv[++i];
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            elf_out = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (elf_src || elf_out) {
        struct stat st;

        if (!elf_src || !elf_out) {
            usage(argv[0]);
            return 2;
        }
        if (stat(elf_src, &st) < 0) {
            perror(elf_src);
            return 1;
        }
        if (!is_elf_file(elf_src))
            return copy_file(elf_src, elf_out, st.st_mode) < 0 ? 1 : 0;
        if (minimize_elf_file(elf_src, elf_out, st.st_mode) < 0) {
            perror(elf_src);
            return 1;
        }
        return 0;
    }

    if (!dump_dir || !out_dir) {
        usage(argv[0]);
        return 2;
    }
    if (mirror_path(dump_dir, out_dir) < 0) {
        perror(dump_dir);
        return 1;
    }
    return 0;
}
