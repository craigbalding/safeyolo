/* Installer preflight. Run as root; inspect permissions as the target account.
 * Uses macOS extended access checks so ACL ordering and group membership are
 * evaluated by the kernel, without executing the account's startup files.
 */
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <libgen.h>
#include <membership.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>

static void fail(const char *message, const char *path) {
    fprintf(stderr, "configure-ssh: %s: %s\n", message, path);
    exit(1);
}

static void protected_path(const char *path) {
    struct stat st;
    if (lstat(path, &st) || S_ISLNK(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & (S_IWGRP | S_IWOTH)))
        fail("expected root ownership, no symlink or group/other write bits", path);
    const int rights[] = {
        _WRITE_OK, _APPEND_OK, _DELETE_OK, _WATTR_OK, _WEXT_OK,
        _WPERM_OK, _CHOWN_OK, S_ISDIR(st.st_mode) ? _RMFILE_OK : _WRITE_OK
    };
    for (size_t i = 0; i < sizeof(rights) / sizeof(rights[0]); ++i) {
        if (access(path, rights[i]) == 0)
            fail("account can modify or replace this path (check ACLs)", path);
        if (errno != EACCES && errno != EPERM && errno != EROFS)
            fail(strerror(errno), path);
    }
}

static void protected_tree(const char *path) {
    char *copy = strdup(path);
    if (!copy)
        fail("cannot allocate path", path);
    protected_path(copy);
    while (strcmp(copy, "/") != 0) {
        char *parent = dirname(copy);
        memmove(copy, parent, strlen(parent) + 1);
        protected_path(copy);
    }
    free(copy);
}

static void scheduler_state(const struct passwd *pw) {
    char path[PATH_MAX];
    struct stat st;
    if (snprintf(path, sizeof(path), "/private/var/at/tabs/%s", pw->pw_name) >= (int)sizeof(path))
        fail("account name is too long", pw->pw_name);
    if (lstat(path, &st) == 0)
        fail("pre-existing crontab; inspect it with crontab -l -u USER before conversion", path);
    if (errno != ENOENT)
        fail("cannot establish absence of an account crontab", path);
    DIR *jobs = opendir("/private/var/at/jobs");
    if (!jobs)
        fail("cannot inspect at/batch jobs", "/private/var/at/jobs");
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(jobs))) {
        if (entry->d_name[0] == '.') continue;
        if (fstatat(dirfd(jobs), entry->d_name, &st, AT_SYMLINK_NOFOLLOW))
            fail("cannot inspect at/batch job", entry->d_name);
        if (st.st_uid == pw->pw_uid)
            fprintf(stderr, "configure-ssh: review existing at/batch job /private/var/at/jobs/%s; "
                    "its later executor must not consume writable code without confinement\n", entry->d_name);
        errno = 0;
    }
    if (errno) fail("cannot enumerate at/batch jobs", "/private/var/at/jobs");
    closedir(jobs);
}

static void launchagents_path(const char *home) {
    char path[PATH_MAX];
    struct stat st;
    if (snprintf(path, sizeof(path), "%s/Library", home) >= (int)sizeof(path))
        fail("home path is too long", home);
    /* Create only this ordinary account directory, as the account. A racing
     * creation is accepted only after the following real-directory check.
     */
    if (mkdir(path, 0700) && errno != EEXIST)
        fail("cannot prepare Library", path);
    if (lstat(path, &st) || !S_ISDIR(st.st_mode))
        fail("Library must be a real directory, not a symlink", path);
    if (snprintf(path, sizeof(path), "%s/Library/LaunchAgents", home) >= (int)sizeof(path))
        fail("home path is too long", home);
    if (lstat(path, &st) == 0) {
        if (!S_ISDIR(st.st_mode))
            fail("LaunchAgents must be absent or a real directory, not a symlink", path);
    } else if (errno != ENOENT) {
        fail("cannot inspect LaunchAgents", path);
    }
}

int main(int argc, char **argv) {
    if (argc < 4 || getuid() != 0 || geteuid() != 0)
        fail("usage as root", "check-account USER SHELL PATH...");
    struct passwd *pw = getpwnam(argv[1]);
    if (!pw || pw->pw_uid == 0)
        fail("expected an existing non-root account", argv[1]);
    uuid_t user_uuid, admin_uuid;
    int member = 0;
    if (mbr_uid_to_uuid(pw->pw_uid, user_uuid) ||
        mbr_gid_to_uuid(80, admin_uuid) ||
        mbr_check_membership(user_uuid, admin_uuid, &member) || member)
        fail("account must not belong to admin (including nested groups)", argv[1]);
    struct stat home;
    if (lstat(pw->pw_dir, &home) || !S_ISDIR(home.st_mode) || home.st_uid != pw->pw_uid)
        fail("home must be a real directory owned by the account", pw->pw_dir);
    scheduler_state(pw);
    if (initgroups(pw->pw_name, pw->pw_gid) || setgid(pw->pw_gid) || setuid(pw->pw_uid))
        fail("cannot adopt account identity for permission checks", argv[1]);
    launchagents_path(pw->pw_dir);
    for (int i = 3; i < argc; ++i)
        protected_tree(argv[i]);
    /* Exercise the binary, compiled account/home and actual profile without
     * a shell, startup files, cache creation or another user-controlled input.
     */
    char *environment[] = {NULL};
    char *arguments[] = {argv[2], "--check", NULL};
    execve(argv[2], arguments, environment);
    fail("cannot run the installed shell launcher", strerror(errno));
}
