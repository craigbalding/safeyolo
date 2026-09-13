/* A launcher that attaches Seatbelt before executing user-controlled code.
 * Configured as the agent account's login shell; zsh interprets commands.
 * Build and install as a root-owned, hardened-runtime binary; see README.md.
 * No shell interpreter runs this file, and no input selects the policy path.
 */
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef AGENT_USER
#define AGENT_USER "sy-agent"
#endif
#ifndef AGENT_HOME
#define AGENT_HOME "/Users/sy-agent"
#endif
#ifndef TOOLCHAIN_ROOT
#define TOOLCHAIN_ROOT "/opt/homebrew"
#endif
#define ENTRY_ROOT "/Library/PrivilegedHelperTools/seatbelt-agent"

static void fail(const char *message) {
    fprintf(stderr, "agent-shell-launcher: %s\n", message);
    exit(1);
}

static void trusted_path(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0 || S_ISLNK(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        fail("shell-launcher files must be root-owned and not writable by group/others");
}

int main(int argc, char **argv) {
    struct passwd *account = getpwnam(AGENT_USER);
    if (!account || getuid() == 0 || getuid() != geteuid() ||
        getuid() != account->pw_uid || strcmp(account->pw_dir, AGENT_HOME) != 0)
        fail("this shell launcher belongs to the configured dedicated account");
    /* sshd invokes the login shell with -c and the literal ForceCommand.
     * Direct login-shell invocation still attaches exactly the same profile.
     */
    int check = argc == 2 && strcmp(argv[1], "--check") == 0;
    if (!check && argc != 1 && !(argc == 3 && strcmp(argv[1], "-c") == 0 &&
                       strcmp(argv[2], "seatbelt-session") == 0))
        fail("unexpected login-shell arguments; check ForceCommand");
    trusted_path("/Library");
    trusted_path("/Library/PrivilegedHelperTools");
    trusted_path(ENTRY_ROOT);
    trusted_path(ENTRY_ROOT "/agent-shell-launcher");
    trusted_path(ENTRY_ROOT "/agent-dev.sb");
    trusted_path(ENTRY_ROOT "/agent-session");

    /* Never evaluate this text here. It becomes a shell argument AFTER Seatbelt attaches. */
    const char *original = getenv("SSH_ORIGINAL_COMMAND");
    char *command = original && *original ? strdup(original) : NULL;
    if (original && *original && !command)
        fail("cannot allocate remote command");
    char term[144] = "TERM=xterm-256color";
    const char *value = getenv("TERM");
    if (value && strlen(value) < 128 && *value) {
        for (const char *p = value; *p; ++p)
            if (!isalnum((unsigned char)*p) && !strchr("-_.+", *p))
                fail("invalid terminal type");
        snprintf(term, sizeof(term), "TERM=%s", value);
    }
    char *environment[] = {
        "HOME=" AGENT_HOME, "USER=" AGENT_USER, "LOGNAME=" AGENT_USER,
        "PATH=" AGENT_HOME "/.local/bin:" TOOLCHAIN_ROOT "/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "SHELL=/bin/zsh", "LANG=en_US.UTF-8", term,
        "TMPDIR=" AGENT_HOME "/tmp/",
        "XDG_CACHE_HOME=" AGENT_HOME "/.cache",
        "PYTHONPYCACHEPREFIX=" AGENT_HOME "/.cache/pycache",
        "CLANG_MODULE_CACHE_PATH=" AGENT_HOME "/.cache/clang",
        "XDG_STATE_HOME=" AGENT_HOME "/.local/state",
        "XDG_CONFIG_HOME=" AGENT_HOME "/.config",
        NULL
    };
    char *arguments[] = {
        "/usr/bin/sandbox-exec", "-f", ENTRY_ROOT "/agent-dev.sb",
        "-D", "AGENT_HOME=" AGENT_HOME,
        "-D", "TOOLCHAIN_ROOT=" TOOLCHAIN_ROOT,
        check ? "/usr/bin/true" : ENTRY_ROOT "/agent-session",
        check ? NULL : (command ? "--command" : "--interactive"), command, NULL
    };
    umask(077);
    if (chdir("/") != 0)
        fail("cannot change working directory");
    for (int fd = 3, maxfd = getdtablesize(); fd < maxfd; ++fd)
        close(fd);
    execve(arguments[0], arguments, environment);
    fprintf(stderr, "agent-shell-launcher: sandbox-exec failed: %s\n", strerror(errno));
    return 1;
}
