#include <sys/mount.h>

#include <magisk.hpp>
#include <sepolicy.hpp>
#include <base.hpp>

#include "init.hpp"

using namespace std;

// 在使用 `monolithic` 策略的设备上，Magisk 直接从 /sepolicy 文件中加载 sepolicy 规则。这个文件通常位于系统的根目录下，用于存储 selinux 策略。这种方式比较简单直接，不需要进行额外的 hook 操作。(/sepolicy 没有)

// 在其他的设备上，`**Magisk 使用 FIFO（命名管道）劫持 selinuxfs 中的节点**`，以实现 selinux hook。具体来说，Magisk 会创建一个 FIFO 文件，**并挂载到 selinuxfs 中的 "load" 和 "enforce" 节点上**，用于接收 selinux 策略和 enforce 值。这样一来，即使系统中没有 /sepolicy 文件，Magisk 也可以通过劫持 selinuxfs 中的节点，来实现 selinux hook。

// 在 2SI 设备上，**由于第二阶段的 init 文件是一个动态可执行文件**，而不是静态的 /init 可执行文件，因此 Magisk 还需要协助劫持 selinuxfs。具体来说，Magisk 会在 init 进程启动之前，通过 `**LD_PRELOAD**` 的方式，将自己的 `preload.so` 库注入到 init 进程中，并**替换 security_load_policy 函数为自己的**实现，以实现 selinux hook。然后，Magisk 启动守护程序，等待 init 进程尝试加载 selinux 策略文件。当 init 进程启动时，Magisk 的钩子函数会拦截 security_load_policy 的调用，并将 selinux 策略文件和 enforce 值写入 FIFO 文件中，以实现自定义的 selinux 策略。
void MagiskInit::patch_sepolicy(const char *in, const char *out) {
    LOGD("Patching monolithic policy\n");
    auto sepol = unique_ptr<sepolicy>(sepolicy::from_file(in));

    sepol->magisk_rules();

    // Custom rules
    if (auto dir = xopen_dir("/data/" PREINITMIRR)) {
        for (dirent *entry; (entry = xreaddir(dir.get()));) {
            auto name = "/data/" PREINITMIRR "/"s + entry->d_name;
            auto rule = name + "/sepolicy.rule";
            if (xaccess(rule.data(), R_OK) == 0 &&
                access((name + "/disable").data(), F_OK) != 0 &&
                access((name + "/remove").data(), F_OK) != 0) {
                LOGD("Loading custom sepolicy patch: [%s]\n", rule.data());
                sepol->load_rule_file(rule.data());
            }
        }
    }

    LOGD("Dumping sepolicy to: [%s]\n", out);
    sepol->to_file(out);

    // Remove OnePlus stupid debug sepolicy and use our own
    if (access("/sepolicy_debug", F_OK) == 0) {
        unlink("/sepolicy_debug");
        link("/sepolicy", "/sepolicy_debug");
    }
}

#define MOCK_COMPAT    SELINUXMOCK "/compatible"
#define MOCK_LOAD      SELINUXMOCK "/load"
#define MOCK_ENFORCE   SELINUXMOCK "/enforce"

// hijack则是通过FIFO劫持 selinuxfs 中的节点，以实现selinux hook 。之后通过xfork() 创建子进程，父进程直接返回继续执行，执行到exec_init 后继续执行系统未经过patch的init， 在执行init的过程中会触发security_getenforce ，此时子进程才会从xopen的阻塞中脱离继续执行，也就是此时以及可以获取到selinux 策略和 enforce 值。
bool MagiskInit::hijack_sepolicy() {
    xmkdir(SELINUXMOCK, 0);

    if (access("/system/bin/init", F_OK) == 0) {
        // On 2SI devices, the 2nd stage init file is always a dynamic executable.
        // This meant that instead of going through convoluted methods trying to alter
        // and block init's control flow, we can just LD_PRELOAD and replace the
        // security_load_policy function with our own implementation.
        dump_preload("/dev/preload.so", 0644);
        setenv("LD_PRELOAD", "/dev/preload.so", 1);
    }

    // Hijack the "load" and "enforce" node in selinuxfs to manipulate
    // the actual sepolicy being loaded into the kernel
    auto hijack = [&] {
        LOGD("Hijack [" SELINUX_LOAD "]\n");
        close(xopen(MOCK_LOAD, O_CREAT | O_RDONLY, 0600));
        xmount(MOCK_LOAD, SELINUX_LOAD, nullptr, MS_BIND, nullptr);
        LOGD("Hijack [" SELINUX_ENFORCE "]\n");
        mkfifo(MOCK_ENFORCE, 0644);
        xmount(MOCK_ENFORCE, SELINUX_ENFORCE, nullptr, MS_BIND, nullptr);
    };

    string dt_compat;
    if (access(SELINUX_ENFORCE, F_OK) != 0) {
        // selinuxfs not mounted yet. Hijack the dt fstab nodes first
        // and let the original init mount selinuxfs for us.
        // This only happens on Android 8.0 - 9.0

        char buf[4096];
        ssprintf(buf, sizeof(buf), "%s/fstab/compatible", config->dt_dir);
        dt_compat = full_read(buf);
        if (dt_compat.empty()) {
            // Device does not do early mount and uses monolithic policy
            return false;
        }

        // Remount procfs with proper options
        xmount(nullptr, "/proc", nullptr, MS_REMOUNT, "hidepid=2,gid=3009");

        LOGD("Hijack [%s]\n", buf);

        // Preserve sysfs and procfs for hijacking
        mount_list.erase(std::remove_if(
                mount_list.begin(), mount_list.end(),
                [](const string &s) { return s == "/proc" || s == "/sys"; }), mount_list.end());

        mkfifo(MOCK_COMPAT, 0444);
        xmount(MOCK_COMPAT, buf, nullptr, MS_BIND, nullptr);
    } else {
        hijack();
    }

    // Read all custom rules into memory
    string rules;
    if (auto dir = xopen_dir("/data/" PREINITMIRR)) {
        for (dirent *entry; (entry = xreaddir(dir.get()));) {
            auto name = "/data/" PREINITMIRR "/"s + entry->d_name;
            auto rule_file = name + "/sepolicy.rule";
            if (xaccess(rule_file.data(), R_OK) == 0 &&
                access((name + "/disable").data(), F_OK) != 0 &&
                access((name + "/remove").data(), F_OK) != 0) {
                LOGD("Load custom sepolicy patch: [%s]\n", rule_file.data());
                full_read(rule_file.data(), rules);
                rules += '\n';
            }
        }
    }
    // Create a new process waiting for init operations
    if (xfork()) {
        // In parent, return and continue boot process
        return true;
    }

    if (!dt_compat.empty()) {
        // This open will block until init calls DoFirstStageMount
        // The only purpose here is actually to wait for init to mount selinuxfs for us
        int fd = xopen(MOCK_COMPAT, O_WRONLY);

        char buf[4096];
        ssprintf(buf, sizeof(buf), "%s/fstab/compatible", config->dt_dir);
        xumount2(buf, MNT_DETACH);

        hijack();

        xwrite(fd, dt_compat.data(), dt_compat.size());
        close(fd);
    }

    // This open will block until init calls security_getenforce
    int fd = xopen(MOCK_ENFORCE, O_WRONLY);

    // Cleanup the hijacks
    umount2("/init", MNT_DETACH);
    xumount2(SELINUX_LOAD, MNT_DETACH);
    xumount2(SELINUX_ENFORCE, MNT_DETACH);

    // Load and patch policy
    auto sepol = unique_ptr<sepolicy>(sepolicy::from_file(MOCK_LOAD));
    sepol->magisk_rules();
    sepol->load_rules(rules);

    // Load patched policy into kernel
    sepol->to_file(SELINUX_LOAD);

    // Write to the enforce node ONLY after sepolicy is loaded. We need to make sure
    // the actual init process is blocked until sepolicy is loaded, or else
    // restorecon will fail and re-exec won't change context, causing boot failure.
    // We (ab)use the fact that init reads the enforce node, and because
    // it has been replaced with our FIFO file, init will block until we
    // write something into the pipe, effectively hijacking its control flow.

    string enforce = full_read(SELINUX_ENFORCE);
    xwrite(fd, enforce.data(), enforce.length());
    close(fd);

    // At this point, the init process will be unblocked
    // and continue on with restorecon + re-exec.

    // Terminate process
    exit(0);
}
