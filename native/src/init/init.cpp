#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>
#include <vector>

#include <xz.h>

#include <base.hpp>
#include <embed.hpp>

#include "init.hpp"

using namespace std;

bool unxz(int fd, const uint8_t *buf, size_t size) {
    uint8_t out[8192];
    xz_crc32_init();
    struct xz_dec *dec = xz_dec_init(XZ_DYNALLOC, 1 << 26);
    struct xz_buf b = {
        .in = buf,
        .in_pos = 0,
        .in_size = size,
        .out = out,
        .out_pos = 0,
        .out_size = sizeof(out)
    };
    enum xz_ret ret;
    do {
        ret = xz_dec_run(dec, &b);
        if (ret != XZ_OK && ret != XZ_STREAM_END)
            return false;
        write(fd, out, b.out_pos);
        b.out_pos = 0;
    } while (b.in_pos != size);
    return true;
}

static int dump_bin(const uint8_t *buf, size_t sz, const char *path, mode_t mode) {
    int fd = xopen(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0)
        return 1;
    if (!unxz(fd, buf, sz))
        return 1;
    close(fd);
    return 0;
}

void restore_ramdisk_init() {
    unlink("/init");

    //获取备份的系统init
    const char *orig_init = backup_init();
    if (access(orig_init, F_OK) == 0) {
        //还原系统init到/init路径
        xrename(orig_init, "/init");
    } else {
        // If the backup init is missing, this means that the boot ramdisk
        // was created from scratch, and the real init is in a separate CPIO,
        // which is guaranteed to be placed at /system/bin/init.
        xsymlink(INIT_PATH, "/init");
    }
}

int dump_preload(const char *path, mode_t mode) {
    return dump_bin(init_ld_xz, sizeof(init_ld_xz), path, mode);
}

class RecoveryInit : public BaseInit {
public:
    using BaseInit::BaseInit;
    void start() override {
        LOGD("Ramdisk is recovery, abort\n");
        restore_ramdisk_init();
        rm_rf("/.backup");
        exec_init();
    }
};

int main(int argc, char *argv[]) {
    umask(0);

    auto name = basename(argv[0]);
    if (name == "magisk"sv)
        return magisk_proxy_main(argc, argv);

    if (getpid() != 1)
        return 1;

    BaseInit *init;
    BootConfig config{};

    if (argc > 1 && argv[1] == "selinux_setup"sv) {
        rust::setup_klog();
        // 第二步，这一步在magisk源码中没有关于 selinux_setup 字符串
        // 因此它其实是由第一步LegacySARInit执行完原版的init由原版的init执行selinux_setup传到第一步patch的init，也就是现在的这里的init
        //  也就是说一开始是通过修改 skip_initramfs patch原版的init为 magiskinit
        //  接着是走到这里的 LegacySARInit ，主要是做一些数据准备的操作，以及patch /system/bin/init 为magiskinit
        // 最后执行原init，原init又执行 /system/bin/init 到这里的 SecondStageInit
        init = new SecondStageInit(argv);
    } else {
        // This will also mount /sys and /proc
        //收集系统信息,在日志中有输出
        load_kernel_info(&config);

        if (config.skip_initramfs)
            // 第一步
            init = new LegacySARInit(argv, &config);
        else if (config.force_normal_boot)
            // 这个应该是从 boot 启动走的
            init = new FirstStageInit(argv, &config);
        else if (access("/sbin/recovery", F_OK) == 0 || access("/system/bin/recovery", F_OK) == 0)
            //RecoveryInit,不执行,暂不分析
            init = new RecoveryInit(argv, &config);
        else if (check_two_stage())
            init = new FirstStageInit(argv, &config);
        else
            //不执行,暂不分析
            init = new RootFSInit(argv, &config);
    }

    // Run the main routine
    init->start();
    exit(1);
}
