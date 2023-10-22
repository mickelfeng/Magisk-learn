#include <sys/mount.h>

#include <magisk.hpp>
#include <base.hpp>
#include <sys/vfs.h>

#include "init.hpp"

using namespace std;

void FirstStageInit::prepare() {
    prepare_data();
    restore_ramdisk_init();
    auto init = mmap_data("/init", true);
    // Redirect original init to magiskinit
    for (size_t off : init.patch(INIT_PATH, REDIR_PATH)) {
        LOGD("Patch @ %08zX [" INIT_PATH "] -> [" REDIR_PATH "]\n", off);
    }
}

// 将/dev/root根目录的init进行patch操作，将其内部的/system/bin/init 字符串改为/data/magiskinit ，这里根目录的init是原始的系统init二进制文件，[2.815494] magiskinit: Patch @ 0001C840 [/system/bin/init] -> [/data/magiskinit]，输出到/data/init ,并且挂载到/init
void LegacySARInit::first_stage_prep() {
    // Patch init binary
    int src = xopen("/init", O_RDONLY);
    int dest = xopen("/data/init", O_CREAT | O_WRONLY, 0);
    {
        mmap_data init("/init");
        //patch掉原init中所有/system/bin/init为/data/magiskinit,因为原init会反复调用execv来执行/system/bin/init.
        for (size_t off : init.patch(INIT_PATH, REDIR_PATH)) {
            LOGD("Patch @ %08zX [" INIT_PATH "] -> [" REDIR_PATH "]\n", off);
        }
        write(dest, init.buf(), init.sz());
        fclone_attr(src, dest);
        close(dest);
        close(src);
    }
    xmount("/data/init", "/init", nullptr, MS_BIND, nullptr);
}

bool SecondStageInit::prepare() {
    umount2("/init", MNT_DETACH);
    unlink("/data/init");

    // Make sure init dmesg logs won't get messed up
    argv[0] = (char *) INIT_PATH;

    // Some weird devices like meizu, uses 2SI but still have legacy rootfs
    struct statfs sfs{};
    statfs("/", &sfs);
    // 检查当前根文件系统是否为 RAMFS 或 TMPFS，如果是，说明当前仍然在 rootfs下，需要在第二阶段重新执行 init，删除 /init链接并创建一个符号链接，指向第二阶段的 init程序，这里的init程序实际是未经过Patch的系统init，其位置是/system/bin/init，以便在第二阶段执行 init。否则返回false。
    if (sfs.f_type == RAMFS_MAGIC || sfs.f_type == TMPFS_MAGIC) {
        // We are still on rootfs, so make sure we will execute the init of the 2nd stage
        unlink("/init");
        xsymlink(INIT_PATH, "/init");
        return true;
    }
    return false;
}
