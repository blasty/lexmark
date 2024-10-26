#include <linux/types.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/debugfs.h>
#include <linux/io.h>
#include <linux/gfp.h>
#include <linux/uaccess.h>
#include <linux/ioport.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/device.h>
#include <linux/list.h>

static struct dentry *debugfs_root = NULL;

#define WTM_BASE 0xd1d20000
#define MMIO_SIZE 0x1000

void __iomem *mmio_base;

#define CMD_WRITE8 1
#define CMD_WRITE16 2
#define CMD_WRITE32 3
#define CMD_READ8 4
#define CMD_READ16 5
#define CMD_READ32 6
#define CMD_GET_SCRATCH 7
#define CMD_WTM_EXEC_CMD 8

typedef struct
{
        u16 cmd;
        u16 reg_offset;
        u32 value;
} cmd_t;

static uint8_t rbuf[4];
static u32 g_wtm_base, g_base;

static uint8_t *scratch;
static u32 g_scratch_phys;

static ssize_t cmd_read(struct file *file, char __user *userbuf, size_t count, loff_t *ppos)
{
        if (count < 0 || count > 4)
        {
                return -EFAULT;
        }
        if (copy_to_user(userbuf, rbuf, count))
        {
                return -EFAULT;
        }

        return count;
}

static ssize_t cmd_write(
    struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
        cmd_t cmd;
        int i;
        uint32_t args[16];

        if (copy_from_user(&cmd, buf, sizeof(cmd_t)))
        {
                return -EFAULT;
        }

        memset(rbuf, 0xaa, 4);

        switch (cmd.cmd)
        {
        case CMD_WRITE8:
                *(volatile u8 *)(g_wtm_base + cmd.reg_offset) = cmd.value & 0xff;
                break;
        case CMD_WRITE16:
                *(volatile u16 *)(g_wtm_base + cmd.reg_offset) = cmd.value & 0xffff;
                break;
        case CMD_WRITE32:
                *(volatile u32 *)(g_wtm_base + cmd.reg_offset) = cmd.value;
                break;
        case CMD_READ8:
                rbuf[0] = *(volatile u8 *)(g_wtm_base + cmd.reg_offset);
                break;
        case CMD_READ16:
                *(u16 *)rbuf = *(volatile u16 *)(g_wtm_base + cmd.reg_offset);
                break;
        case CMD_READ32:
                *(u32 *)rbuf = *(volatile u32 *)(g_wtm_base + cmd.reg_offset);
                break;
        case CMD_GET_SCRATCH:
                *(u32 *)rbuf = g_scratch_phys;
                break;
        case CMD_WTM_EXEC_CMD:
                copy_from_user(args, buf + sizeof(cmd_t), sizeof(uint32_t) * 16);
                for (i = 0; i < 16; i++)
                {
                        *(volatile u32 *)(g_wtm_base + (i * 4)) = args[i];
                }
                *(volatile u32 *)(g_wtm_base + 0xc8) |= 1;
                *(volatile u32 *)(g_wtm_base + 0x40) = cmd.value;
                break;
        default:
                return -EINVAL;
                break;
        }

        return count;
}

loff_t cmd_seek(struct file *fp, loff_t offs, int whence)
{
        g_base = offs & 0xffffffff;
        return g_base;
}

static const struct file_operations cmd_file_ops = {
    .owner = THIS_MODULE,
    .open = simple_open,

    .write = cmd_write,
    .read = cmd_read,
    .llseek = cmd_seek,
};

int fuck(struct device *dev, void *data)
{
        struct platform_device *pdev;
        if (dev->bus == &platform_bus_type)
        {
                pdev = to_platform_device(dev);
                if (strcmp(pdev->name, "d1d20000.wtm-mailbox-controller") != 0)
                {
                        return 0;
                }
                printk(KERN_ALERT "Platform device: (%08x) -- %s\n", *(u32 *)((u8 *)(pdev) + 0x50), pdev->name);

                u32 *ctx = (u32 *)(*(u32 *)((u8 *)(pdev) + 0x50));
                g_wtm_base = ctx[1];

                printk(KERN_ALERT "WTM base: %08x\n", g_wtm_base);
        }
        return 0;
}

static int __init hax_init(void)
{
        printk(KERN_INFO "Listing all platform devices:\n");

        // Locking the bus during iteration
        bus_for_each_dev(&platform_bus_type, NULL, NULL, fuck);

        printk(KERN_ALERT "HAX: init\n");
        g_base = 0;

        scratch = kzalloc(0x1000, 0xcc1);

        if (scratch == NULL)
        {
                printk(KERN_ALERT "HAX: scratch alloc fail!!\n");
        }
        else
        {
                memset(scratch, 0xd0, 0x1000);
                g_scratch_phys = virt_to_phys(scratch);
                printk(KERN_ALERT "HAX: scratch: virt=%p, phys=%08x\n", scratch, g_scratch_phys);
        }

        debugfs_root = debugfs_create_dir("hax", NULL);
        if (IS_ERR(debugfs_root) || !debugfs_root)
        {
                pr_warn("hax: failed to create hax debugfs directory\n");
                debugfs_root = NULL;
                return -1;
        }

        if (!debugfs_create_file_size(
                "cmd", S_IFREG | S_IRUGO, debugfs_root,
                NULL, &cmd_file_ops, 32))
        {
                printk(KERN_ALERT "hax: failed to create cmd file\n");
                return -1;
        }

        return 0;
}

static void __exit hax_exit(void)
{
        printk(KERN_ALERT "HAX: exiting...\n");

        if (debugfs_root)
                debugfs_remove_recursive(debugfs_root);

        if (scratch != NULL)
        {
                kfree(scratch);
        }
}

module_init(hax_init);
module_exit(hax_exit);

MODULE_DESCRIPTION("a simple hax module.");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("blasty");
