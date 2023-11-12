/**
 * 钩子函数的注册
 */
#include "kernel_api.h"
#include "dep.h"
#include "hook_func.h"

// 使用静态变量更适合与模块化编程，使用static进行定义的结构或变量只能在本文件中使用
// 定义netfilter的5个钩子点：
//  注册网络过滤器钩子函数
static struct nf_hook_ops NF_HKLocalIn;
static struct nf_hook_ops NF_HKLocalOut;
static struct nf_hook_ops NF_HKPreRouting;
static struct nf_hook_ops NF_HKForward;
static struct nf_hook_ops NF_HKPostRouting;

/**
 * @brief:初始化netfilter的五个hook点
 */

void hook_init(void)
{
    NF_HKLocalIn.hook = NfHookLocalIn; // 注册回调函数
    NF_HKLocalIn.hooknum = NF_INET_LOCAL_IN;
    NF_HKLocalIn.pf = PF_INET;
    NF_HKLocalIn.priority = NF_IP_PRI_FIRST;

    NF_HKLocalOut.hook = NfHookLocalOut; // 注册回调函数
    NF_HKLocalOut.hooknum = NF_INET_LOCAL_OUT;
    NF_HKLocalOut.pf = PF_INET;
    NF_HKLocalOut.priority = NF_IP_PRI_FIRST;

    NF_HKPreRouting.hook = NfHookPreRouting; // 注册回调函数
    NF_HKPreRouting.hooknum = NF_INET_PRE_ROUTING;
    NF_HKPreRouting.pf = PF_INET;
    NF_HKPreRouting.priority = NF_IP_PRI_FIRST;

    NF_HKForward.hook = NfHookForward; // 注册回调函数
    NF_HKForward.hooknum = NF_INET_FORWARD;
    NF_HKForward.pf = PF_INET;
    NF_HKForward.priority = NF_IP_PRI_FIRST;

    NF_HKPostRouting.hook = NfHookPostRouting; // 注册回调函数
    NF_HKPostRouting.hooknum = NF_INET_POST_ROUTING;
    NF_HKPostRouting.pf = PF_INET;
    NF_HKPostRouting.priority = NF_IP_PRI_FIRST;
}

// 内核模块初始化
static int mod_init(void)
{
    printk("[caixing fw] my firewall module loaded.\n");
    // 初始化钩子
    hook_init();
    /* 注册netfilter钩子函数 */
    nf_register_net_hook(&init_net, &NF_HKLocalIn); // 注册hook
    nf_register_net_hook(&init_net, &NF_HKLocalOut);
    nf_register_net_hook(&init_net, &NF_HKPreRouting);
    nf_register_net_hook(&init_net, &NF_HKForward);
    nf_register_net_hook(&init_net, &NF_HKPostRouting);
    netlink_init();
    return 0;
}

// 内核模块释放
static void mod_exit(void)
{
    printk("[caixing fw] my firewall module exit.\n");
    /* 取消注册netfilter钩子函数 */
    nf_unregister_net_hook(&init_net, &NF_HKLocalIn);
    nf_unregister_net_hook(&init_net, &NF_HKLocalOut);
    nf_unregister_net_hook(&init_net, &NF_HKPreRouting);
    nf_unregister_net_hook(&init_net, &NF_HKForward);
    nf_unregister_net_hook(&init_net, &NF_HKPostRouting);
    netlink_release();
}

// 模块证书
MODULE_LICENSE("GPL");
MODULE_AUTHOR("cx");
module_init(mod_init);
module_exit(mod_exit);