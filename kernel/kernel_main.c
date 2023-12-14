/**
 * @file kernel_main.c
 * @author cSuk1 (652240843@qq.com)
 * @brief 钩子函数的注册
 * @version 0.1
 * @date 2023-11-23
 *
 *
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
static struct nf_hook_ops NF_HKPreRouting2;
// static struct nf_hook_ops NF_HKForward;
static struct nf_hook_ops NF_HKPostRouting;
static struct nf_hook_ops NF_HKPostRouting2;

/**
 * @brief:初始化netfilter的五个hook点
 */

void hook_init(void)
{
    // 入站
    NF_HKLocalIn.hook = NfHookLocalIn; // 注册回调函数
    NF_HKLocalIn.hooknum = NF_INET_LOCAL_IN;
    NF_HKLocalIn.pf = PF_INET;
    NF_HKLocalIn.priority = NF_IP_PRI_FIRST;

    // 出站
    NF_HKLocalOut.hook = NfHookLocalOut; // 注册回调函数
    NF_HKLocalOut.hooknum = NF_INET_LOCAL_OUT;
    NF_HKLocalOut.pf = PF_INET;
    NF_HKLocalOut.priority = NF_IP_PRI_FIRST;

    // 预路由
    // nat链
    NF_HKPreRouting.hook = NfHookPreRouting; // 注册回调函数
    NF_HKPreRouting.hooknum = NF_INET_PRE_ROUTING;
    NF_HKPreRouting.pf = PF_INET;
    NF_HKPreRouting.priority = NF_IP_PRI_NAT_DST;
    // filter表
    NF_HKPreRouting2.hook = NfHookLocalIn; // 注册回调函数
    NF_HKPreRouting2.hooknum = NF_INET_PRE_ROUTING;
    NF_HKPreRouting2.pf = PF_INET;
    NF_HKPreRouting2.priority = NF_IP_PRI_FIRST;

    // NF_HKForward.hook = NfHookForward; // 注册回调函数
    // NF_HKForward.hooknum = NF_INET_FORWARD;
    // NF_HKForward.pf = PF_INET;
    // NF_HKForward.priority = NF_IP_PRI_FIRST;

    // 后路由
    // nat链
    NF_HKPostRouting.hook = NfHookPostRouting; // 注册回调函数
    NF_HKPostRouting.hooknum = NF_INET_POST_ROUTING;
    NF_HKPostRouting.pf = PF_INET;
    NF_HKPostRouting.priority = NF_IP_PRI_NAT_SRC;
    // filter表
    NF_HKPostRouting2.hook = NfHookLocalIn; // 注册回调函数
    NF_HKPostRouting2.hooknum = NF_INET_POST_ROUTING;
    NF_HKPostRouting2.pf = PF_INET;
    NF_HKPostRouting2.priority = NF_IP_PRI_FIRST;
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
    nf_register_net_hook(&init_net, &NF_HKPreRouting2);
    // nf_register_net_hook(&init_net, &NF_HKForward);
    nf_register_net_hook(&init_net, &NF_HKPostRouting);
    nf_register_net_hook(&init_net, &NF_HKPostRouting2);
    netlink_init();
    conn_init();
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
    nf_unregister_net_hook(&init_net, &NF_HKPreRouting2);
    // nf_unregister_net_hook(&init_net, &NF_HKForward);
    nf_unregister_net_hook(&init_net, &NF_HKPostRouting);
    nf_unregister_net_hook(&init_net, &NF_HKPostRouting2);
    netlink_release();
    conn_exit();
}

// 模块证书
MODULE_LICENSE("GPL");
MODULE_AUTHOR("caixing");
module_init(mod_init);
module_exit(mod_exit);