/**
 * @file nl_sock.c
 * @author cSuk1 (652240843@qq.com)
 * @brief netlink套接字
 * @version 0.1
 * @date 2023-11-23
 *
 *
 */
#include "kernel_api.h"

// 创建一个套接字结构
static struct sock *nl_sock = NULL;

/**
 * @brief：从NETLINK_MYFW套接字发送消息
 */
int NLFWSend(unsigned int pid, void *data, unsigned int len)
{
    int ret;
    // netlink套接字消息头
    struct nlmsghdr *nl_hd;
    // 套接字缓冲区
    struct sk_buff *skb;
    // 创建一个新的 netlink 消息缓冲区。
    skb = nlmsg_new(len, GFP_ATOMIC);
    if (skb == NULL)
    {
        printk(KERN_WARNING "[caixing fw] NETLINK_MYFW send alloc reply nlmsg skb failed!\n");
        return -1;
    }
    // 向netlink消息缓冲区中添加netlink消息头
    nl_hd = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(len) - NLMSG_HDRLEN, 0);
    // 将data复制到netlink消息数据中
    memcpy(NLMSG_DATA(nl_hd), data, len);
    // 设置目标组
    // 会将消息发送给所有正在监听 netlink 套接字的接收者。
    NETLINK_CB(skb).dst_group = 0;
    // 将netlink消息发送给指定的接收者
    ret = netlink_unicast(nl_sock, skb, pid, MSG_DONTWAIT);
    printk("[caixing fw] NETLINK_MYFW data send to user pid=%d,len=%d,ret=%d\n", pid, nl_hd->nlmsg_len - NLMSG_SPACE(0), ret);
    return ret;
}
/**
 * @brief：从NETLINK_MYFW套接字接收消息
 * @param: struct sk_buff *skb，in the path linux/include/linux/skbuff.h line 687
 */
void NLFWRecv(struct sk_buff *skb)
{
    void *data;
    // NETLINK套接字消息头
    struct nlmsghdr *nl_hd = NULL;
    unsigned int pid, len;
    // 利用nlmsg_hdr获取skb中指向netlink消息头部的指针
    nl_hd = nlmsg_hdr(skb);
    if ((nl_hd->nlmsg_len < NLMSG_HDRLEN) || (skb->len < nl_hd->nlmsg_len))
    {
        printk(KERN_WARNING "[caixing fw] NETLINK_MYFW Illegal netlink packet!\n");
        return;
    }
    // 利用NLMSG_DATA从netlink消息中获取指向数据消息的指针
    data = NLMSG_DATA(nl_hd);
    // 获取来源进程的pid
    pid = nl_hd->nlmsg_pid;
    // 计算数据部分的长度
    len = nl_hd->nlmsg_len - NLMSG_SPACE(0);
    // 如果数据部分长度小于用户的请求体的大小
    if (len < sizeof(struct UsrReq))
    {
        printk(KERN_WARNING "[caixing fw] NETLINK_MYFW packet size < UsrReq!\n");
        return;
    }
    printk("[caixing fw] NETLINK_MYFW data receive from user: user_pid=%d, len=%d\n", pid, len);
    // 取出了源地址、数据和长度，然后处理用户请求
    ProcUsrReq(pid, data, len);
}

/**
 * struct netlink_kernel_cfg in the path linux/include/linux/netlink.h line 44
 * 用于配置Netlink套接字的参数
 */
struct netlink_kernel_cfg nl_conf = {
    .groups = 0,
    .flags = 0,
    // 指定了一个回调函数NLFWRecv，用于在接收到 netlink 消息时进行处理
    // void (*input)(struct sk_buff *skb);
    .input = NLFWRecv,
    .cb_mutex = NULL,
    .bind = NULL,
    .unbind = NULL,
    .compare = NULL,
};

/**
 * @brief:初始化NETLINK_MYFW套接字
 */
struct sock *netlink_init()
{
    /**
     * 函数的第一个参数 net 是指定关联的网络命名空间，一般使用 &init_net。
     * 第二个参数用于标识 netlink 套接字的协议类型，这里使用自定义的协议NETLINK_MYFW。
     * 第三个参数nl_conf是一个指向netlink_kernel_cfg结构体的指针，用于配置netlink套接字的行为。
     */
    nl_sock = netlink_kernel_create(&init_net, NETLINK_MYFW, &nl_conf);
    if (!nl_sock)
    {
        printk(KERN_WARNING "[caixing fw] fail to create NETLINK_MYFW socket\n");
        return NULL;
    }
    printk("[caixing fw] create NETLINK_MYFW socket success, NETLINK_MYFW socket = %p\n", nl_sock);
    return nl_sock;
}

/**
 * @brief:释放NETLINK_MYFW套接字
 */
void netlink_release()
{
    netlink_kernel_release(nl_sock);
}