/**
 * 钩子函数
 */
#include "hook_func.h"
#include "kernel_api.h"
#include "dep.h"

// 设置默认动作
unsigned int DEFAULT_ACTION = NF_ACCEPT;

/*******************************************************
 * @brief 本地输入
 *
 * @param priv
 * @param skb
 * @param state
 * @return unsigned int
 * @author cSuk1 (652240843@qq.com)
 * @date 2023-11-23
 *******************************************************/
unsigned int NfHookLocalIn(void *priv, struct sk_buff *skb,
                           const struct nf_hook_state *state)
{
    int flag;
    // 接收匹配到的规则
    struct FTRule rule;
    flag = ftrule_match(skb, &rule, DEFAULT_ACTION);
    if (flag > -1)
    { // 查规则集,如果匹配到了
        // printk(KERN_DEBUG "[rule match] match a rule the action is %d.\n", flag);
        return (flag == NF_ACCEPT) ? NF_ACCEPT : NF_DROP;
    }
    // 否则返回默认行为
    return DEFAULT_ACTION;
}

/*******************************************************
 * @brief 本地出站
 *
 * @param priv
 * @param skb
 * @param state
 * @return unsigned int
 * @author cSuk1 (652240843@qq.com)
 * @date 2023-11-23
 *******************************************************/
unsigned int NfHookLocalOut(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    int flag;
    // 接收匹配到的规则
    struct FTRule rule;
    flag = ftrule_match(skb, &rule, NF_ACCEPT);
    if (flag > -1)
    { // 查规则集,如果匹配到了
        // printk(KERN_DEBUG "[rule match] match a rule the action is %d.\n", flag);
        return (flag == NF_ACCEPT) ? NF_ACCEPT : NF_DROP;
    }
    // 否则返回默认行为
    return NF_ACCEPT;
}

/*******************************************************
 * @brief nat in
 *
 * @note 进行目的网络地址转换——DNAT
 * @param priv
 * @param skb
 * @param state
 * @return unsigned int
 * @author Andromeda (ech0uname@qq.com)
 * @date 2023-12-09
 *******************************************************/
unsigned int NfHookPreRouting(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    // 获取数据包内容
    struct connSess *conn;
    struct NATRule record;
    unsigned short sport, dport;
    unsigned int sip, dip;
    u_int8_t proto;
    struct tcphdr *tcpHeader;
    struct udphdr *udpHeader;
    int hdr_len, tot_len;
    // 初始化
    struct iphdr *header = ip_hdr(skb);
    // ! 获取源和目的ip 源和目的端口
    // 源ip和目的ip,并从网络字节顺序转为主机字节顺序
    sip = ntohl(header->saddr);
    dip = ntohl(header->daddr);
    // 协议
    proto = header->protocol;
    switch (proto)
    {
        // 传输层协议为tcp
    case IPPROTO_TCP:
        tcpHeader = (struct tcphdr *)(skb->data + (header->ihl * 4));
        sport = ntohs(tcpHeader->source);
        dport = ntohs(tcpHeader->dest);
        break;
        // 传输层协议为udp
    case IPPROTO_UDP:
        udpHeader = (struct udphdr *)(skb->data + (header->ihl * 4));
        sport = ntohs(udpHeader->source);
        dport = ntohs(udpHeader->dest);
        break;
        // ICMP
    case IPPROTO_ICMP:
    // 默认情况
    default:
        sport = 0;
        dport = 0;
        break;
    }
    // ! 从连接池取出连接
    conn = hasConn(sip, dip, sport, dport, 0);
    if (conn == NULL)
    {
        printk(KERN_WARNING "[fwnat] not in the connection pool!\n");
        return NF_ACCEPT;
    }
    // 如果不是DNAT
    if (conn->natType != NAT_TYPE_DEST)
    {
        return NF_ACCEPT;
    }

    // ! 修改数据包
    record = conn->nat;
    // 修改目的地址
    header->daddr = htonl(record.daddr);
    hdr_len = header->ihl * 4;
    tot_len = ntohs(header->tot_len);
    // 计算校验和
    header->check = 0;
    header->check = ip_fast_csum(header, header->ihl);
    // ! 修改上层协议报文
    switch (proto)
    {
    case IPPROTO_TCP:
        // 获取TCP头
        tcpHeader = (struct tcphdr *)(skb->data + (header->ihl * 4));
        // 设置目标端口
        tcpHeader->dest = htons(record.dport);
        // 初始化校验和
        tcpHeader->check = 0;
        // 计算校验和
        skb->csum = csum_partial((unsigned char *)tcpHeader, tot_len - hdr_len, 0);
        // 设置校验和
        tcpHeader->check = csum_tcpudp_magic(header->saddr, header->daddr,
                                             tot_len - hdr_len, header->protocol, skb->csum);
        break;
    case IPPROTO_UDP:
        // 获取UDP头
        udpHeader = (struct udphdr *)(skb->data + (header->ihl * 4));
        // 设置目标端口
        udpHeader->dest = htons(record.dport);
        udpHeader->check = 0;
        // 初始化校验和
        tcpHeader->check = 0;
        // 计算校验和
        skb->csum = csum_partial((unsigned char *)udpHeader, tot_len - hdr_len, 0);
        // 设置校验和
        udpHeader->check = csum_tcpudp_magic(header->saddr, header->daddr,
                                             tot_len - hdr_len, header->protocol, skb->csum);
        break;
    // case IPPROTO_ICMP:
    default:
        break;
    }
    return NF_ACCEPT;
}

unsigned int NfHookForward(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    return NF_ACCEPT;
}

/*******************************************************
 * @brief nat out
 *
 * @note 进行源网络地址转换——SNAT
 * @param priv
 * @param skb
 * @param state
 * @return unsigned int
 * @author Andromeda (ech0uname@qq.com)
 * @date 2023-12-09
 *******************************************************/
unsigned int NfHookPostRouting(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    // 获取数据包内容
    struct connSess *conn, *reverseConn;
    struct NATRule record;
    int isMatch, hdr_len, tot_len;
    struct tcphdr *tcpHeader;
    struct udphdr *udpHeader;
    u_int8_t proto;
    unsigned int sip, dip;
    unsigned short sport, dport;
    // 初始化
    struct iphdr *header = ip_hdr(skb);
    // ! 获取源ip和目的ip,源和目的端口
    // 并从网络字节顺序转为主机字节顺序
    sip = ntohl(header->saddr);
    dip = ntohl(header->daddr);
    // 协议
    proto = header->protocol;
    switch (proto)
    {
        // 传输层协议为tcp
    case IPPROTO_TCP:
        tcpHeader = (struct tcphdr *)(skb->data + (header->ihl * 4));
        sport = ntohs(tcpHeader->source);
        dport = ntohs(tcpHeader->dest);
        break;
        // 传输层协议为udp
    case IPPROTO_UDP:
        udpHeader = (struct udphdr *)(skb->data + (header->ihl * 4));
        sport = ntohs(udpHeader->source);
        dport = ntohs(udpHeader->dest);
        break;
        // ICMP
    case IPPROTO_ICMP:
    // 默认情况
    default:
        sport = 0;
        dport = 0;
        break;
    }
    // ! 检查连接池
    conn = hasConn(sip, dip, sport, dport, 0);
    if (conn == NULL)
    {
        printk(KERN_WARNING "[fwnat] not in the connection pool!\n");
        return NF_ACCEPT;
    }
    // 如果是SNAT
    if (conn->natType == NAT_TYPE_SRC)
    {
        // ! 取出nat记录
        record = conn->nat;
    }
    else
    {
        // 为dnat
        unsigned short newPort = 0;
        // 匹配nat规则
        struct NATRule *rule = matchNATRule(sip, dip, &isMatch);
        if (!isMatch || rule == NULL)
        {
            // 不符合NAT规则,无需NAT
            return NF_ACCEPT;
        }
        // 新建NAT记录
        if (sport != 0)
        {
            // ! 获取一个可用的端口号
            newPort = getNewNATPort(*rule);
            if (newPort == 0)
            { // 获取新端口失败,放弃NAT
                printk(KERN_WARNING "[fwnat] get new port failed!\n");
                return NF_ACCEPT;
            }
        }
        record = genNATRule(sip, rule->daddr, sport, newPort);
        // 记录在原连接中
        setConnNAT(conn, record, NAT_TYPE_SRC);
        rule->nowPort = newPort;
    }
    // ! 寻找反向的连接，如果没有则创建反向连接会话
    reverseConn = hasConn(dip, record.daddr, dport, record.dport, 0);
    if (reverseConn == NULL)
    { // 新建反向连接入连接池
        reverseConn = addConn(dip, record.daddr, dport, record.dport, proto, 0, 0);
        if (reverseConn == NULL)
        { // 创建反向连接失败,放弃NAT
            printk(KERN_WARNING "[fwnat] add reverse connection failed!\n");
            return NF_ACCEPT;
        }
        setConnNAT(reverseConn, genNATRule(record.daddr, sip, record.dport, sport), NAT_TYPE_DEST);
    }
    // 更新时间
    addConnExpires(reverseConn, CONN_EXPIRES * CONN_NAT_TIMES);
    addConnExpires(conn, CONN_EXPIRES * CONN_NAT_TIMES);
    // 修改数据包内容
    header->saddr = htonl(record.daddr);
    hdr_len = header->ihl * 4;
    tot_len = ntohs(header->tot_len);
    header->check = 0;
    header->check = ip_fast_csum(header, header->ihl);
    switch (proto)
    {
    case IPPROTO_TCP:
        tcpHeader = (struct tcphdr *)(skb->data + (header->ihl * 4));
        tcpHeader->source = htons(record.dport);
        tcpHeader->check = 0;
        skb->csum = csum_partial((unsigned char *)tcpHeader, tot_len - hdr_len, 0);
        tcpHeader->check = csum_tcpudp_magic(header->saddr, header->daddr,
                                             tot_len - hdr_len, header->protocol, skb->csum);
        break;
    case IPPROTO_UDP:
        udpHeader = (struct udphdr *)(skb->data + (header->ihl * 4));
        udpHeader->source = htons(record.dport);
        udpHeader->check = 0;
        skb->csum = csum_partial((unsigned char *)udpHeader, tot_len - hdr_len, 0);
        udpHeader->check = csum_tcpudp_magic(header->saddr, header->daddr,
                                             tot_len - hdr_len, header->protocol, skb->csum);
        break;
    case IPPROTO_ICMP:
    default:
        break;
    }
    return NF_ACCEPT;
}