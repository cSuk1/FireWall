/**
 * 过滤规则维护函数
 */
#include "kernel_api.h"

// 规则链表
static struct FTRule *FTRuleHd = NULL;
// 规则链表锁，保证并发安全
static DEFINE_RWLOCK(FTRuleLock);

/**
 * @brief:新增一条过滤规则
 * @param:前序规则名
 * @param:添加的规则
 */
struct FTRule *addFTRule(char after[], struct FTRule rule)
{
    struct FTRule *new_rule, *tmp;
    // 为新规则分配空间
    // GFP_KERNEL 表示内存分配在进程上下文中进行，
    // 并且请求的内存应该来自内核的内存池（kernel memory pool）。
    // 这意味着内存分配是在内核空间进行的，分配的内存可以由进程在内核中使用。
    new_rule = (struct FTRule *)kzalloc(sizeof(struct FTRule), GFP_KERNEL);
    if (new_rule == NULL)
    {
        printk(KERN_WARNING "[caixing fw] kzalloc for new ft rule fail.\n");
        return NULL;
    }
    memcpy(new_rule, &rule, sizeof(struct FTRule));
    // 新增规则至规则链表
    write_lock(&FTRuleLock);
    // if (rule.action != NF_ACCEPT)
    //     eraseConnRelated(rule); // 消除新增规则的影响
    // 如果链表为空，直接插入
    if (FTRuleHd == NULL)
    {
        FTRuleHd = new_rule;
        FTRuleHd->next = NULL;
        write_unlock(&FTRuleLock);
        return new_rule;
    }
    // 如果前序规则名为空
    if (strlen(after) == 0)
    {
        new_rule->next = FTRuleHd;
        FTRuleHd = new_rule;
        write_unlock(&FTRuleLock);
        return new_rule;
    }
    // 插入前序规则名之后
    for (tmp = FTRuleHd; tmp != NULL; tmp = tmp->next)
    {
        if (strcmp(tmp->name, after) == 0)
        {
            new_rule->next = tmp->next;
            tmp->next = new_rule;
            write_unlock(&FTRuleLock);
            return new_rule;
        }
    }
    // 添加失败
    write_unlock(&FTRuleLock);
    kfree(new_rule);
    return NULL;
}

/**
 * @brief：获取所有过滤规则
 * @param：承载数据长度
 * @return：所有规则的内存内容
 */
void *getAllFTRules(unsigned int *len)
{
    struct KernelResHdr *head;
    struct FTRule *tmp;
    void *mem, *p;
    unsigned int count;
    // 上锁
    read_lock(&FTRuleLock);
    // 计算规则个数count
    for (tmp = FTRuleHd, count = 0; tmp != NULL; tmp = tmp->next, count++)
        ;
    // 分配内存空间
    *len = sizeof(struct KernelResHdr) + sizeof(struct FTRule) * count;
    mem = kzalloc(*len, GFP_ATOMIC);
    if (mem == NULL)
    {
        printk(KERN_WARNING "[caixing fw] kernel kzalloc fail.\n");
        read_unlock(&FTRuleLock);
        return NULL;
    }
    head = (struct KernelResHdr *)mem;
    // 设置内核响应头
    head->bodyTp = RSP_FTRULES;
    head->arrayLen = count;
    for (tmp = FTRuleHd, p = (mem + sizeof(struct KernelResHdr)); tmp != NULL; tmp = tmp->next, p = p + sizeof(struct FTRule))
        memcpy(p, tmp, sizeof(struct FTRule));
    read_unlock(&FTRuleLock);
    return mem;
}

/**
 * @brief:删除名为name的过滤规则
 * @param:规则名
 * @return:删除的规则个数
 */
int delFTRule(char name[])
{
    // 用于遍历规则链表
    struct FTRule *tmp;
    // 删除的规则个数
    int ret = 0;
    // 遍历规则链表
    // 上锁
    read_lock(&FTRuleLock);
    // 如果链表头为 name
    while (FTRuleHd != NULL && strcmp(FTRuleHd->name, name) == 0)
    {
        struct FTRule *delRule = FTRuleHd;
        FTRuleHd = FTRuleHd->next;
        kfree(delRule);
        ret++;
    }
    for (tmp = FTRuleHd; tmp != NULL && tmp->next != NULL;)
    {
        // 匹配到一条规则
        if (strcmp(tmp->next->name, name) == 0)
        {
            // 保存被删除规则的指针
            struct FTRule *delRule = tmp->next;
            // 被删除规则前一个规则的next指针移向next的next
            tmp->next = tmp->next->next;
            // 释放被删除指针
            kfree(delRule);
            ret++;
        }
        else
        {
            tmp = tmp->next;
        }
    }
    // 解锁
    read_unlock(&FTRuleLock);
    return ret;
}

/**
 * @brief:过滤规则的匹配
 * @param:struct FTRule
 * @param:匹配到的过滤规则（如果有）
 * @return:1-匹配到 0未匹配
 */
int ftrule_match(struct sk_buff *skb, struct FTRule *rule)
{
    int ismatch = -1;
    // 用于遍历规则链表
    struct FTRule *tmp;
    // 获取ip头
    struct iphdr *hdr = ip_hdr(skb);
    // 传输层报文头
    struct tcphdr *tcpHeader;
    struct udphdr *udpHeader;
    // 源ip和目的ip，并从网络字节顺序转为主机字节顺序
    unsigned int sip = ntohl(hdr->saddr);
    unsigned int tip = ntohl(hdr->daddr);
    // 源端口和目的端口
    unsigned short src_port, dst_port;
    // 协议
    u_int8_t proto = hdr->protocol;
    switch (proto)
    {
        // 传输层协议为tcp
    case IPPROTO_TCP:
        tcpHeader = (struct tcphdr *)(skb->data + (hdr->ihl * 4));
        src_port = ntohs(tcpHeader->source);
        dst_port = ntohs(tcpHeader->dest);
        break;
        // 传输层协议为udp
    case IPPROTO_UDP:
        udpHeader = (struct udphdr *)(skb->data + (hdr->ihl * 4));
        src_port = ntohs(udpHeader->source);
        dst_port = ntohs(udpHeader->dest);
        break;
        // ICMP
    case IPPROTO_ICMP:
        // 默认情况
    default:
        src_port = 0;
        dst_port = 0;
        break;
    }
    // 遍历规则链表
    // 上锁
    read_lock(&FTRuleLock);
    for (tmp = FTRuleHd; tmp != NULL; tmp = tmp->next)
    {
        // 匹配到一条规则
        if (((sip & tmp->smask) == (tmp->saddr & tmp->smask) || tmp->saddr == 0) &&
            ((tip & tmp->tmask) == (tmp->taddr & tmp->tmask)) &&
            (src_port >= ((unsigned short)(tmp->sport >> 16)) && src_port <= ((unsigned short)(tmp->sport & 0xFFFFu))) &&
            (dst_port >= ((unsigned short)(tmp->tport >> 16)) && dst_port <= ((unsigned short)(tmp->tport & 0xFFFFu))) &&
            (tmp->protocol == IPPROTO_IP || tmp->protocol == proto))
        {
            if (tmp->act == NF_ACCEPT)
            {
                ismatch = 1;
            }
            else
            {
                ismatch = 0;
            }

            // 赋值匹配到的规则
            rule = tmp;
            break;
        }
    }
    // 解锁
    read_unlock(&FTRuleLock);
    return ismatch;
}