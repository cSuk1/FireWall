/**
 * @file nat_rule.c
 * @author cSuk1 (652240843@qq.com)
 * @brief nat规则
 * @version 0.1
 * @date 2023-11-23
 *
 *
 */
#include "kernel_api.h"

// NAT规则链表
static struct NATRule *NATRuleHd = NULL;
// NAT规则链表锁，保证并发安全
static DEFINE_RWLOCK(NATRuleLock);

/**
 * @brief：新增nat规则链表
 * @param：nat规则
 * @return：nat规则
 */
struct NATRule *addNATRule(struct NATRule rule)
{
    // 为新规则分配内存空间
    struct NATRule *new_rule;
    new_rule = (struct NATRule *)kzalloc(sizeof(struct NATRule), GFP_KERNEL);
    if (new_rule == NULL)
    {
        printk(KERN_WARNING "[caixing fw] kzalloc for new nat rule fail.\n");
        return NULL;
    }
    // 复制规则到内存空间
    memcpy(new_rule, &rule, sizeof(struct NATRule));
    // 获取写锁
    write_lock(&NATRuleLock);
    if (NATRuleHd == NULL)
    {
        // 将新规则放入规则表
        NATRuleHd = new_rule;
        NATRuleHd->next = NULL;
        // 释放写锁
        write_unlock(&NATRuleLock);
        return new_rule;
    }
    // 将新规则放在链表第一个位置
    new_rule->next = NATRuleHd;
    NATRuleHd = new_rule;
    // 释放写锁
    write_unlock(&NATRuleLock);
    return new_rule;
}

/**
 * @brief：获取所有nat规则
 * @param：承载数据长度
 * @return：所有规则的内存内容
 */
void *getAllNATRules(unsigned int *len)
{
    // 响应头
    struct KernelResHdr *head;
    // nat规则
    struct NATRule *tmp;
    void *mem, *p;
    unsigned int count;
    // 上锁
    read_lock(&NATRuleLock);
    // 计算规则个数count
    for (tmp = NATRuleHd, count = 0; tmp != NULL; tmp = tmp->next, count++)
        ;
    // 为响应体分配内存空间
    *len = sizeof(struct KernelResHdr) + sizeof(struct NATRule) * count;
    mem = kzalloc(*len, GFP_ATOMIC);
    if (mem == NULL)
    {
        printk(KERN_WARNING "[caixing fw] kernel kzalloc fail.\n");
        // 释放锁
        read_unlock(&NATRuleLock);
        return NULL;
    }
    head = (struct KernelResHdr *)mem;
    // 设置内核响应头
    head->bodyTp = RSP_NATRULES;
    head->arrayLen = count;
    for (tmp = NATRuleHd, p = (mem + sizeof(struct KernelResHdr)); tmp != NULL; tmp = tmp->next, p = p + sizeof(struct NATRule))
        memcpy(p, tmp, sizeof(struct NATRule));
    read_unlock(&NATRuleLock);
    // 返回内存内容
    return mem;
}

/**
 * @brief：删除nat规则
 * @param：规则序号
 */
int delNATRule(unsigned int seq)
{
    struct NATRule *now, *tmp;
    int count = 0;
    // 获取锁
    write_lock(&NATRuleLock);
    // 如果删除第一个nat规则，直接对头节点操作
    if (seq == 0)
    {
        tmp = NATRuleHd;
        NATRuleHd = NATRuleHd->next;
        kfree(tmp);
        write_unlock(&NATRuleLock);
        return 1;
    }
    // 否则遍历规则表找到序号为seq的规则并删除
    for (now = NATRuleHd, count = 1; now != NULL && now->next != NULL; now = now->next, count++)
    {
        if (count == seq)
        { // 删除规则
            tmp = now->next;
            now->next = now->next->next;
            kfree(tmp);
            write_unlock(&NATRuleLock);
            return 1;
        }
    }
    // 释放锁
    write_unlock(&NATRuleLock);
    return 0;
}

// 匹配ip
bool isIPMatch(unsigned int ipl, unsigned int ipr, unsigned int mask)
{
    return (ipl & mask) == (ipr & mask);
}

/*******************************************************
 * @brief 匹配nat规则
 *
 * @param sip
 * @param dip
 * @param isMatch
 * @return struct NATRule*
 * @author Andromeda (ech0uname@qq.com)
 * @date 2023-12-09
 *******************************************************/
struct NATRule *matchNATRule(unsigned int sip, unsigned int dip, int *isMatch)
{
    struct NATRule *now;
    *isMatch = 0;
    read_lock(&NATRuleLock);
    for (now = NATRuleHd; now != NULL; now = now->next)
    {
        if (isIPMatch(sip, now->saddr, now->smask) &&
            !isIPMatch(dip, now->saddr, now->smask) &&
            dip != now->daddr)
        {
            read_unlock(&NATRuleLock);
            *isMatch = 1;
            return now;
        }
    }
    read_unlock(&NATRuleLock);
    return NULL;
}

/*******************************************************
 * @brief 获取nat记录
 *
 * @param preIP
 * @param afterIP
 * @param prePort
 * @param afterPort
 * @return struct NATRule
 * @author Andromeda (ech0uname@qq.com)
 * @date 2023-12-09
 *******************************************************/
struct NATRule genNATRule(unsigned int preIP, unsigned int afterIP, unsigned short prePort, unsigned short afterPort)
{
    struct NATRule rule;
    rule.saddr = preIP;
    rule.sport = prePort;
    rule.daddr = afterIP;
    rule.dport = afterPort;
    return rule;
}