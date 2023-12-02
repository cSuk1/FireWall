/**
 * @file kernel.c
 * @author cSuk1 (652240843@qq.com)
 * @brief 解析内核响应
 * @version 0.1
 * @date 2023-11-23
 *
 *
 */
#include "call.h"

void ProcKernelResp(struct KernelResp rsp)
{
    // 处理错误码
    switch (rsp.stat)
    {
    case ERROR_CODE_EXIT:
        exit(0);
        break;
    case ERROR_CODE_NO_SUCH_RULE:
        printf("no such rule.\n");
        return;
    case ERROR_CODE_WRONG_IP:
        printf("Incorrect IP format.\n");
        return;
    }
    if (rsp.stat < 0 || rsp.data == NULL || rsp.header == NULL || rsp.body == NULL)
        return;
    // 处理响应数据
    // 处理数据
    switch (rsp.header->bodyTp)
    {
        // 删除
    case RSP_NULL:
        printf("delete %d rule/rules.\n", rsp.header->arrayLen);
        break;
        // 添加过滤规则
    case RSP_MSG:
        printf("From kernel: %s\n", (char *)rsp.body);
        break;
        // 获取所有过滤规则
    case RSP_FTRULES:
        showRules((struct FTRule *)rsp.body, rsp.header->arrayLen);
        break;
    case RSP_NATRULES:
        // 获取所有nat规则
        showNATRules((struct NATRule *)rsp.body, rsp.header->arrayLen);
        break;
    case RSP_FTLOGS:
        break;
    case RSP_CONNLOGS:
        showConns((struct ConnLog *)rsp.body, rsp.header->arrayLen);
        break;
    }
    if (rsp.header->bodyTp != RSP_NULL && rsp.body != NULL)
    {
        free(rsp.data);
    }
}

void printLine(int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        printf("-");
    }
    printf("\n");
}

int showOneRule(struct FTRule rule)
{
    char saddr[25], daddr[25], sport[13], dport[13], proto[6], action[8], log[5];
    // ip
    IPint2IPstr(rule.saddr, rule.smask, saddr);
    IPint2IPstr(rule.taddr, rule.tmask, daddr);
    // port
    if (rule.sport == 0xFFFFu)
        strcpy(sport, "any");
    else if ((rule.sport >> 16) == (rule.sport & 0xFFFFu))
        sprintf(sport, "only %u", (rule.sport >> 16));
    else
        sprintf(sport, "%u~%u", (rule.sport >> 16), (rule.sport & 0xFFFFu));
    if (rule.tport == 0xFFFFu)
        strcpy(dport, "any");
    else if ((rule.tport >> 16) == (rule.tport & 0xFFFFu))
        sprintf(dport, "only %u", (rule.tport >> 16));
    else
        sprintf(dport, "%u~%u", (rule.tport >> 16), (rule.tport & 0xFFFFu));
    // action
    if (rule.act == NF_ACCEPT)
    {
        sprintf(action, "accept");
    }
    else if (rule.act == NF_DROP)
    {
        sprintf(action, "drop");
    }
    else
    {
        sprintf(action, "other");
    }
    // protocol
    if (rule.protocol == IPPROTO_TCP)
    {
        sprintf(proto, "TCP");
    }
    else if (rule.protocol == IPPROTO_UDP)
    {
        sprintf(proto, "UDP");
    }
    else if (rule.protocol == IPPROTO_ICMP)
    {
        sprintf(proto, "ICMP");
    }
    else if (rule.protocol == IPPROTO_IP)
    {
        sprintf(proto, "IP");
    }
    else
    {
        sprintf(proto, "other");
    }
    // log
    if (rule.islog)
    {
        sprintf(log, "yes");
    }
    else
    {
        sprintf(log, "no");
    }
    // print
    printf("| %-*s | %-18s | %-18s | %-11s | %-11s | %-8s | %-6s | %-3s |\n", MAXRuleNameLen,
           rule.name, saddr, daddr, sport, dport, proto, action, log);
    printLine(111);
}

int showRules(struct FTRule *rules, int len)
{
    int i;
    if (len == 0)
    {
        printf("No rules now.\n");
        return 0;
    }
    // printf("rule num: %d\n", len);
    printLine(111);
    printf("| %-*s | %-18s | %-18s | %-11s | %-11s | %-8s | %-6s | %-3s |\n", MAXRuleNameLen,
           "name", "source ip", "target ip", "source port", "target port", "protocol", "action", "log");
    printLine(111);
    for (i = 0; i < len; i++)
    {
        showOneRule(rules[i]);
    }
    return 0;
}

int showNATRules(struct NATRule *rules, int len)
{
    printf("获取所有NAT规则成功\n");
}

int showOneConn(struct ConnLog log)
{
    struct tm *timeinfo;
    char saddr[25], daddr[25], proto[6];
    // ip
    IPint2IPstrWithPort(log.saddr, log.sport, saddr);
    IPint2IPstrWithPort(log.daddr, log.dport, daddr);
    // protocol
    if (log.protocol == IPPROTO_TCP)
    {
        sprintf(proto, "TCP");
    }
    else if (log.protocol == IPPROTO_UDP)
    {
        sprintf(proto, "UDP");
    }
    else if (log.protocol == IPPROTO_ICMP)
    {
        sprintf(proto, "ICMP");
    }
    else if (log.protocol == IPPROTO_IP)
    {
        sprintf(proto, "any");
    }
    else
    {
        sprintf(proto, "other");
    }
    printf("%s %s %s\n", proto, saddr, daddr);
    // if (log.natType == NAT_TYPE_SRC)
    // {
    //     IPint2IPstrWithPort(log.nat.daddr, log.nat.dport, saddr);
    //     printf("| %-5s |=>%21s |->|  %21c | %11c |\n", "NAT", saddr, ' ', ' ');
    // }
    // else if (log.natType == NAT_TYPE_DEST)
    // {
    //     IPint2IPstrWithPort(log.nat.daddr, log.nat.dport, daddr);
    //     printf("| %-5s |  %21c |->|=>%21s | %11c |\n", "NAT", ' ', daddr, ' ');
    // }
}

int showConns(struct ConnLog *logs, int len)
{
    int i;
    if (len == 0)
    {
        printf("No connections now.\n");
        return 0;
    }
    printf("connection num: %d\n", len);
    for (i = 0; i < len; i++)
    {
        showOneConn(logs[i]);
    }
    return 0;
}