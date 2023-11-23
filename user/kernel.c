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

int showRules(struct FTRule *rules, int len)
{
    printf("获取所有过滤规则成功\n");
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