/**
 * 对内核响应进行解析的一些函数
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
        break;
    }
    if (rsp.header->bodyTp != RSP_NULL && rsp.body != NULL)
    {
        free(rsp.data);
    }
}

int showRules(struct FTRule *rules, int len)
{
    printf("获取所有过滤规则成功");
}

int showNATRules(struct NATRule *rules, int len)
{
    printf("获取所有NAT规则成功");
}