/**
 * @file operate.c
 * @author cSuk1 (652240843@qq.com)
 * @brief 发送消息到内核
 * @version 0.1
 * @date 2023-11-23
 *
 *
 */
#include "api.h"

/**
 * @brief:与内核进行通信
 * @param:消息内容
 * @param:消息长度
 * @return:内核响应
 */
struct KernelResp ComWithKernel(void *smsg, unsigned int slen)
{
    struct sockaddr_nl local;
    struct sockaddr_nl target;
    struct KernelResp rsp;
    int data_len, targetlen = sizeof(struct sockaddr_nl);
    /**
     * 创建一个套接字
     * PF_NETLINK 是套接字协议族，用于指定使用Netlink协议族的套接字。
     * SOCK_RAW 是套接字类型，指定使用原始套接字，以便可以直接访问底层协议。
     * NETLINK_MYFW 是自定义的Netlink协议标识符，用于识别特定的Netlink协议。
     */
    int skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_MYFW);
    // 套接字创建失败
    if (skfd < 0)
    {
        rsp.stat = ERROR_CODE_EXCHANGE;
        return rsp;
    }
    /**
     * 初始化local结构体并设置了Netlink套接字的本地地址
     * local.nl_family = AF_NETLINK;：将nl_family成员设置为AF_NETLINK，表示使用Netlink协议族。
     * local.nl_pid = getpid();：将nl_pid成员设置为当前进程的PID，即获取当前进程的进程ID。
     * local.nl_groups = 0;：将nl_groups成员设置为0，表示不加入任何多播组。
     */
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_pid = getpid();
    local.nl_groups = 0;
    // 将netlink套接字与local地址绑定
    if (bind(skfd, (struct sockaddr *)&local, sizeof(local)) != 0)
    {
        close(skfd);
        rsp.stat = ERROR_CODE_EXCHANGE;
        return rsp;
    }
    /**
     * 初始化并设置Netlink套接字的目标地址。
     * target.nl_family = AF_NETLINK;：将nl_family成员设置为AF_NETLINK，表示使用Netlink协议族。
     * target.nl_pid = 0;：将nl_pid成员设置为0，表示目标地址为内核空间，因为在Netlink通信中，0表示内核进程。
     * target.nl_groups = 0;：将nl_groups成员设置为0，表示不加入任何多播组。
     */
    memset(&target, 0, sizeof(target));
    target.nl_family = AF_NETLINK;
    target.nl_pid = 0;
    target.nl_groups = 0;
    // 为发送到内核的消息分配内存
    /**
     * LMSG_SPACE用于计算给定数据长度（slen）的Netlink消息所需的总空间大小。
     * NLMSG_SPACE宏会计算出消息头部和数据部分所需的空间，并将其转换为字节数。
     * 使用malloc函数分配足够的内存空间，以存储计算出的消息空间大小。
     * sizeof(uint8_t)是为了确保以字节为单位分配内存。
     */
    struct nlmsghdr *message = (struct nlmsghdr *)malloc(NLMSG_SPACE(slen) * sizeof(uint8_t));
    if (!message)
    {
        close(skfd);
        rsp.stat = ERROR_CODE_EXCHANGE;
        return rsp;
    }
    // 初始化内存
    memset(message, '\0', sizeof(struct nlmsghdr));
    // 设置消息长度
    message->nlmsg_len = NLMSG_SPACE(slen);
    // 设置标志、类型和序列号
    message->nlmsg_flags = 0;
    message->nlmsg_type = 0;
    message->nlmsg_seq = 0;
    // 设置消息的源进程号
    message->nlmsg_pid = local.nl_pid;
    // 从smsg中复制slen个字节到message的数据部分
    memcpy(NLMSG_DATA(message), smsg, slen);
    // 通过套接字发送消息
    if (!sendto(skfd, message, message->nlmsg_len, 0, (struct sockaddr *)&target, sizeof(target)))
    {
        close(skfd);
        free(message);
        rsp.stat = ERROR_CODE_EXCHANGE;
        return rsp;
    }
    // 通过套接字接收消息
    struct nlmsghdr *nl_hd = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD) * sizeof(uint8_t));
    if (!nl_hd)
    {
        close(skfd);
        free(message);
        rsp.stat = ERROR_CODE_EXCHANGE;
        return rsp;
    }
    if (!recvfrom(skfd, nl_hd, NLMSG_SPACE(MAX_PAYLOAD), 0, (struct sockaddr *)&target, (socklen_t *)&targetlen))
    {
        close(skfd);
        free(message);
        free(nl_hd);
        rsp.stat = ERROR_CODE_EXCHANGE;
        return rsp;
    }
    // 计算数据部分的额长度
    data_len = nl_hd->nlmsg_len - NLMSG_SPACE(0);
    rsp.data = malloc(data_len);
    if (!(rsp.data))
    {
        close(skfd);
        free(message);
        free(nl_hd);
        rsp.stat = ERROR_CODE_EXCHANGE;
        return rsp;
    }
    memset(rsp.data, 0, data_len);
    // 将收到的消息nl_hd的data_len个字节复制到rsp的data字段
    memcpy(rsp.data, NLMSG_DATA(nl_hd), data_len);
    rsp.stat = data_len - sizeof(struct KernelResHdr);
    if (rsp.stat < 0)
    {
        rsp.stat = ERROR_CODE_EXCHANGE;
    }
    // 指向响应头
    rsp.header = (struct KernelResHdr *)rsp.data;
    // 指向响应体
    rsp.body = rsp.data + sizeof(struct KernelResHdr);
    close(skfd);
    free(message);
    free(nl_hd);
    return rsp;
}

/**
 * @brief:格式化输出FTRule
 */
void printFTRule(struct ftrule *rule)
{
    printf("-------New Rule Info------\n");
    printf("规则名: %s\n", rule->name);
    printf("源地址: %s\n", rule->sip);
    printf("源端口: %s\n", rule->sport);
    printf("目的地址: %s\n", rule->tip);
    printf("目的端口: %s\n", rule->tport);
    printf("协议: %s\n", rule->protocol);
    printf("行为: %u\n", rule->act);
    printf("日志: %u\n", rule->islog);
    printf("--------------------------\n");
}

/**
 * @brief:格式化输出nat rule
 */
void printNATRule(struct natrule *rule)
{
    printf("-----New NAT Rule Info----\n");
    printf("转换前地址/掩码: %s\n", rule->sip);
    printf("转换后地址: %s\n", rule->tip);
    printf("转换端口范围: %s\n", rule->tport);
    printf("--------------------------\n");
}

/**
 * @brief:添加过滤规则的函数
 * @param:原始输入的过滤规则
 * @return:内核响应
 */
struct KernelResp addFtRule(struct ftrule *filter_rule)
{
    printFTRule(filter_rule);
    // 用户请求
    struct UsrReq req;
    // 内核响应
    struct KernelResp rsp;
    // 添加的规则
    struct FTRule rule;
    // 设置规则参数
    if (strcmp(filter_rule->sip, "any") == 0)
    {
        rule.saddr = 0;
        rule.smask = 0;
    }
    else
    {
        if (IPstr2IPint(filter_rule->sip, &rule.saddr, &rule.smask) != 0)
        {
            rsp.stat = ERROR_CODE_WRONG_IP;
            return rsp;
        }
    }
    if (IPstr2IPint(filter_rule->tip, &rule.taddr, &rule.tmask) != 0)
    {
        rsp.stat = ERROR_CODE_WRONG_IP;
        return rsp;
    }
    // 设置源地址和目的地址
    rule.saddr = rule.saddr;
    rule.taddr = rule.taddr;
    unsigned short sportMin, sportMax, tportMin, tportMax;
    // 设置源端口范围
    if (strcmp(filter_rule->sport, "any") == 0)
    {
        sportMin = 0, sportMax = 0xFFFFu;
    }
    else
    {
        sscanf(filter_rule->sport, "%hu-%hu", &sportMin, &sportMax);
    }
    // 如果最大端口小于最小端口
    if (sportMin > sportMax)
    {
        int temp = sportMin;
        sportMin = sportMax;
        sportMax = temp;
    }
    // 设置目的端口范围
    // 设置源端口范围
    if (strcmp(filter_rule->tport, "any") == 0)
    {
        tportMin = 0, tportMax = 0xFFFFu;
    }
    else
    {
        sscanf(filter_rule->tport, "%hu-%hu", &tportMin, &tportMax);
    }
    // 如果最大端口小于最小端口则换位置
    if (tportMin > tportMax)
    {
        tportMin = tportMax ^ tportMin;
        tportMax = tportMax ^ tportMin;
        tportMin = tportMin ^ tportMax;
    }
    // 高位为起始端口号，低位为末尾端口号
    rule.sport = (((unsigned int)sportMin << 16) | (((unsigned int)sportMax) & 0xFFFFu));
    rule.tport = (((unsigned int)tportMin << 16) | (((unsigned int)tportMax) & 0xFFFFu));
    rule.islog = filter_rule->islog;
    rule.act = filter_rule->act;
    // 设置过滤规则的协议
    if (strcmp(filter_rule->protocol, "TCP") == 0)
        rule.protocol = IPPROTO_TCP;
    else if (strcmp(filter_rule->protocol, "UDP") == 0)
        rule.protocol = IPPROTO_UDP;
    else if (strcmp(filter_rule->protocol, "ICMP") == 0)
        rule.protocol = IPPROTO_ICMP;
    else if (strcmp(filter_rule->protocol, "any") == 0)
        rule.protocol = IPPROTO_IP;
    else
    {
        rule.protocol = IPPROTO_IP;
    }
    // 设置规则名
    strncpy(rule.name, filter_rule->name, MAXRuleNameLen);
    // 设置请求行为为REQ_ADDFTRULE即添加过滤规则
    req.tp = REQ_ADDFTRULE;
    req.ruleName[0] = 0;
    // 设置前序规则名为空
    char after[MAXRuleNameLen + 1];
    strcpy(after, "");
    strncpy(req.ruleName, after, MAXRuleNameLen);
    req.msg.FTRule = rule;
    // 将用户请求发送给内核，与内核通信，获取内核响应
    return ComWithKernel(&req, sizeof(req));
}

/**
 * @brief:展示过滤规则的函数
 * @return:内核响应
 */
struct KernelResp getAllFTRules(void)
{
    // 用户请求
    struct UsrReq req;
    // 设置请求类型为REQ_GETAllFTRULES即获取所有过滤规则
    req.tp = REQ_GETAllFTRULES;
    // 将用户请求发送给内核，与内核通信，获取内核响应
    return ComWithKernel(&req, sizeof(req));
}

/**
 * @brief:删除规则
 * @param:rule name
 */
struct KernelResp delFTRule(char name[])
{
    // 用户请求
    struct UsrReq req;
    // 设置请求类型为REQ_DELFTRULES即删除一条过滤规则
    req.tp = REQ_DELFTRULES;
    strcpy(req.ruleName, name);
    // 将用户请求发送给内核，与内核通信，获取内核响应
    return ComWithKernel(&req, sizeof(req));
}

/**
 * @brief:新增nat规则
 */
struct KernelResp addNATRule(struct natrule *nat_rule)
{
    printNATRule(nat_rule);
    struct KernelResp rsp;
    struct UsrReq req;
    struct NATRule NATRule;
    unsigned short minport, maxport;
    // 进行IP地址的格式转化
    if (IPstr2IPint(nat_rule->tip, &NATRule.daddr, &NATRule.smask) != 0)
    {
        rsp.stat = ERROR_CODE_WRONG_IP;
        return rsp;
    }
    if (IPstr2IPint(nat_rule->sip, &NATRule.saddr, &NATRule.smask) != 0)
    {
        rsp.stat = ERROR_CODE_WRONG_IP;
        return rsp;
    }
    // 如果转换的端口为any
    if (strcmp(nat_rule->tport, "any") == 0)
    {
        minport = 0, maxport = 0xFFFFu;
    }
    // 取出端口范围
    else
    {
        sscanf(nat_rule->tport, "%hu-%hu", &minport, &maxport);
    }
    // 如果最大端口小于最小端口则换个位置
    if (minport > maxport)
    {
        // 颠倒范围
        minport = minport ^ maxport;
        maxport = minport ^ maxport;
        minport = maxport ^ minport;
    }
    NATRule.sport = minport;
    NATRule.dport = maxport;
    // 设置请求类型为增加一条nat规则
    req.tp = REQ_ADDNATRULE;
    // 设置请求体为一条NAT规则
    req.msg.NATRule = NATRule;
    // 发送消息到内核
    return ComWithKernel(&req, sizeof(req));
}

/**
 * @brief:获取所有nat规则
 */
struct KernelResp getAllNATRules(void)
{
    struct UsrReq req;
    // 设置请求类型为REQ_GETNATRULES即获取所有过滤规则
    req.tp = REQ_GETNATRULES;
    // 将用户请求发送给内核，与内核通信，获取内核响应
    return ComWithKernel(&req, sizeof(req));
}

/**
 * @brief:删除nat规则
 */
struct KernelResp delNATRule(int seq)
{
    // 用户请求
    struct UsrReq req;
    // 设置请求类型为REQ_DELNATRULE即删除一个nat规则
    req.tp = REQ_DELNATRULE;
    // 设置序号
    req.msg.num = seq;
    // 将用户请求发送给内核，与内核通信，获取内核响应
    return ComWithKernel(&req, sizeof(req));
}

/**
 * @brief：设置默认策略
 */
struct KernelResp setDefaultAction(unsigned int action)
{
    // 用户请求
    struct UsrReq req;
    // 设置默认行为
    req.tp = REQ_SETACT;
    // 设置默认行为
    req.msg.defaultAction = action;
    // 将用户请求发送给内核，与内核通信，获取内核响应
    return ComWithKernel(&req, sizeof(req));
}

/*******************************************************
 * @brief Get the All Conns object
 *
 * @return struct KernelResp
 * @author cSuk1 (652240843@qq.com)
 * @date 2023-11-23
 *******************************************************/
struct KernelResp getAllConns()
{
    // 用户请求
    struct UsrReq req;
    // 设置请求类型
    req.tp = REQ_GETAllCONNS;
    // 将用户请求发送给内核，与内核通信，获取内核响应
    return ComWithKernel(&req, sizeof(req));
}