#ifndef _API_APP_H
#define _API_APP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>

/* 用户层与内核层通用接口 */
#define MAXRuleNameLen 32 // 规则名称最大长度

/**
 * @brief:请求行为
 */
#define REQ_GETAllFTRULES 1 // 获取所有过滤规则
#define REQ_ADDFTRULE 2     // 添加过滤规则
#define REQ_DELFTRULES 3    // 删除过滤规则
#define REQ_SETACT 4        // 设置行为
#define REQ_GETAllLOGS 5    // 获取所有日志
#define REQ_GETAllCONNS 6   // 获取所有网络连接
#define REQ_ADDNATRULE 7    // 添加网络地址转换规则
#define REQ_DELNATRULE 8    // 删除网络地址转换规则
#define REQ_GETNATRULES 9   // 获取所有网络地址转换规则

/**
 *
 */
#define uint8_t unsigned char
#define NETLINK_MYFW 17
// 接收消息的最大载荷
#define MAX_PAYLOAD (1024 * 256)

/**
 * @brief:响应状态码
 */
#define ERROR_CODE_EXIT -1
#define ERROR_CODE_EXCHANGE -2  // 与内核交换信息失败
#define ERROR_CODE_WRONG_IP -11 // 错误的IP格式
#define ERROR_CODE_NO_SUCH_RULE -12

/**
 * @brief:响应体的类型
 */
#define RSP_NULL 10
#define RSP_MSG 11
#define RSP_FTRULES 12  // body为FTRule[]
#define RSP_FTLOGS 13   // body为IPlog[]
#define RSP_NATRULES 14 // body为NATRecord[]
#define RSP_CONNLOGS 15 // body为ConnLog[]

/**
 * @brief:内核响应头
 */
struct KernelResHdr
{
    unsigned int bodyTp; // 响应体的类型
    unsigned int arrayLen;
};

/**
 * @brief:内核响应的结构体
 */
struct KernelResp
{
    int stat;                    // 响应状态码
    void *data;                  // 响应数据
    struct KernelResHdr *header; // 响应主体头部
    void *body;                  // 响应主体
};

/**
 * @brief:用户输入过滤规则结构
 */
struct ftrule
{
    char name[MAXRuleNameLen + 1]; // 规则名
    char sip[25];                  // 源ip
    char tip[25];                  // 目的ip
    char sport[15];                // 源端口
    char tport[15];                // 目的端口
    char protocol[6];              // 协议
    unsigned int act;              // 对数据包的行为
    unsigned int islog;            // 是否记录日志
};

/**
 * @brief:用户输入nat规则结构
 */
struct natrule
{
    char sip[25];   // nat源地址
    char tip[25];   // nat地址
    char tport[15]; // 端口
};

/**
 * @brief:内核接受的过滤规则
 */
struct FTRule
{
    char name[MAXRuleNameLen + 1];
    unsigned int saddr;
    unsigned int smask;
    unsigned int taddr;
    unsigned int tmask;
    unsigned int sport;
    unsigned int tport;
    u_int8_t protocol;
    unsigned int act;
    unsigned int islog;
    struct FTRule *next;
};

/**
 * @brief:内核接受的nat规则
 */
struct NATRule
{
    unsigned int saddr; // 源IP
    unsigned int smask; // 源IP的掩码
    unsigned int daddr; // 转换后的IP

    unsigned short sport;   // 原始端口
    unsigned short dport;   // 转换后的端口
    unsigned short nowPort; // 当前使用的端口
    struct NATRule *next;
};

/**
 * @brief:用户层的请求结构
 */
struct UsrReq
{
    // 请求类型
    unsigned int tp;
    // 前序规则名
    char ruleName[MAXRuleNameLen + 1];
    // 请求体——过滤规则、NAT规则、默认动作
    union
    {
        struct FTRule FTRule;
        struct NATRule NATRule;
        unsigned int defaultAction;
        unsigned int num;
    } msg;
};

/**
 * @brief:用户层与内核通信函数的声明
 */
struct KernelResp addFtRule(struct ftrule *filter_rule); // 新增过滤规则
struct KernelResp getAllFTRules(void);                   // 获取所有过滤规则
struct KernelResp delFTRule(char name[]);                // 删除名为name的规则
struct KernelResp addNATRule(struct natrule *nat_rule);  // 新增nat规则
struct KernelResp getAllNATRules(void);                  // 获取所有nat规则
struct KernelResp delNATRule(int seq);                   // 删除序号为seq的nat规则
struct KernelResp setDefaultAction(unsigned int action); // 设置默认策略

/**
 * @brief:格式转换的工具函数
 */
int IPstr2IPint(const char *ipStr, unsigned int *ip, unsigned int *mask);
int IPint2IPstr(unsigned int ip, unsigned int mask, char *ipStr);
int IPint2IPstrNoMask(unsigned int ip, char *ipStr);
int IPint2IPstrWithPort(unsigned int ip, unsigned short port, char *ipStr);

#endif