#ifndef _NETLINK_API_H
#define _NETLINK_API_H

#include "dep.h"

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
// netlink协议号
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
    unsigned int bodyTp;
    unsigned int arrayLen;
};

/**
 *@brief:过滤规则结构
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
 * @brief:内核响应的结构体
 */
struct KernelResp
{
    int stat;                    // <0 代表请求失败，失败码; >=0 代表body长度
    void *data;                  // 回应包指针，记得free
    struct KernelResHdr *header; // 不要free；指向data中的头部
    void *body;                  // 不要free；指向data中的Body
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
    unsigned int tp;
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
 * 处理用户层发出的请求
 */
int ProcUsrReq(unsigned int pid, void *msg, unsigned int len);

/**
 * 新增过滤规则
 */
struct FTRule *addFTRule(char after[], struct FTRule rule);

/**
 * 获取所有过滤规则
 */
void *getAllFTRules(unsigned int *len);

/**
 * 删除过滤规则
 */
int delFTRule(char name[]);

/**
 * 过滤规则匹配
 */
int ftrule_match(struct sk_buff *skb, struct FTRule *rule);

/**
 * 添加nat规则
 */
struct NATRule *addNATRule(struct NATRule rule);

/**
 * 获取所有nat规则
 */
void *getAllNATRules(unsigned int *len);

/**
 * 删除nat规则
 */
int delNATRule(unsigned int seq);

/**
 * NETLINK_MYFW套接字发送消息给用户层
 */
int NLFWSend(unsigned int pid, void *data, unsigned int len);

/**
 * netlink sock的初始化与释放
 */
struct sock *netlink_init(void);
void netlink_release(void);

#endif