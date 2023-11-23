/**
 * @file kernel_api.h
 * @author cSuk1 (652240843@qq.com)
 * @brief 内核接口
 * @version 0.1
 * @date 2023-11-23
 *
 *
 */
#ifndef _NETLINK_API_H
#define _NETLINK_API_H

#include "dep.h"

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

// 处理用户请求
int ProcUsrReq(unsigned int pid, void *msg, unsigned int len);

// 过滤规则相关
struct FTRule *addFTRule(char after[], struct FTRule rule);
void *getAllFTRules(unsigned int *len);
int delFTRule(char name[]);
int ftrule_match(struct sk_buff *skb, struct FTRule *rule);

// nat规则相关
struct NATRule *addNATRule(struct NATRule rule);
void *getAllNATRules(unsigned int *len);
int delNATRule(unsigned int seq);

// 连接会话表，根据会话表放行
// 红黑树结构，用于在Linux内核中进行高效的插入、删除和搜索操作。
#include <linux/rbtree.h>

#define CONN_NEEDLOG 0x10
#define CONN_MAX_SYM_NUM 3
#define CONN_EXPIRES 7       // 新建连接或已有连接刷新时的存活时长（秒）
#define CONN_NAT_TIMES 10    // NAT的超时时间倍率
#define CONN_ROLL_INTERVAL 5 // 定期清理超时连接的时间间隔（秒）

typedef unsigned int conn_key_t[CONN_MAX_SYM_NUM]; // 连接标识符，用于标明一个连接，可比较

struct connSess
{
    struct rb_node node;
    conn_key_t key;        // 连接标识符
    unsigned long expires; // 超时时间
    u_int8_t protocol;     // 协议
    struct NATRule nat;    // 该连接对应的NAT记录
    int natType;           // NAT 转换类型
};

void conn_init(void);
void conn_exit(void);
struct connSess *hasConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport);
struct connSess *addConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport, u_int8_t proto, u_int8_t log);

// netlink相关
int NLFWSend(unsigned int pid, void *data, unsigned int len);
struct sock *netlink_init(void);
void netlink_release(void);

#endif