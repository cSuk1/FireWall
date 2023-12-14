# 基于 netfilter 的 Linux 系统防火墙

[toc]

## 功能完成情况

- [X] 用户层
- [X] 内核层
- [X] 通信
- [X] 规则过滤
- [X] 规则过滤 web 面板
- [X] 连接管理
- [X] 连接管理 web 面板
- [X] 状态防火墙
- [X] NAT
- [ ] NAT web 面板
- [ ] 日志记录
- [ ] 日志审计 web 面板
- [X] 基础 DOS 防御
- [ ] 远程登录 web 面板

## 项目概要

### 整体架构

- Web 端控制面板

  > 使用数据库存储过滤规则表和 NAT 规则表等数据，使用 B/S 架构直接对防火墙行为进行控制
  >
- 命令行管理工具

  > 可以使用提供的用户态的命令行工具进行防火墙的过滤规则和 NAT 规则的配置
  >
- 内核驱动模块

  > 在内核基于 NETFILTER 实现包过滤、NAT 等功能
  >

![image-20231213154809687](https://andromeda-1313240745.cos.ap-chengdu.myqcloud.com/2023/12/202312131548844.png)

### 设计思路

1、**Node + MySQL**

> Web 控制面板使用用户程序提供的命令行管理语法实现便利的的 B/S 架构 UI

2、**用户态程序**

> 用户程序向下使用内核驱动模块提供的接口，向上为 web 控制面板提供防火墙管理接口

3、**NETLINK 套接字**

> 使用 NETLINK 套接字和自定义的协议实现用户空间与内核空间的数据交换

4、**NETFILTER 框架**

> 使用 NETFILTER 提供的底层接口编写相关的内核驱动模块

### 开发环境

- 操作系统：Linux 5.15.0-89-generic #99~20.04.1-Ubuntu SMP Thu Nov 2 15:16:47 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
- C 编译器：gcc (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0
- 构建工具：GNU Make 4.2.1
- Node 运行环境：node v10.19.0
- 开发工具：visual studio code 1.85.0

## 关键数据结构与变量

用户请求类型和结构体如下，tp 为请求的类型。

使用了 `union`关键字来定义结构体 `UsrReq`成员 `msg`。可以实现在相同的内存空间中节省存储空间，因为每次请求只需要一种数据，因此只需要存储其中一种类型的数据。

```c
// tp请求类型
#define REQ_GETAllFTRULES 1 // 获取所有过滤规则
#define REQ_ADDFTRULE 2     // 添加过滤规则
#define REQ_DELFTRULES 3    // 删除过滤规则
#define REQ_SETACT 4        // 设置行为
#define REQ_GETAllLOGS 5    // 获取所有日志
#define REQ_GETAllCONNS 6   // 获取所有网络连接
#define REQ_ADDNATRULE 7    // 添加网络地址转换规则
#define REQ_DELNATRULE 8    // 删除网络地址转换规则
#define REQ_GETNATRULES 9   // 获取所有网络地址转换规则

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
```

内核响应状态码和响应结构体如下，stat 为内核返回第状态码。data 存储返回时数据，header 指针指向 data 中的头部，body 指针指向 data 中的数据载荷。

```c
// stat
#define RSP_NULL 10
#define RSP_MSG 11
#define RSP_FTRULES 12  // body为过滤规则
#define RSP_FTLOGS 13   // body为日志
#define RSP_NATRULES 14 // body为nat规则
#define RSP_CONNLOGS 15 // body为连接

struct KernelResp
{
    int stat;
    void *data;
    struct KernelResHdr *header;
    void *body;
};
```

过滤规则的结构体如下，包括 rulename、源地址、目的地址、源端口、目的端口、协议、策略、是否记录日志几个参数。

```c
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
```

NAT 规则结构体如下

```c
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
```

连接会话的结构体如下

```C
struct connSess
{
    struct rb_node node;
    conn_key_t key;        // 连接标识符
    unsigned long expires; // 超时时间
    u_int8_t syn;          // 记录syn数
    u_int8_t rate;         // 记录数据包到达的速率
    u_int8_t protocol;     // 协议
    u_int8_t needLog;      // 是否记录日志
    struct NATRule nat;    // 该连接对应的NAT记录
    int natType;           // NAT 转换类型
};
```

过滤规则链表和过滤规则表的读写自旋锁如下。前者维护过滤规则表，后者可以保证规则表可以同时被多个进程读取但不能同时被多个进程写入，用于保证规则表并发安全。

```c
// 规则链表
static struct FTRule *FTRuleHd = NULL;
// 规则链表锁，保证并发安全
static DEFINE_RWLOCK(FTRuleLock);
```

NAT 规则表和 NAT 规则表的读写自旋锁。

```c
// NAT规则链表
static struct NATRule *NATRuleHd = NULL;
// NAT规则链表锁，保证并发安全
static DEFINE_RWLOCK(NATRuleLock);
```

利用红黑树存储连接会话。红黑树是一种自平衡的二叉搜索树，它可以高效地查找数据。由于对于连接会话来说，数据包到达的频率远远大于新连接建立的频率，因此使用红黑树存储连接会话，能够大大降低数据包到达时匹配连接会话的时间复杂度。

同理，connLock 为连接会话表的读写自旋锁。

> 为什么不用红黑树来存储过滤规则呢？这样不是更快吗？
>
> 在开发的时候也考虑过使用红黑树来存储过滤规则，但是后来考虑到过滤规则具有先后顺序，应该返回匹配到的第一条规则，那么红黑树就不是最合适的数据结构，如果为了提高效率而增加配置维护的难度和降低安全性，那就是舍本逐末了。因此不使用红黑树来存储过滤规则。

```c
// 红黑树和读写锁
static struct rb_root connRoot = RB_ROOT;
static DEFINE_RWLOCK(connLock);
```

下面的六个钩子点，分别用于

- 本地入站规则检查
- 本地出站规则检查
- 预路由阶段处理数据包，处理 DNAT
- 预路由阶段过滤数据包，建立 NAT 连接
- 后路由阶段处理数据包，处理 SNAT
- 后路由阶段过滤数据包，建立 NAT 连接

```c
static struct nf_hook_ops NF_HKLocalIn;
static struct nf_hook_ops NF_HKLocalOut;
static struct nf_hook_ops NF_HKPreRouting;
static struct nf_hook_ops NF_HKPreRouting2;
static struct nf_hook_ops NF_HKPostRouting;
static struct nf_hook_ops NF_HKPostRouting2;
```

对数据包的默认策略，这个变量定义了对未匹配到规则的数据包的默认策略。

```c
// 设置默认动作
unsigned int DEFAULT_ACTION = NF_ACCEPT;
```

下面的两个变量用于在内核创建一个 sock 套接字并配置 netlink 内核套接字的参数。创建一个 `netlink_kernel_cfg`结构体变量，配置 netlink 内核套接字的行为和回调函数。

```c
// 创建一个套接字结构
static struct sock *nl_sock = NULL;

struct netlink_kernel_cfg nl_conf = {
    .groups = 0,
    .flags = 0,
    // 指定了一个回调函数NLFWRecv，用于在接收到 netlink 消息时进行处理
    // void (*input)(struct sk_buff *skb);
    .input = NLFWRecv,
    .cb_mutex = NULL,
    .bind = NULL,
    .unbind = NULL,
    .compare = NULL,
};
```

## NETLINK

> 使用 NETLINK 套接字实现用户空间与内核空间的数据交换。

### 用户空间

### 内核驱动

## NETFILTER

## 包过滤

## 连接状态

## NAT 网络地址转换

> 当内网主机访问互联网时，会建立两个连接会话 A->C 和 C->B，这两条会话都有对应的 NAT 记录，进入互联网的数据包首先进行过滤，放行则添加连接会话 A->C。在后路由阶段匹配连接会话 A->C 的 NAT 规则，修改源地址（如果是初次进入则会添加反向的连接会话 C->B 并创建对应的 NAT 规则）然后发送到互联网。从互联网进入内网的数据包先在预路由阶段检查是否存在连接会话，如果存在则根据连接会话 C->B 的 NAT 记录修改目的地址，并进行转发。
>
> 预路由阶段只处理 DNAT，后路由阶段只处理 SNAT。

SNAT 流程如下所示

![img](image/2.png)

DNAT 流程如下所示

![img](image/3.png)

## DoS 防御

> 大部分情况下，这样的防御方式只能说是小孩子过家家，根本招架不住正经的 DoS 或者 DDoS。所以这里的功能实现仅仅用于学习和巩固。

### SYN Flood

限制了来自单个 IP 的 SYN 数据包数量

![1](image/1.png)

### 流量限制

限制了来自单个 IP 的数据包到达速率

```C
needDel = rb_entry(node, struct connSess, node);
if (isTimeout(needDel->expires) || needDel->rate > MAX_RATE)
{
    // 删除
    if (needDel->rate > MAX_RATE)
    {
        ban_ip(needDel->key[0]);
    }
    hasChange = 1;
    break;
}
```

## web 管理面板
