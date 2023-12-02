/*******************************************************
 * @file connect.c
 * @author cSuk1 (652240843@qq.com)
 * @brief
 * @version 0.1
 * @date 2023-11-23
 *
 *
 *******************************************************/

#include "kernel_api.h"

// 红黑树和读写锁
static struct rb_root connRoot = RB_ROOT;
static DEFINE_RWLOCK(connLock);

// 红黑树操作相关
/*******************************************************
 * @brief 比较连接标识符
 *
 * @param l
 * @param r
 * @return int
 * @author cSuk1 (652240843@qq.com)
 * @date 2023-11-23
 *******************************************************/
int connKeyCmp(conn_key_t l, conn_key_t r)
{
    register int i;
    for (i = 0; i < CONN_MAX_SYM_NUM; i++)
    {
        if (l[i] != r[i])
        {
            return (l[i] < r[i]) ? -1 : 1;
        }
    }
    return 0;
}

/*******************************************************
 * @brief 插入节点
 *
 * @param root
 * @param data
 * @return struct connSess*
 * @author cSuk1 (652240843@qq.com)
 * @date 2023-11-23
 *******************************************************/
struct connSess *insertNode(struct rb_root *root, struct connSess *data)
{
    struct rb_node **new, *parent;
    if (data == NULL)
    {
        return NULL;
    }
    parent = NULL;
    read_lock(&connLock);
    new = &(root->rb_node);
    /* Figure out where to put new node */
    while (*new)
    {
        struct connSess *this = rb_entry(*new, struct connSess, node);
        int result = connKeyCmp(data->key, this->key);
        parent = *new;
        if (result < 0)
            new = &((*new)->rb_left);
        else if (result > 0)
            new = &((*new)->rb_right);
        else
        { // 已存在
            read_unlock(&connLock);
            return this;
        }
    }
    /* Add new node and rebalance tree. */
    read_unlock(&connLock);
    write_lock(&connLock);
    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, root);
    write_unlock(&connLock);
    return data; // 插入成功
}

/*******************************************************
 * @brief 按标识符查找节点，无该节点返回则NULL
 *
 * @param root
 * @param key
 * @return struct connSess*
 * @author cSuk1 (652240843@qq.com)
 * @date 2023-11-23
 *******************************************************/
struct connSess *searchNode(struct rb_root *root, conn_key_t key)
{
    int result;
    struct rb_node *node;
    read_lock(&connLock);
    node = root->rb_node;
    while (node)
    {
        struct connSess *data = rb_entry(node, struct connSess, node);
        result = connKeyCmp(key, data->key);
        if (result < 0)
            node = node->rb_left;
        else if (result > 0)
            node = node->rb_right;
        else
        { // 找到节点
            read_unlock(&connLock);
            return data;
        }
    }
    read_unlock(&connLock);
    return NULL;
}

/*******************************************************
 * @brief 删除一个会话
 *
 * @param root
 * @param node
 * @author cSuk1 (652240843@qq.com)
 * @date 2023-11-23
 *******************************************************/
void eraseNode(struct rb_root *root, struct connSess *node)
{
    if (node != NULL)
    {
        // 获取连接锁
        write_lock(&connLock);
        // 从红黑树中删除该节点
        rb_erase(&(node->node), root);
        // 释放连接锁
        write_unlock(&connLock);
        // 释放该节点
        kfree(node);
    }
}

/*******************************************************
 * @brief 删除连接
 *
 * @param node
 * @author cSuk1 (652240843@qq.com)
 * @date 2023-12-02
 *******************************************************/
void delConn(struct connSess *node)
{
    if (node == NULL)
    {
        return;
    }
    read_lock(&connLock);
    eraseNode(&connRoot, node);
    read_unlock(&connLock);
}

/*******************************************************
 * @brief 添加一条连接
 *
 * @param sip
 * @param dip
 * @param sport
 * @param dport
 * @param proto
 * @param log
 * @return struct connSess*
 * @author cSuk1 (652240843@qq.com)
 * @date 2023-11-23
 *******************************************************/
struct connSess *addConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport, u_int8_t proto, u_int8_t log, u_int8_t issyn)
{
    // 初始化
    struct connSess *node = (struct connSess *)kzalloc(sizeof(struct connSess), GFP_ATOMIC);
    if (node == NULL)
    {
        printk(KERN_WARNING "[caixing fw] addconn kzalloc fail.\n");
        return 0;
    }
    // 初始化节点
    node->needLog = log;
    node->protocol = proto;
    node->syn = issyn;
    node->rate = 1;
    // printk("[issyn]%u\n", node->syn);
    node->expires = timeFromNow(CONN_EXPIRES); // 设置超时时间
    node->natType = NAT_TYPE_NO;
    // 构建标识符
    node->key[0] = sip;
    node->key[1] = dip;
    node->key[2] = ((((unsigned int)sport) << 16) | ((unsigned int)dport));
    // 插入节点
    return insertNode(&connRoot, node);
}

/*******************************************************
 * @brief 是否超时
 *
 * @param expires
 * @return int
 * @author cSuk1 (652240843@qq.com)
 * @date 2023-11-23
 *******************************************************/
int isTimeout(unsigned long expires)
{
    return (jiffies >= expires) ? 1 : 0; // 当前时间 >= 超时时间 ?
}

/*******************************************************
 * @brief 重新设置超时时间
 *
 * @param node
 * @param plus
 * @author cSuk1 (652240843@qq.com)
 * @date 2023-11-23
 *******************************************************/
void addConnExpires(struct connSess *node, unsigned int plus)
{
    if (node == NULL)
        return;
    write_lock(&connLock);
    node->expires = timeFromNow(plus);
    write_unlock(&connLock);
}

/*******************************************************
 * @brief 检查是否存在连接，存在连接则直接放行
 *
 * @param sip
 * @param dip
 * @param sport
 * @param dport
 * @return struct connSess*
 * @author cSuk1 (652240843@qq.com)
 * @date 2023-11-23
 *******************************************************/
struct connSess *hasConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport, u_int8_t issyn)
{
    conn_key_t key;
    struct connSess *node = NULL;
    // 构建标识符
    key[0] = sip;
    key[1] = dip;
    key[2] = ((((unsigned int)sport) << 16) | ((unsigned int)dport));
    // 查找节点
    node = searchNode(&connRoot, key);
    if (node != NULL)
    {
        node->syn += issyn;
        node->rate += 1;
        // printk("[issyn]%u\n", node->syn);
        addConnExpires(node, CONN_EXPIRES); // 重新设置超时时间
        return node;
    }
    else
    {
        return NULL;
    }
}

/*******************************************************
 * @brief Get the All Connections object
 *
 * @param len
 * @return void*
 * @author cSuk1 (652240843@qq.com)
 * @date 2023-11-23
 *******************************************************/
void *getAllConnections(unsigned int *len)
{
    // 返回数据包头
    struct KernelResHdr *head;
    // 返回数据包节点
    struct rb_node *node;
    // 当前会话
    struct connSess *now;
    // 日志信息
    struct ConnLog log;
    // 内存空间
    void *mem, *p;
    // 返回数据包长度
    unsigned int count;
    // 获取连接日志信息
    read_lock(&connLock);
    // 计算总量
    for (node = rb_first(&connRoot), count = 0; node; node = rb_next(node), count++)
        ;
    // 分配返回数据空间
    *len = sizeof(struct KernelResHdr) + sizeof(struct ConnLog) * count;
    mem = kzalloc(*len, GFP_ATOMIC);
    if (mem == NULL)
    {
        printk(KERN_WARNING "[caixing fw] getconns kzalloc fail.\n");
        read_unlock(&connLock);
        return NULL;
    }
    // 构建返回数据包
    head = (struct KernelResHdr *)mem;
    // 响应类型
    head->bodyTp = RSP_CONNLOGS;
    head->arrayLen = count;
    p = (mem + sizeof(struct KernelResHdr));
    // 遍历连接日志信息
    for (node = rb_first(&connRoot); node; node = rb_next(node), p = p + sizeof(struct ConnLog))
    {
        now = rb_entry(node, struct connSess, node);
        log.saddr = now->key[0];
        log.daddr = now->key[1];
        log.sport = (unsigned short)(now->key[2] >> 16);
        log.dport = (unsigned short)(now->key[2] & 0xFFFFu);
        log.protocol = now->protocol;
        log.natType = now->natType;
        log.nat = now->nat;
        memcpy(p, &log, sizeof(struct ConnLog));
    }
    read_unlock(&connLock);
    return mem;
}

// 对超时连接的处理
/*******************************************************
 * @brief 删除超时连接
 *
 * @return int
 * @author cSuk1 (652240843@qq.com)
 * @date 2023-11-23
 *******************************************************/
int rollConn(void)
{
    struct rb_node *node;
    struct connSess *needDel = NULL;
    int hasChange = 1; // 连接池是否有更改（删除节点）
    while (hasChange)
    { // 有更改时，持续遍历，防止漏下节点
        hasChange = 0;
        read_lock(&connLock);
        for (node = rb_first(&connRoot); node; node = rb_next(node))
        {
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
            else
            {
                needDel->rate = 0;
            }
        }
        read_unlock(&connLock);
        if (hasChange)
        { // 需要删除 开始删除节点
            eraseNode(&connRoot, needDel);
        }
    }
    return 0;
}

/*******************************************************
 * @brief 定时器部分
 *
 * @author cSuk1 (652240843@qq.com)
 * @date 2023-11-23
 *******************************************************/
static struct timer_list conn_timer; // 定义计时器

// 计时器回调函数
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
void conn_timer_callback(unsigned long arg)
{
#else
void conn_timer_callback(struct timer_list *t)
{
#endif
    // 调用rollConn函数，更新连接状态
    rollConn();
    // 重新激活定时器，每隔CONN_ROLL_INTERVAL时间调用一次rollConn函数
    mod_timer(&conn_timer, timeFromNow(CONN_ROLL_INTERVAL)); // 重新激活定时器
}

/*******************************************************
 * @brief 连接池初始化
 *
 * @author cSuk1 (652240843@qq.com)
 * @date 2023-11-23
 *******************************************************/
void conn_init(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
    // 初始化定时器
    init_timer(&conn_timer);
    conn_timer.function = &conn_timer_callback; // 设置定时器回调方法
    conn_timer.data = ((unsigned long)0);
#else
    // 初始化定时器
    timer_setup(&conn_timer, conn_timer_callback, 0);
#endif
    conn_timer.expires = timeFromNow(CONN_ROLL_INTERVAL); // 超时时间设置为CONN_ROLL_INTERVAL秒后
    add_timer(&conn_timer);                               // 激活定时器
}

// 关闭连接池
void conn_exit(void)
{
    del_timer(&conn_timer);
}