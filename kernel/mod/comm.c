/**
 * 处理用户空间请求
 */
#include "kernel_api.h"

// 声明改变量在其他地方定义
extern unsigned int DEFAULT_ACTION;

/**
 * @brief:发送消息到用户层
 * @param:pid，用户进程id
 * @param:msg，发送的消息
 * @return:内核响应长度
 */
int sendmsg(unsigned int pid, const char *msg)
{
    // 分配空间
    void *mem;
    unsigned int rsp_len;
    struct KernelResHdr *rsp_hdr;
    rsp_len = sizeof(struct KernelResHdr) + strlen(msg) + 1;
    mem = kzalloc(rsp_len, GFP_ATOMIC);
    if (mem == NULL)
    {
        printk(KERN_WARNING "[caixing fw] sendmsg kzalloc fail.\n");
        return 0;
    }
    // 构造响应数据包
    rsp_hdr = (struct KernelResHdr *)mem;
    rsp_hdr->bodyTp = RSP_MSG;
    rsp_hdr->arrayLen = strlen(msg);
    memcpy(mem + sizeof(struct KernelResHdr), msg, strlen(msg));
    // 发送响应
    NLFWSend(pid, mem, rsp_len);
    // 释放内存
    kfree(mem);
    return rsp_len;
}

/**
 * @brief:处理用户请求
 */
int ProcUsrReq(unsigned int pid, void *msg, unsigned int len)
{
    // 用户请求
    struct UsrReq *req;
    // 响应头
    struct KernelResHdr *rsp_hdr;
    void *mem;
    // 响应长度
    unsigned int rsp_len = 0;
    // 删除的规则个数
    int cnt = 0;
    // 将消息转为用户请求
    req = (struct UsrReq *)msg;
    // 匹配用户请求行为
    switch (req->tp)
    {
        /**
         * 过滤规则的操作
         */
        // 新增过滤规则
    case REQ_ADDFTRULE:
        // 添加规则
        if (addFTRule(req->ruleName, req->msg.FTRule) == NULL)
        {
            rsp_len = sendmsg(pid, "Fail to add a new filter rule");
            printk("[caixing fw] add a rule fail.\n");
        }
        else
        {
            rsp_len = sendmsg(pid, "Add a new filter rule successfully.");
            printk("[caixing fw] add a rule success: %s.\n", req->msg.FTRule.name);
        }
        break;
    // 读取所有规则
    case REQ_GETAllFTRULES:
        // 获取所有规则
        mem = getAllFTRules(&rsp_len);
        if (mem == NULL)
        {
            printk(KERN_WARNING "[caixing fw] kernel get all rules fail.\n");
            sendmsg(pid, "get all rules fail.");
            break;
        }
        // 将获取的所有规则发送给用户
        NLFWSend(pid, mem, rsp_len);
        kfree(mem);
        break;
    // 删除过滤规则
    case REQ_DELFTRULES:
        rsp_len = sizeof(struct KernelResHdr);
        // 分配空间
        rsp_hdr = (struct KernelResHdr *)kzalloc(rsp_len, GFP_KERNEL);
        if (rsp_hdr == NULL)
        {
            printk(KERN_WARNING "[caixing fw] kernel allloc mem fail.\n");
            sendmsg(pid, "fail to delete the rule.");
            break;
        }
        rsp_hdr->bodyTp = RSP_NULL;
        // 删除名为req->ruleName的规则
        cnt = delFTRule(req->ruleName);
        // 当cnt=0时
        if (cnt <= 0)
        {
            printk("[caixing fw] no rule named %s.\n", req->ruleName);
            sendmsg(pid, "no rule named this.\n");
            break;
        }
        printk("[caixing fw] delete rule success: %s.\n", req->ruleName);
        rsp_hdr->arrayLen = cnt;
        NLFWSend(pid, rsp_hdr, rsp_len);
        // 释放空间
        kfree(rsp_hdr);
        break;
    /**
     * nat规则的操作
     */
    case REQ_ADDNATRULE:
        // 添加规则
        if (addNATRule(req->msg.NATRule) == NULL)
        {
            rsp_len = sendmsg(pid, "Fail to add a new NAT rule");
            printk("[caixing fw] add a NAT rule fail.\n");
        }
        else
        {
            rsp_len = sendmsg(pid, "Add a new NAT rule successfully.");
            printk("[caixing fw] add a NAT rule success.\n");
        }
        break;
    case REQ_GETNATRULES:
        // 获取所有规则
        mem = getAllNATRules(&rsp_len);
        if (mem == NULL)
        {
            printk(KERN_WARNING "[caixing fw] kernel get all NAT rules fail.\n");
            sendmsg(pid, "get all NAT rules fail.");
            break;
        }
        // 将获取的所有规则发送给用户
        NLFWSend(pid, mem, rsp_len);
        kfree(mem);
        break;
    case REQ_DELNATRULE:
        // 删除一个nat规则
        // 分配响应空间
        rsp_len = sizeof(struct KernelResHdr);
        rsp_hdr = (struct KernelResHdr *)kzalloc(rsp_len, GFP_KERNEL);
        // 分配失败
        if (rsp_hdr == NULL)
        {
            printk(KERN_WARNING "[caixing fw] kzalloc fail.\n");
            sendmsg(pid, "form rsp fail but del maybe success.");
            break;
        }
        // 设置响应类型
        rsp_hdr->bodyTp = RSP_NULL;
        rsp_hdr->arrayLen = delNATRule(req->msg.num);
        printk("[caixing fw] success del %d NAT rules.\n", rsp_hdr->arrayLen);
        // 发送响应给用户空间
        NLFWSend(pid, rsp_hdr, rsp_len);
        kfree(rsp_hdr);
        break;
    case REQ_SETACT:
        // 设置默认策略
        if (req->msg.defaultAction == NF_ACCEPT)
        {
            DEFAULT_ACTION = NF_ACCEPT;
            rsp_len = sendmsg(pid, "Set default action to ACCEPT.");
            printk("[caixing fw] Set default action to NF_ACCEPT.\n");
        }
        else
        {
            DEFAULT_ACTION = NF_DROP;
            rsp_len = sendmsg(pid, "Set default action to DROP.");
            printk("[caixing fw] Set default action to NF_DROP.\n");
        }
        break;
    default:
        rsp_len = sendmsg(pid, "unexcepted req type");
        break;
    }
    return rsp_len;
}