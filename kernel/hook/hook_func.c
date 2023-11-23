/**
 * 钩子函数
 */
#include "hook_func.h"
#include "kernel_api.h"
#include "dep.h"

// 设置默认动作
unsigned int DEFAULT_ACTION = NF_ACCEPT;

/**
 * @brief:本地输入钩子，用于包过滤
 */
unsigned int NfHookLocalIn(void *priv, struct sk_buff *skb,
                           const struct nf_hook_state *state)
{
    int flag;
    // 接收匹配到的规则
    struct FTRule rule;
    flag = ftrule_match(skb, &rule);
    if (flag > -1)
    { // 查规则集，如果匹配到了
        printk(KERN_DEBUG "[rule match] match a rule the action is %d.\n", flag);
        return (flag == NF_ACCEPT) ? NF_ACCEPT : NF_DROP;
    }
    // 否则返回默认行为
    return DEFAULT_ACTION;
}

unsigned int NfHookLocalOut(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    return NF_ACCEPT;
}

unsigned int NfHookPreRouting(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    return NF_ACCEPT;
}

unsigned int NfHookForward(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    return NF_ACCEPT;
}

unsigned int NfHookPostRouting(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    return NF_ACCEPT;
}