#ifndef _HOOK_FUNC_H
#define _HOOK_FUNC_H
/**
 * 声明netfilter的五个钩子函数
 */
#include "dep.h"

/**
 * 表示本地输入（Local Input）钩子函数的操作。
 * 该钩子函数在数据包到达本地系统后被调用。
 */
unsigned int NfHookLocalIn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

/**
 * 表示本地输出（Local Output）钩子函数的操作。
 * 该钩子函数在本地系统产生数据包后被调用。
 */
unsigned int NfHookLocalOut(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

/**
 * 表示预路由（Pre-Routing）钩子函数的操作。
 * 该钩子函数在数据包进入网络协议栈之前被调用。
 */
unsigned int NfHookPreRouting(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

/**
 * 表示转发（Forward）钩子函数的操作。
 * 该钩子函数在数据包转发过程中被调用。
 */
unsigned int NfHookForward(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

/**
 * 表示后路由（Post-Routing）钩子函数的操作。
 * 该钩子函数在数据包离开网络协议栈之前被调用。
 */
unsigned int NfHookPostRouting(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

#endif