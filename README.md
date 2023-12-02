- [x] 用户层
- [x] 内核层
- [x] 通信
- [x] 规则过滤
- [x] 规则过滤 web 面板
- [x] 连接管理
- [x] 连接管理 web 面板
- [x] 状态防火墙
- [ ] NAT 规则
- [ ] NAT 规则 web 面板
- [ ] 日志记录
- [ ] 日志审计 web 面板
- [x] 基础 DOS 防御——预防 SYN Flood
- [x] 基础 DOS 防御——限制单个连接的数据包到达速率
- [ ] 远程登录 web 面板

# 用户层

# 内核层

# NETLINK

# NETFILTER

# web 控制后台

# DoS 防御

> 大部分情况下，这样的防御方式只能说是小孩子过家家，根本招架不住正经的 DoS 或者 DDoS。所以这里的功能实现仅仅用于学习和巩固。

## SYN Flood

限制了来自单个 IP 的 SYN 数据包数量

![1](image/1.png)

## 流量限制

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
