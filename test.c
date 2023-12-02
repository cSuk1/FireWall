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