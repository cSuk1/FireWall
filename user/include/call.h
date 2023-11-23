#ifndef _CALL_H
#define _CALL_H

#include "api.h"

// 展示所有过滤规则
int showRules(struct FTRule *rules, int len);
// 展示nat规则
int showNATRules(struct NATRule *rules, int len);
// 展示连接
int showConns(struct ConnLog *logs, int len);
// 处理内核响应
void ProcKernelResp(struct KernelResp rsp);

#endif