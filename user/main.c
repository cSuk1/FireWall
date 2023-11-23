/**
 * @file main.c
 * @author cSuk1 (652240843@qq.com)
 * @brief 主函数
 * @version 0.1
 * @date 2023-11-23
 *
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include "call.h"

void PrintUsage()
{
    printf("usage:\n");
    printf("main <-h for help> <command> <option> <param> ...\n");
    printf("commands: rule add # add new rule for filtering \n");
    printf("                --param: -n <name>\n");
    printf("                         -si <source ip/mask>\n");
    printf("                         -sp <source port>\n");
    printf("                         -ti <target ip/mask>\n");
    printf("                         -tp <target port>\n");
    printf("                         -p <TCP/UDP/ICMP/ANY>\n");
    printf("                         -a <re for refuse/ac for accept>\n");
    printf("                         -l <y for log/n for no log>\n");
    printf("               del # del rule for filtering\n");
    printf("                --param: -n <name>\n");
    printf("               ls # list all rules for filtering\n");
    printf("               default ac/re\n");
    printf("          nat  add # add new nat rule\n");
    printf("                --param: -si <source ip/mask>\n");
    printf("                         -ti <nat ip>\n");
    printf("                         -tp <target port>\n");
    printf("               del # del nat rule\n");
    printf("                --param: -s <seq num>\n");
    printf("               ls # list all nat\n");
    printf("               default\n");
    printf("          ls   log # list log\n");
    printf("               conn # list established connections\n");
    exit(0);
}

void processAdd()
{
}

int main(int argc, char *argv[])
{
    struct ftrule rule;
    struct natrule nat_rule;
    char ruleName[MAXRuleNameLen + 1];
    int natseq = -1;
    struct KernelResp rsp;
    // 解析参数
    for (size_t i = 0; i < argc; i++)
    {
        // 输出帮助信息
        if (strcmp(argv[i], "-h") == 0)
        {
            PrintUsage();
            exit(0);
        }

        // 如果参数为rule
        if (strcmp(argv[i], "rule") == 0)
        {
            if (i + 1 == argc)
            {
                break;
            }

            // 如果是列出所有过滤规则
            if (strcmp(argv[i + 1], "ls") == 0)
            {
                // 列出所有过滤规则
                rsp = getAllFTRules();
                ProcKernelResp(rsp);
                exit(0);
            }
            // 删除规则
            else if (strcmp(argv[i + 1], "del") == 0)
            {
                int NumofParam = 0;
                for (size_t j = i + 2; j < argc; j++)
                {
                    if (strcmp(argv[j], "-n") == 0)
                    {
                        if (j + 1 == argc)
                        {
                            break;
                        }
                        // 获取要删除的规则名
                        sscanf(argv[j + 1], "%s", ruleName);
                        // 删除规则
                        rsp = delFTRule(ruleName);
                        // 处理响应
                        ProcKernelResp(rsp);
                        exit(0);
                    }
                }
                PrintUsage();
                exit(0);
            }
            else if (strcmp(argv[i + 1], "add") == 0)
            {
                int NumofParam = 0;
                for (size_t j = i + 2; j < argc; j++)
                {
                    // 读取规则的参数
                    // 规则名
                    if (strcmp(argv[j], "-n") == 0)
                    {
                        if (j + 1 == argc)
                        {
                            break;
                        }
                        sscanf(argv[j + 1], "%s", rule.name);
                        NumofParam++;
                        j++;
                    }
                    // 源ip
                    else if (strcmp(argv[j], "-si") == 0)
                    {
                        if (j + 1 == argc)
                        {
                            break;
                        }
                        sscanf(argv[j + 1], "%s", rule.sip);
                        NumofParam++;
                        j++;
                    }
                    // 源端口
                    else if (strcmp(argv[j], "-sp") == 0)
                    {
                        if (j + 1 == argc)
                        {
                            break;
                        }
                        sscanf(argv[j + 1], "%s", rule.sport);
                        NumofParam++;
                        j++;
                    }
                    // 目标ip
                    else if (strcmp(argv[j], "-ti") == 0)
                    {
                        if (j + 1 == argc)
                        {
                            break;
                        }
                        sscanf(argv[j + 1], "%s", rule.tip);
                        NumofParam++;
                        j++;
                    }
                    // 目标端口
                    else if (strcmp(argv[j], "-tp") == 0)
                    {
                        if (j + 1 == argc)
                        {
                            break;
                        }
                        sscanf(argv[j + 1], "%s", rule.tport);
                        NumofParam++;
                        j++;
                    }
                    // 协议
                    else if (strcmp(argv[j], "-p") == 0)
                    {
                        if (j + 1 == argc)
                        {
                            break;
                        }
                        sscanf(argv[j + 1], "%s", rule.protocol);
                        NumofParam++;
                        j++;
                    }
                    // 行为
                    else if (strcmp(argv[j], "-a") == 0)
                    {
                        if (j + 1 == argc)
                        {
                            break;
                        }
                        if (strcmp(argv[j + 1], "re") == 0)
                        {
                            rule.act = 0;
                        }
                        else
                        {
                            rule.act = 1;
                        }
                        NumofParam++;
                        j++;
                    }
                    // 是否记录日志
                    else if (strcmp(argv[j], "-l") == 0)
                    {
                        if (j + 1 == argc)
                        {
                            break;
                        }
                        if (strcmp(argv[j + 1], "y") == 0)
                        {
                            rule.islog = 1;
                        }
                        else
                        {
                            rule.islog = 0;
                        }
                        NumofParam++;
                        j++;
                    }
                }
                // 参数错误
                if (NumofParam != 8)
                {
                    PrintUsage();
                    exit(0);
                }
                else
                {
                    // 添加过滤规则
                    rsp = addFtRule(&rule);
                    ProcKernelResp(rsp);
                    exit(0);
                }
            }
            else if (strcmp(argv[i + 1], "default") == 0)
            {
                if (i + 2 < argc)
                {
                    // 默认拒绝
                    if (strcmp(argv[i + 2], "re") == 0)
                    {
                        rsp = setDefaultAction(NF_DROP);
                        ProcKernelResp(rsp);
                        exit(0);
                    }
                    else if (strcmp(argv[i + 2], "ac") == 0)
                    {
                        // 默认接受
                        rsp = setDefaultAction(NF_ACCEPT);
                        ProcKernelResp(rsp);
                        exit(0);
                    }
                    else
                    {
                        PrintUsage();
                        exit(0);
                    }
                }
            }
        }
        else if (strcmp(argv[i], "nat") == 0)
        {
            // 如果参数为nat
            if (i + 1 == argc)
            {
                break;
            }

            // 如果是列出所有nat规则
            if (strcmp(argv[i + 1], "ls") == 0)
            {
                // 列出nat规则
                rsp = getAllNATRules();
                ProcKernelResp(rsp);
                exit(0);
            }
            // 删除nat规则
            else if (strcmp(argv[i + 1], "del") == 0)
            {
                // 删除nat规则
                for (size_t j = i + 2; j < argc; j++)
                {
                    // 指定序号
                    if (strcmp(argv[j], "-s") == 0)
                    {
                        if (j + 1 == argc)
                        {
                            break;
                        }
                        // 获取要删除的规则序号
                        sscanf(argv[j + 1], "%d", &natseq);
                        // 删除规则
                        rsp = delNATRule(natseq);
                        // 处理响应
                        ProcKernelResp(rsp);
                        exit(0);
                    }
                }
                PrintUsage();
                exit(0);
            }
            else if (strcmp(argv[i + 1], "add") == 0)
            {
                int NumofParam = 0;
                for (size_t j = i + 2; j < argc; j++)
                {
                    // 读取nat规则的参数
                    // 源ip
                    if (strcmp(argv[j], "-si") == 0)
                    {
                        if (j + 1 == argc)
                        {
                            break;
                        }
                        sscanf(argv[j + 1], "%s", nat_rule.sip);
                        NumofParam++;
                        j++;
                    }
                    // nat ip
                    else if (strcmp(argv[j], "-ti") == 0)
                    {
                        if (j + 1 == argc)
                        {
                            break;
                        }
                        sscanf(argv[j + 1], "%s", nat_rule.tip);
                        NumofParam++;
                        j++;
                    }
                    // 目标端口
                    else if (strcmp(argv[j], "-tp") == 0)
                    {
                        if (j + 1 == argc)
                        {
                            break;
                        }
                        sscanf(argv[j + 1], "%s", nat_rule.tport);
                        NumofParam++;
                        j++;
                    }
                }
                // 参数错误
                if (NumofParam != 3)
                {
                    PrintUsage();
                    exit(0);
                }
                else
                {
                    // 添加nat规则
                    rsp = addNATRule(&nat_rule);
                    ProcKernelResp(rsp);
                    exit(0);
                }
            }
        }
        else if (strcmp(argv[i], "ls") == 0)
        {
            // 如果参数为nat
            if (i + 1 == argc)
            {
                break;
            }
            if (strcmp(argv[i + 1], "conn") == 0)
            {
                rsp = getAllConns();
                ProcKernelResp(rsp);
                exit(0);
            }
        }
    }
    PrintUsage();

    return 0;
}