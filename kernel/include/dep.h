/**
 * @file dep.h
 * @author cSuk1 (652240843@qq.com)
 * @brief 依赖
 * @version 0.1
 * @date 2023-11-23
 *
 *
 */
#ifndef _DEP_H
#define _DEP_H

// 内核模块编写的的依赖头文件
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/spinlock.h>

#endif