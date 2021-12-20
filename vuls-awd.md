---
title: "网络安全"
author: 黄玮
output: revealjs::revealjs_presentation
---

# 网络安全综合实验：开源信息系统搭建、加固与漏洞攻防

---

## 内容提纲

* 基础运行环境准备
* 漏洞攻防环境现状
* 漏洞攻防环境搭建
* 漏洞攻击
* 漏洞利用检测
* 漏洞利用防御与加固

# 基础运行环境准备

---

## 二选一

* 直接使用本学期课程实验所用的虚拟机环境
* [再来一遍] 从零开始搭建基础虚拟机环境

---

## 基础虚拟机环境搭建必知必会

* 安装后虚拟机网卡没有分配到 IP ？
* SSH 服务启用与 SSH 免密登录
    * [可选] [vscode remote on win10](https://www.bilibili.com/video/BV1Hb4y1R7FE?p=52)
* [克隆出来的虚拟机 IP 地址一样？](https://c4pr1c3.github.io/LinuxSysAdmin/cloud-init.md.html#/why-reset-machine-id)
* [多重加载镜像制作与使用](https://www.bilibili.com/video/BV1Hb4y1R7FE?p=19)
* 备份与还原
    * 虚拟机快照与还原
    * 默认配置文件编辑前备份

---

## 基础虚拟机环境搭建必知必会（指令汇编）

```bash
# 确保使用 root 权限操作
sudo su -

# 养成良好配置习惯：备份配置文件
cp /etc/network/interfaces /etc/network/interfaces.bak

# 非交互式配置文件内容追加
cat << EOF >> /etc/network/interfaces
allow-hotplug eth0
iface eth0 inet dhcp
allow-hotplug eth1
iface eth1 inet dhcp
EOF

# 手动重启指定网卡
ifdown eth{0,1} && ifup eth{0,1}

# 配置 SSH 服务开机自启动
systemctl enable ssh

# 启动 SSH 服务
systemctl start ssh
```

# 漏洞攻防环境现状

---

## [本课程第 7 章课件中推荐过的训练学习资源](chap0x07.md)

* [https://github.com/c4pr1c3/ctf-games](https://github.com/c4pr1c3/ctf-games) 获得本课程定制的 Web 漏洞攻防训练环境
* [upload-labs 一个使用 PHP 语言编写的，专门收集渗透测试和 CTF 中遇到的各种上传漏洞的靶场](https://github.com/c0ny1/upload-labs)
* [PHP XXE 漏洞与利用源代码分析示例](https://github.com/vulnspy/phpaudit-XXE)
* [vulhub 提供的 XXE 漏洞学习训练环境](https://github.com/vulhub/vulhub/tree/master/php/php_xxe)
* [python-xxe](https://github.com/c4pr1c3/python-xxe)
* [sqli-labs](https://github.com/c4pr1c3/sqli-labs) | [sqli-labs 国内 gitee 镜像](https://gitee.com/c4pr1c3/sqli-labs)
* [一个包含php,java,python,C#等各种语言版本的XXE漏洞Demo](https://github.com/c0ny1/xxe-lab)
* [upload-labs 一个使用 PHP 语言编写的，专门收集渗透测试和 CTF 中遇到的各种上传漏洞的靶场](https://github.com/c0ny1/upload-labs)

---

## [vulhub](https://github.com/topics/vulhub)

* [vulhub/vulhub](https://github.com/vulhub/vulhub)
* [fofapro/vulfocus](https://github.com/fofapro/vulfocus)
* [sqlsec/ssrf-vuls](https://github.com/sqlsec/ssrf-vuls)

# 漏洞攻防环境搭建

---

## 本课程的选型依据

1. 开箱即用，上手难度低
2. 包含「可复现漏洞环境」数量多、涵盖漏洞类型丰富
3. 运行负载低，可个人电脑单机使用

---

## [fofapro/vulfocus](https://github.com/fofapro/vulfocus)

> 🚀Vulfocus 是一个漏洞集成平台，将漏洞环境 docker 镜像，放入即可使用，开箱即用。 

---

### 快速上手 vulfocus

[c4pr1c3/ctf-games - fofapro/vulfocus](https://github.com/c4pr1c3/ctf-games/tree/master/fofapro/vulfocus)

# 漏洞攻击

---

# 漏洞利用检测

---

# 漏洞利用防御与加固



