---
title: "网络安全"
author: 黄玮
output: revealjs::revealjs_presentation
---

# 第七章 Web 应用漏洞攻防

---

## Web 安全模型 {id="web-sec-model"}

![](images/chap0x07/web-sec-model.png)

---

## Web 应用模型 {id="web-app-model"}

|          | 浏览器(Browser)  | Web 服务器(Server)         | 后端服务(Backend)          |
|          | --               | --                         | --                         |
| 业务     | UI / UE          | CRUD / RESTful             | Search / Cache / DB        |
| 框架     | Vue.js           | Laravel / Struts2          | -                          |
| 语言     | js / html / css  | PHP / Java / Python / Ruby | SQL / DSL                  |
| 运行环境 | Chrome / Firefox | Nginx / php-fpm / Tomcat   | K8S / ES / MySQL / MongoDB |
| 基础设施 | Win / macOS      | Linux                      | Linux                      |

---

## 通信协议

* 浏览器 <--> Web 服务器：HTTP

# 回顾 HTTP {id="review-of-http"}

---

1. 浏览器 --- HTTP 请求消息 ---> 服务器
    * 服务器 --- 请求 ---&gt; 后端服务
    * 服务器 &lt;--- 响应 --- 后端服务
2. 浏览器 &lt;--- HTTP 响应消息 --- 服务器

---

![](images/chap0x07/firefox-in-kali-debug-mode.png)

---

## 必知必会基本概念 {id="http-essentials-1"}

`HTTP-message   = Request | Response     ; HTTP/1.1 messages`

---

## 必知必会基本概念 {id="http-essentials-2"}

* 请求行
    * [`Request-Line   = Method SP Request-URI SP HTTP-Version CRLF`](https://www.ietf.org/rfc/rfc2616.txt)
* 请求头
    * 常见请求头
    * 不同请求头取值的特殊含义
* 请求体
    * 二进制文件上传的编码方式
* （响应）状态行
    * `Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF`
* 响应头
* 响应体

---

## 必知必会基本概念 {id="http-essentials-3"}

* URL 编码
* SQL
* JSON
* ...

# 漏洞攻防训练环境搭建

---

* PHP Web 漏洞复现环境
* WebGoat 漏洞复现环境

---

## 千叮咛万嘱咐的注意事项

1. ⚠️  不要在宿主机上直接搭建漏洞复现环境       ⚠️
2. ⚠️  请在虚拟机内搭建漏洞复现环境             ⚠️
3. ⚠️  且训练入口严格限定在本机虚拟网络范围内   ⚠️

---

## PHP Web 漏洞复现环境 {id="php-web-sec-lab"}

```bash
# （可选步骤）新版 Kali 已在默认安装时禁用 root 用户
# 允许 root 用户远程 SSH 登录
# root 用户权限执行以下命令
sed -i.bak "s/#PermitRootLogin prohibit-password/PermitRootLogin yes/g" /etc/ssh/sshd_config

# 开启 SSH 服务
systemctl start ssh

# 设置 SSH 服务开机自启动
systemctl enable ssh

# 检查当前系统中是否已安装 PHP 命令行解释器
php -v

# 如果输出了 PHP 解释器版本信息，则跳过以下安装步骤
# 直接跳到「启动 PHP 内置开发版 Web 服务器」

# 安装当前发行版支持的最新版 PHP 命令行解释器
apt update && apt install php-cli

# 如果需要安装「旧版本」PHP 解释器，推荐使用 Docker
# https://hub.docker.com/_/php

# 安装完毕后检查当前安装的 PHP 命令行解释器版本
php -v

# 启动 PHP 内置开发版 Web 服务器
# 建议在 tmux 会话中执行该命令
php -S 0.0.0.0:8080

# 使用浏览器访问虚拟机的任意一个可用网卡上的 IP 地址
# 端口号设置为 8080
# 例如 http://127.0.0.1:8080/
```

---

## WebGoat 漏洞攻防训练环境 {id="webgoat-lab-setup"}

访问 [https://github.com/c4pr1c3/ctf-games](https://github.com/c4pr1c3/ctf-games) 获得本课程定制的 Web 漏洞攻防训练环境。

> 或访问国内镜像仓库 [https://gitee.com/c4pr1c3/ctf-games](https://gitee.com/c4pr1c3/ctf-games)

# 输入相关的通用漏洞

---

## 一切罪恶都是源于恶意输入数据

* 不要相信任何来自客户端的提交数据
    * 客户端的任何数据校验都是纸老虎
        * 客户端的数据校验机制防君子不防黑客
* 数据和指令/代码必须严格区分
    * 缓冲区溢出时的机器指令运行在可执行堆栈上
    * SQL 注入时执行任意SQL语句
    * XSS 时执行任何客户端脚本代码（JS/Flash AS）
    * 文件上传时上传服务端脚本代码在服务器端执行任意代码

# 1. 未验证的用户输入-示例 {id="tainted-user-input"}

---

## 缺陷代码示例

```php
<?php
$file = $_GET['file'];
echo file_get_contents($file);
```

---

## 利用方式示例

```bash
curl "http://127.0.0.1:8080/exp-1.php?file=exp-1.php"
curl "http://127.0.0.1:8080/exp-1.php?file=/etc/passwd"
curl "http://127.0.0.1:8080/exp-1.php?file=/etc/shadow"
```

---

## 基本原理

攻击者可以篡改 `HTTP 请求消息` 的任何一个部分

* HTTP 请求行 
* HTTP 请求头 
* HTTP 请求体

---

## 常见的输入篡改攻击

* 强制浏览
* 命令注入
* 跨站点脚本攻击
* 缓冲区溢出攻击
* 格式化字符串攻击
* SQL 注入
* Cookie 毒化
* 隐藏域控制

---

## 输入篡改攻击的成因

* 只在客户端进行输入验证
* 过滤时未进行规范化
* 过滤后引入新漏洞

---

## 典型漏洞利用方法

1. 拦截 HTTP 请求数据
2. 修改数据 
3. 继续发送篡改后数据

---

## 典型漏洞利用工具

* HTTP 协议调试工具 
* BurpSuite
* 浏览器内置的开发者工具

---

## 安全加固方案 {id="prevent-input-weakness-1"}

* 所有的用户输入需要在服务器端进行集中的统一验证
    * HTTP 请求行 
    * HTTP 请求头 
    * HTTP 请求体
* 代码复查
* 不要“滥用”隐藏域
    * 存储在 Session 中或从每次请求中获取参数值

---

## 安全加固方案 {id="prevent-input-weakness-2"}

* 请求参数需要严格的验证其类型
    * 数据类型（string, integer, real, etc…）
    * 最小和最大长度
    * 是否允许 NULL
    * 参数是否是必需的
    * 数字的取值范围
    * 特定模式（正则表达式）
        * 白名单机制

---

## 安全加固方案 {id="prevent-input-weakness-3"}

* 服务器返回给客户端的重要参数、赋值使用 `HMAC` 进行参数签名
    * 千万不要使用 `MD5`、`SHA-XXX` 之类的摘要算法对参数进行摘要计算，也不要使用基于“秘密盐值”的 `MD5`、`SHA-XXX` 之类的摘要算法对参数进行摘要计算
        * [Hash 长度扩展攻击可以用来伪造消息和对应的散列值](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
    * 对客户端提交的请求校验关键逻辑代码中的参数，一旦 `消息完整性签名` 校验失败，说明客户端尝试篡改请求参数攻击，代码逻辑直接跳过后续业务逻辑代码，给客户端返回统一的错误信息

# 2. 缓冲区溢出漏洞

---

* 应用程序的缓冲区中存在过量的输入数据，溢出的数据中包含恶意指令且恶意指令被精确填充到可执行堆/栈（内存）中进而导致恶意代码被执行
* 一般情况下，Web 应用程序不存在缓冲区溢出漏洞

---

* Java Web 应用程序不存在缓冲区溢出风险？
    * OutOfMemoryError
    * CVE-2011-0311
    * CVE-2009-1099

---

* PHP Web应用程序不存在缓冲区溢出风险？
    * CVE-2011-3268 
    * CVE-2008-5557 
    * CVE-2008-2050 
    * CVE-2007-1399 
    * CVE-2007-1381 

---

* 其他语言编写的Web应用程序呢？
    * 后台应用系统
    * 本地代码

---

只要系统中直接或间接存在使用 `C/C++` 编写的代码，那么该系统就难以彻底摆脱「缓冲区溢出等」`内存破坏类` 攻击。
 
---

## 安全加固方案 {id="prevention-to-bof"}

* 避免使用本地代码
* 避免直接调用本地应用程序
* 及时更新应用运行环境
    * Java 虚拟机的安全更新补丁
    * PHP 语言的安全更新补丁
* 限制 Web 应用程序的运行权限
    * 沙盒技术

# 3. 文件上传漏洞

---

## 推荐训练学习资源

* [upload-labs 一个使用 PHP 语言编写的，专门收集渗透测试和 CTF 中遇到的各种上传漏洞的靶场](https://github.com/c0ny1/upload-labs)

# 服务端脚本相关漏洞

---

# 4. 脆弱的访问控制

---

# 5. 认证和会话管理缺陷

---

# 6. 文件包含

---

# 7. XXE 注入

---

# 8. 反序列化漏洞

---

# 9. 第三方组件缺陷

---

# 后台相关漏洞

---

# 10. SQL 注入漏洞 {id="sqli"}

---

## 推荐训练学习资源

* [sqli-labs](https://github.com/c4pr1c3/sqli-labs) | [sqli-labs 国内 gitee 镜像](https://gitee.com/c4pr1c3/sqli-labs)

---

# 11. 命令注入

---

# 12. 服务端请求伪造

---

# 输出相关漏洞

---

# 13. 跨站点脚本

---

# 14. 信息泄露

---

# 再看一个输入相关的有趣漏洞

---

# 15. CSRF 漏洞

---

1. 利用站点已验证通过的用户会话（无需获取用户的登录凭证）

http://victim.org/addFriend.do?friend=attacker@gmail.com

2. 当一个已经登录 `victim.org` 的用户打开一个包含有 `XSS` 攻击代码的页面（或者通过一个隐藏的iframe），并且该 `XSS` 代码执行上述的 `URL` 请求，则该用户就会执行 `addFriend` 这个操作

3. 结果：用户在不知情的情况下添加了攻击者作为自己的好友

---

![添加后门账号](images/chap0x07/csrf-facebook-add-backdoor-account.mp4)

---

## CSRF 知名安全事件 {id="csrf-notorious-event"}

* 新浪微博 `2011 年 6 月 28 日` 晚间的大规模 `XSS+CSRF` 蠕虫事件
    * 事件时间线：16分钟
        * 20:14，开始有大量带V的认证用户中招转发蠕虫
        * 20:30，2kt.cn中的病毒页面无法访问
        * 20:32，新浪微博中hellosamy用户无法访问
        * 21:02，新浪漏洞修补完毕
    * 感染人数：32961人！
* 病毒作者使用的用户名 `hello-samy` 是为了向世界上第一个 `XSS+CSRF` 蠕虫作者 `samy` 致敬

---

## CSRF 描述 {id="csrf-description"}

* 从名称上来看类似跨站点攻击，但实质上完全不同：
    * XSS 是滥用用户对 Web 站点的信任
    * CSRF 是滥用 Web 站点对其授权用户的信任
* 伪装成来自受信任站点的合法用户
    * 有时也被称为会话劫持攻击
* 典型案例
    * 诱骗用户访问一个图片源标记为恶意请求链接的页面，从而触发一个异步的恶意远程调用
    * 接受受信任并且通过验证的用户的输入但并不检查数据的来源地址

---

## 与 XSS 的联系

* 跨站点请求伪造通常伴随 XSS 漏洞利用过程
* 先有 XSS，再有 CSRF
    * 借助 XSS 漏洞获得在用户浏览器执行脚本的机会
* 没有 XSS，一样可以有 CSRF
    * 借助已通过网站认证和获得授权的用户浏览器会话
        * 假借用户的合法cookie
* 一个URL即可触发一次CSRF
    * http://victim.org/deluser.php?id=admin

# 平台相关漏洞

---


# 16. Web 服务器 URI 解析类漏洞 {id="web-svr-uri-parse-vul"}


---


# 17. 不当配置缺陷


