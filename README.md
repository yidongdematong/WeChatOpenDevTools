# WeChatOpenDevTools

> 暂时支持的小程序版本 8555  9105  9115  9129  9133  

懒人用法:

```
1.下载安装并设置好环境变量 node 18.15.0  
https://nodejs.org/dist/v18.15.0/

2.确保微信没有在运行 双击 打开公众号F12 即可唤醒微信 登录微信后即可 开始调试公众号

3.双击 打开小程序F12.bat 即可打开小程序进行调试
```




# 针对微信多开，开启wechat调试 模式
```
修改原始逻辑，不再根据进程名称枚举锁定进程id注入，重复枚举系统WeChatAppEx.exe进程，注入成功后记录pid。重复执行对应多开微信客户端个数次数后，这样可以满足微信多开开启调试模式场景。
```

### 该学习的已经学习完成了！还要继续学习新东西的话 加下面的群吧
[如果你有不方便发的东西 可以加入我们的TG群](https://t.me/+208rGDduK4s1NWU1)

[你也可以加入专门玩js逆向的交流QQ群【JsDebug】](http://qm.qq.com/cgi-bin/qm/qr?_wv=1027&k=8M97BQs-icsb3BitUoqxqIHIBcf6ayLf&authKey=kAJwU36Ih9k7nWbYXtUnXeZnnXOFpQpvv4Zl4PGxdCNd1icroeGsgK1eTpSVMXSw&noverify=0&group_code=461168359)                             

