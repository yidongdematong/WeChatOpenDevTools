//HOOK微信小程序
var frida = require("frida");
const cmdline = require('cmdline-windows');
const fs = require('fs');
const path = require('path');
const ini=require('ini');

// 启动
// node WeChatAppEx.exe.js 8555  wechatPath

// wechatPath "C:\Users\Administrator\Desktop\WeChat_142217\[3.9.10.19]\"
async function run() {
    let WeChatv = (process.argv[2]);
    // const args=process.argv.slice(2);
    var device = await frida.getLocalDevice();
    var processes = await device.enumerateProcesses();
    var pid = -1;
    var version = "";

    // 开启注入前，首先判断是否已经注入，加载配置文件
    
    const pidIniPath=path.join(__dirname,`/PID.ini`);
    let recordIni=fs.readFileSync(pidIniPath,'utf8').toString();
    let config=ini.parse(recordIni);
    let pidList=config['pidList'];
    // console.log(typeof(pidList));   
    // for(let key in pidList){
    //     console.log(key);
    // }
 
    console.log(pidList['pid']);
    
    // 临时pidList
    let tempPidList=config['pidList'];

    // version = Number(args[0]);
    // wechat=String(args[1]);
    // // if(wechat==None){
    // //     console.log("请输入微信路径")
    // //     return
    // // }
    // console.log(args);
    // 追加pid至配置文件
    // let newPid=Number(args[0]);

    
    
    // let commandLine = cmdline.getCmdline(pid);
    // console.log(commandLine);
    // processes.forEach(p_=>{
    //     console.log(p_.name,p_.pid)
    //     let commandLine = cmdline.getCmdline(p_.pid);
    //     console.log(commandLine);
    // })
    // return;
    // 遍历进程列表，排除配置文件的进程id列表
    let objectCount=Object.getOwnPropertyNames(pidList).length;
    let injectFlag=false;
    for(let key in pidList){
        existPid=pidList[key];
            processes.forEach(async (p_) => {
       
        // 比对pid列表，如果记录pid不包含系统进程id，则注入，否则，跳过
      
        // console.log("existPid",existPid,"p_Pid",p_.pid,"panduan结果",Number(existPid)==Number(p_.pid));
             //    否则遍历系统进程注入，并更新pid
        if (p_.name == "WeChatAppEx.exe") {
         let commandLine = cmdline.getCmdline(p_.pid);
         if (commandLine.indexOf("--type=") == -1) {
             try {
               
                 if(!WeChatv){
                     version = commandLine.split(`--wmpf_extra_config=\"{`)[1].split("}\"")[0];
                     version = version.replaceAll(`\\"`, '"');
                     version =  JSON.parse(`{${version}}`);
                     version =  version.version;
                    //  console.log(version);
                 }else{
                     version = WeChatv;
                 }
                //  console.log("existPid",existPid,"p_Pid",p_.pid,"panduan结果",Number(existPid)==Number(p_.pid));
                 if(Number(existPid)!=p_.pid){
                    pid = p_.pid;
                    return;
                 }else {
                    console.log("进程：",existPid,"已注入");
                    injectFlag=true;
                 }
                 
             } catch (err){
                 console.log(err);
             }
         }

        }
    
    });
}

    // if(injectFlag){
    //     console.log("请勿重复注入");
    //     return;
    // }
    let addressFilePath = path.join(__dirname, `/Core/WeChatAppEx.exe/address_${version}_x64.json`);
    let addressSource = `var version = ${version};`;
    
    try {
        fs.accessSync(addressFilePath);
        let addressSourceHeadFilePath = path.join(__dirname, `/Core/AddressSource.head`);
        let addressSourceEndFilePath = path.join(__dirname, `/Core/AddressSource.end`);
        let hookFilePath = path.join(__dirname, `/Core/WeChatAppEx.exe/hook.js`);

        addressSource += fs.readFileSync(addressSourceHeadFilePath);
        addressSource += fs.readFileSync(addressFilePath);
        addressSource += fs.readFileSync(addressSourceEndFilePath);
        addressSource += fs.readFileSync(hookFilePath);
   
    } catch (error) {
        console.log(`暂不支持 ${version}_64 的版本!`)
        return;
    }
    console.log("HOOK文件组装成功! 小程序版本: " + version)
    let pidCount = "pid".concat(String(objectCount));
    config.pidList[pidCount]=pid;
    console.log("PID记录文件更新，已追加进程id",pid);
    fs.writeFileSync(pidIniPath,ini.stringify(config),'utf8');
    fs.closeSync(2);
    session = await frida.attach(pid);
    script = await session.createScript(addressSource);
    script.message.connect(onMessage);
    await script.load();
}
function onMessage(message, data) {
    if (message.type === 'send') {
        console.log(message.payload);
    } else if (message.type === 'error') {
        console.error(message.stack);
    }
}


run();
