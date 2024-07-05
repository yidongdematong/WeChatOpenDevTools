//HOOK微信小程序
var frida = require("frida");
const cmdline = require('cmdline-windows');
const fs = require('fs');
const path = require('path');

// 启动
// node WeChatAppEx.exe.js 8555  wechatPath

// wechatPath "C:\Users\Administrator\Desktop\WeChat_142217\[3.9.10.19]\"
async function run() {
    // let WeChatv = (process.argv[2]);
    const args=process.argv.slice(2);
    var device = await frida.getLocalDevice();
    var processes = await device.enumerateProcesses();
    var pid = -1;
    var version = "";

    
 

    version = Number(args[0]);
    wechat=String(args[1]);
    // if(wechat==None){
    //     console.log("请输入微信路径")
    //     return
    // }
    console.log(args);
    // let commandLine = cmdline.getCmdline(pid);
    // console.log(commandLine);
    // processes.forEach(p_=>{
    //     console.log(p_.name,p_.pid)
    //     let commandLine = cmdline.getCmdline(p_.pid);
    //     console.log(commandLine);
    // })
    // return;
    processes.forEach(async (p_) => { 
        
            let commandLine = cmdline.getCmdline(p_.pid);
            
            console.log("commandLine",commandLine);
            if(commandLine.indexOf(wechat) > 0){
                
                console.log("commandLine.indexOf(wechat)",commandLine.indexOf(wechat))
                if (commandLine.indexOf("--type=") == -1) {
                    try {
                        if(!WeChatv){
                            version = commandLine.split(`--wmpf_extra_config=\"{`)[1].split("}\"")[0];
                            console.log("version1",version);
                            version = version.replaceAll(`\\"`, '"');
                            console.log("version2",version);
                            version =  JSON.parse(`{${version}}`);
                            console.log("version3",version);
                            version =  version.version;
                            console.log(version);
                            
                        }else{
                            version = WeChatv;
                        }
                        pid = p_.pid;
                        console.log(pid)
                    } catch {
                    }
                }
            }
            
    });
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
