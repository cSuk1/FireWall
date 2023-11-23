/**
 * 连接管理
 */
// 导入express模块
const express = require("express");
// 创建 application/x-www-form-urlencoded 编码解析
let bodyParser = require("body-parser");
let urlencodedParser = bodyParser.urlencoded({ extended: false });
// 创建路由对象，并挂载具体的路由
const conn_manager = express.Router();
// 引入jwt
const jwt = require("jsonwebtoken");
const conf = require("./conf");
let cookieParser = require("cookie-parser");
conn_manager.use(cookieParser(conf.key));
// 导入加密模块
const crypto = require("crypto");
const { signedCookies } = require("cookie-parser");
// 数据库
mysql = require("mysql");
// 执行
const { exec } = require("child_process");


conn_manager.get("/conn_manager/getall", urlencodedParser, (req, res) => {
    // 获取请求中的token
    let token = req.signedCookies.token;
    // 验证token
    jwt.verify(token, conf.key, (err, decoded) => {
        if (err) {
            console.log("Invalid token:", err.message);
            res.redirect("/login.html");
        } else {
            let cmd = "../main ls conn";
            // 执行cmd
            exec(cmd, (error, stdout, stderr) => {
                if (error) {
                    console.log("执行命令发生错误：" + error.message);
                    res.send({ code: conf.ERROR_SERVER, msg: "服务器异常" });
                    return;
                }
                if (stderr) {
                    res.send({ code: conf.ERROR_SERVER, msg: "参数错误" });
                    return;
                }
                const data = stdout;
                // 获取连接数
                const lines = data.split('\n');
                const connectionNum = parseInt(lines[0].split(':')[1].trim());
                console.log(connectionNum);
                const connections = [];
                for (let i = 1; i < lines.length - 1; i++) {
                    const [protocol, localAddress, remoteAddress] = lines[i].split(' ');
                    console.log(protocol, localAddress, remoteAddress);
                    const [localIP, localPort] = localAddress.split(':');
                    const [remoteIP, remotePort] = remoteAddress.split(':');
                    const connection = {
                        protocol: protocol.trim(),
                        localAddress: {
                            ip: localIP.trim(),
                            port: parseInt(localPort)
                        },
                        remoteAddress: {
                            ip: remoteIP.trim(),
                            port: parseInt(remotePort)
                        }
                    };
                    connections.push(connection);
                }

                const json = {
                    'connection num': connectionNum,
                    connections: connections
                };
                // 将查询到的内容发送给前端
                const jsonResult = JSON.stringify(json);
                // 发送 JSON 数组到前端
                res.send(jsonResult);
                return;
            });
        }
    });
});


module.exports = conn_manager;
