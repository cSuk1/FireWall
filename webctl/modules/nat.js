/**
 * 过滤规则管理
 */
// 导入express模块
const express = require("express");
// 创建 application/x-www-form-urlencoded 编码解析
let bodyParser = require("body-parser");
let urlencodedParser = bodyParser.urlencoded({ extended: false });
// 创建路由对象，并挂载具体的路由
const nat_manager = express.Router();
// 引入jwt
const jwt = require("jsonwebtoken");
const conf = require("./conf");
let cookieParser = require("cookie-parser");
nat_manager.use(cookieParser(conf.key));
// 导入加密模块
const crypto = require("crypto");
const { signedCookies } = require("cookie-parser");
// 数据库
mysql = require("mysql");
// 执行
const { exec } = require("child_process");

/**
 *
 * @param {*} name
 * @param {*} source_ip
 * @param {*} dest_ip
 * @param {*} source_port
 * @param {*} dest_port
 * @param {*} protocol
 * @param {*} act
 */
// 向数据库中插入过滤规则
function insertNATRule(
    seq,
    source_ip,
    dest_ip,
    min_port,
    max_port,
    res
) {
    // 定义sql语句
    let sql =
        "INSERT INTO t_nat_rules (create_time,seq,bf_ip,af_ip,min_port,max_port) VALUES (NOW(),?,?,?,?,?)";
    // 定义sql参数
    let sql_params = [
        seq,
        source_ip,
        dest_ip,
        min_port,
        max_port
    ];
    // 获取数据库连接
    conf.pool.getConnection((err, connection) => {
        if (err) {
            console.log(err);
            return;
        }
        // 执行sql语句
        connection.query(sql, sql_params, function (err, result) {
            // 如果有错误，则输出错误信息
            if (err) {
                console.log(err);
                res.send({ code: conf.ERROR_SERVER, msg: "服务器异常" });
            } else {
                res.send({ code: conf.ADD_FILTER_RULE_SUCCESS, msg: "添加成功" });
            }
        });
        // 释放连接
        connection.release();
    });
}

/**
 * 
 * @param {*} name 
 */
function delNATRule(seq, res) {
    let sql = "DELETE FROM t_nat_rules WHERE seq = ?";
    // 获取数据库连接
    conf.pool.getConnection((err, connection) => {
        if (err) {
            console.log(err);
            return;
        }
        // 执行sql语句
        connection.query(sql, [seq], function (err, result) {
            // 如果有错误，则输出错误信息
            if (err) {
                console.log(err);
                res.send({ code: conf.ERROR_SERVER, msg: "服务器异常" });
            } else {
                res.send({ code: conf.DEL_FILTER_RULE_SUCCESS, msg: "删除成功" });
            }
        });
        // 释放连接
        connection.release();
    });
}

/**
 * @brief 添加过滤规则
 */
nat_manager.post("/nat_manager/add", urlencodedParser, (req, res) => {
    // 获取请求中的token
    let token = req.signedCookies.token;
    // 验证token
    jwt.verify(token, conf.key, (err, decoded) => {
        if (err) {
            console.log("Invalid token:", err.message);
            res.redirect("/login.html");
            return;
        } else {
            console.log("Decoded token:", decoded);
            let seq = req.body.seq;
            // console.log("seq ", seq);
            let source_ip = req.body.source_ip;
            let source_port = req.body.source_port;
            let dest_ip = req.body.dest_ip;
            // let dest_port = req.body.dest_port;
            // let protocol = req.body.protocol;
            // let act = req.body.act;
            // 要执行的命令
            let cmd =
                "../main nat add " +
                " -si " +
                source_ip +
                " -ti " +
                dest_ip +
                " -tp " +
                source_port;
            // console.log(cmd);

            // 执行命令
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
                console.log(stdout);
                // 插入规则
                const numbers = source_port.split('-');
                if (numbers.length === 2) {
                    const firstNumber = parseInt(numbers[0]);
                    const secondNumber = parseInt(numbers[1]);
                    if (firstNumber > secondNumber) {
                        insertNATRule(seq, source_ip, dest_ip, secondNumber, firstNumber, res);
                    } else {
                        insertNATRule(seq, source_ip, dest_ip, firstNumber, secondNumber, res);
                    }
                } else {
                    insertNATRule(seq, source_ip, dest_ip, 0, 65535, res);
                }
            });
        }
    });
});

nat_manager.get("/nat_manager/getall", urlencodedParser, (req, res) => {
    // 获取请求中的token
    let token = req.signedCookies.token;
    // 验证token
    jwt.verify(token, conf.key, (err, decoded) => {
        if (err) {
            console.log("Invalid token:", err.message);
            res.redirect("/login.html");
        } else {
            let sql = "SELECT * FROM t_nat_rules";
            conf.pool.getConnection((err, connection) => {
                if (err) {
                    console.log(err);
                    return;
                }
                // 执行sql语句
                connection.query(sql, [], function (err, result) {
                    // 如果有错误，则输出错误信息
                    if (err) {
                        console.log(err);
                        res.send({ code: conf.ERROR_SERVER, msg: "服务器异常" });
                        return;
                    } else {
                        // 如果没有错误，则输出查询结果
                        if (result.length > 0) {
                            // 遍历数据库查询结果
                            for (let i = 0; i < result.length; i++) {
                                // 将查询到的内容发送给前端
                                const jsonResult = JSON.stringify(result);
                                // 发送 JSON 数组到前端
                                res.send(jsonResult);
                                return;
                            }
                        } else {
                            res.send({ code: conf.ERROR_NODATA, msg: "没有数据" });
                            return;
                        }
                    }
                });
                // 释放连接
                connection.release();
            });
        }
    });
});


/**
 * @brief 删除过滤规则
 */
nat_manager.get("/nat_manager/del", urlencodedParser, (req, res) => {
    // 获取请求中的token
    let token = req.signedCookies.token;
    // 验证token
    jwt.verify(token, conf.key, (err, decoded) => {
        if (err) {
            console.log("Invalid token:", err.message);
            res.redirect("/login.html");
            return;
        } else {
            console.log("Decoded token:", decoded);
            let cmdseq = req.query.cmdseq;
            let dataseq = req.query.dataseq;
            // 要执行的命令
            let cmd = "../main nat del -s " + cmdseq;
            // console.log(cmd);
            // 执行命令
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
                console.log(stdout);
                delNATRule(dataseq, res);
            });
        }
    });
});


module.exports = nat_manager;
