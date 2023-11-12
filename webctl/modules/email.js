/**
 * @brief 登录
 */

// 导入express模块
const express = require("express");
// 创建 application/x-www-form-urlencoded 编码解析
let bodyParser = require("body-parser");
let urlencodedParser = bodyParser.urlencoded({ extended: false });
// 创建路由对象，并挂载具体的路由
const setEmail = express.Router();
// 引入jwt
const jwt = require("jsonwebtoken");
const conf = require("./conf");
let cookieParser = require("cookie-parser");
setEmail.use(cookieParser(conf.key));
// 导入加密模块
const crypto = require("crypto");
const { signedCookies } = require("cookie-parser");
// 数据库
mysql = require("mysql");
let genJwt = require("./genJwt");

function initEmail(username, email, res) {
  // 更新邮箱
  let sql = `update t_users set email=? where username=?`;
  conf.pool.getConnection((err, connection) => {
    if (err) {
      console.log(err);
      return;
    }
    // 执行sql语句
    connection.query(sql, [email, username], function (err, result) {
      // 如果有错误，则输出错误信息
      if (err) {
        console.log(err);
        res.send({ code: conf.ERROR_SERVER, msg: "服务器异常" });
      } else {
        // 如果没有错误，则输出执行结果
        res.send({ code: conf.INIT_SUCCESS, msg: "邮箱设置成功" });
      }
    });
    // 释放连接
    connection.release();
  });
}

/**
 * @brief 初始化
 */
setEmail.post("/setEmail", urlencodedParser, (req, res) => {
  // 获取用户名和密码
  let email = req.body.email;
  let username = req.signedCookies.username;
  initEmail(username, email, res);
});

module.exports = setEmail;
