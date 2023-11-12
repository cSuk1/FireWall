/**
 * @brief 登录
 */

// 导入express模块
const express = require("express");
// 创建 application/x-www-form-urlencoded 编码解析
let bodyParser = require("body-parser");
let urlencodedParser = bodyParser.urlencoded({ extended: false });
// 创建路由对象，并挂载具体的路由
const login = express.Router();
// 引入jwt
const jwt = require("jsonwebtoken");
const conf = require("./conf");
let cookieParser = require("cookie-parser");
login.use(cookieParser(conf.key));
// 导入加密模块
const crypto = require("crypto");
const { signedCookies } = require("cookie-parser");
// 数据库
mysql = require("mysql");
let genJwt = require("./genJwt");

/**
 * @brief 密码校验
 * @param {*} username
 * @param {*} password
 * @param {*} res
 */
function checkPassword(username, password, res) {
  // 查询数据库中用户名和密码是否匹配
  let sql = "SELECT * FROM t_users WHERE username = ? AND password = ?";
  conf.pool.getConnection((err, connection) => {
    if (err) {
      console.log(err);
      return;
    }
    // 执行sql语句
    connection.query(sql, [username, password], function (err, result) {
      // 如果有错误，则输出错误信息
      if (err) {
        console.log(err);
        res.send({ code: conf.ERROR_SERVER, msg: "服务器异常" });
      } else {
        // 如果没有错误，则输出查询结果
        if (result.length > 0) {
          // 生成token
          const token = genJwt.generateToken(username);
          //设置cookie，设置cookie的名称，cookie的值，cookie的过期时间，cookie是否可以被js访问，是否签名
          res.cookie("username", username, {
            maxAge: 3000 * 1000,
            httpOnly: true,
            signed: true,
          });
          res.cookie("token", token, {
            maxAge: 3000 * 1000,
            httpOnly: true,
            signed: true,
          });
          if (!result[0].email) {
            console.log("未设置邮箱");
            res.send({ code: conf.UNINIT_EMAIL, msg: "未设置邮箱" });
          } else {
            res.send({ code: conf.LOGIIN_SUCCESS, msg: "登录成功" });
          }
        } else {
          res.send({ code: conf.LOGIIN_FAIL, msg: "用户名或密码错误" });
        }
      }
    });
    // 释放连接
    connection.release();
  });
}

/**
 * @brief 登录
 */
login.post("/login", urlencodedParser, (req, res) => {
  // 获取用户名和密码
  let username = req.body.username;
  // 加密用户输入的密码
  let password = crypto
    .createHash("sha1")
    .update(req.body.password)
    .digest("hex");
  // 校验密码
  checkPassword(username, password, res);
});

module.exports = login;
