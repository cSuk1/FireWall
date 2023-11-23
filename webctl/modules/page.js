/**
 * @brief 页面访问控制路由
 */

// 导入express模块
const express = require("express");
// 创建 application/x-www-form-urlencoded 编码解析
let bodyParser = require("body-parser");
let urlencodedParser = bodyParser.urlencoded({ extended: false });
// 创建路由对象，并挂载具体的路由
const router = express.Router();
// 配置文件
const {
  pool,
  key,
} = require("./conf");
let cookieParser = require("cookie-parser");
router.use(cookieParser(key));
// 导入加密模块
const crypto = require("crypto");
const { signedCookies } = require("cookie-parser");
// 引入jwt
const jwt = require("jsonwebtoken");
// 引入path模块
let path = require("path");

/**
 * @brief 访问默认路径
 */
router.get("/", function (req, res, next) {
  //获取当前文件所在的目录的父级目录
  let Path = path.resolve(__dirname, "..");
  //获取请求中的token
  let token = req.signedCookies.token;
  // 验证token
  jwt.verify(token, key, (err, decoded) => {
    if (err) {
      console.log("Invalid token:", err.message);
      res.sendFile(Path + "/views/login.html");
    } else {
      console.log("Decoded token:", decoded);
      res.sendFile(Path + "/views/index.html");
    }
  });
});

/**
 * @brief 访问index.html
 */
router.get("/index.html", function (req, res, next) {
  // 获取当前文件所在的目录
  let Path = path.resolve(__dirname, "..");
  // 获取请求中的token
  let token = req.signedCookies.token;
  // 验证token
  jwt.verify(token, key, (err, decoded) => {
    if (err) {
      console.log("Invalid token:", err.message);
      res.sendFile(Path + "/views/login.html");
    } else {
      console.log("Decoded token:", decoded);
      res.sendFile(Path + "/views/index.html");
    }
  });
});

/**
 * @brief 访问过滤规则
 */
router.get("/filter.html", function (req, res, next) {
  // 获取当前文件所在的目录
  let Path = path.resolve(__dirname, "..");
  // 获取请求中的token
  let token = req.signedCookies.token;
  // 验证token
  jwt.verify(token, key, (err, decoded) => {
    if (err) {
      console.log("Invalid token:", err.message);
      res.sendFile(Path + "/views/login.html");
    } else {
      console.log("Decoded token:", decoded);
      res.sendFile(Path + "/views/filter.html");
    }
  });
});

/**
 * @brief 登录
 */
router.get("/login.html", function (req, res, next) {
  //获取当前文件所在的目录的绝对路径
  let Path = path.resolve(__dirname, "..");
  let token = req.signedCookies.token;
  // 验证token
  jwt.verify(token, key, (err, decoded) => {
    if (err) {
      console.log("Invalid token:", err.message);
      res.sendFile(Path + "/views/login.html");
    } else {
      console.log("Decoded token:", decoded);
      res.sendFile(Path + "/views/index.html");
    }
  });
});

/**
 * @brief 初始化邮箱
 */
router.get("/setEmail.html", function (req, res, next) {
  //获取当前文件所在的目录的绝对路径
  let Path = path.resolve(__dirname, "..");
  let token = req.signedCookies.token;
  // 验证token
  jwt.verify(token, key, (err, decoded) => {
    if (err) {
      console.log("Invalid token:", err.message);
      res.sendFile(Path + "/views/setEmail.html");
    } else {
      console.log("Decoded token:", decoded);
      res.sendFile(Path + "/views/setEmail.html");
    }
  });
});

router.get("/conn.html", function (req, res, next) {
  //获取当前文件所在的目录的绝对路径
  let Path = path.resolve(__dirname, "..");
  let token = req.signedCookies.token;
  // 验证token
  jwt.verify(token, key, (err, decoded) => {
    if (err) {
      console.log("Invalid token:", err.message);
      res.sendFile(Path + "/views/login.html");
    } else {
      console.log("Decoded token:", decoded);
      res.sendFile(Path + "/views/conn.html");
    }
  });
});

// 向外导出路由
module.exports = router;
