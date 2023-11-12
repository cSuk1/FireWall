/**
 * 过滤规则管理
 */
// 导入express模块
const express = require("express");
// 创建 application/x-www-form-urlencoded 编码解析
let bodyParser = require("body-parser");
let urlencodedParser = bodyParser.urlencoded({ extended: false });
// 创建路由对象，并挂载具体的路由
const filter_manager = express.Router();
// 引入jwt
const jwt = require("jsonwebtoken");
const conf = require("./conf");
let cookieParser = require("cookie-parser");
filter_manager.use(cookieParser(conf.key));
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
function insertFilterRule(
  name,
  source_ip,
  dest_ip,
  source_port,
  dest_port,
  protocol,
  act,
  res
) {
  // 定义sql语句
  let sql =
    "INSERT INTO t_filter_rules (create_time,name,src_ip,dst_ip,src_port,dst_port,protocol,act) VALUES (NOW(),?,?,?,?,?,?,?)";
  // 定义sql参数
  let sql_params = [
    name,
    source_ip,
    dest_ip,
    source_port,
    dest_port,
    protocol,
    act,
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
function delFilterRule(name, res) {
  let sql = "DELETE FROM t_filter_rules WHERE name = ?";
  // 获取数据库连接
  conf.pool.getConnection((err, connection) => {
    if (err) {
      console.log(err);
      return;
    }
    // 执行sql语句
    connection.query(sql, [name], function (err, result) {
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
filter_manager.post("/filter_manager/add", urlencodedParser, (req, res) => {
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
      let name = req.body.name;
      let source_ip = req.body.source_ip;
      let source_port = req.body.source_port;
      let dest_ip = req.body.dest_ip;
      let dest_port = req.body.dest_port;
      let protocol = req.body.protocol;
      let act = req.body.act;
      // 要执行的命令
      let cmd =
        "../main rule add -n " +
        name +
        " -si " +
        source_ip +
        " -sp " +
        source_port +
        " -ti " +
        dest_ip +
        " -tp " +
        dest_port +
        " -p " +
        protocol +
        " -a " +
        act +
        " -l no";
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
        insertFilterRule(
          name,
          source_ip,
          dest_ip,
          source_port,
          dest_port,
          protocol,
          act,
          res
        );
      });
    }
  });
});

filter_manager.get("/filter_manager/getall", urlencodedParser, (req, res) => {
  // 获取请求中的token
  let token = req.signedCookies.token;
  // 验证token
  jwt.verify(token, conf.key, (err, decoded) => {
    if (err) {
      console.log("Invalid token:", err.message);
      res.redirect("/login.html");
    } else {
      let sql = "SELECT * FROM t_filter_rules";
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
filter_manager.get("/filter_manager/del", urlencodedParser, (req, res) => {
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
      let name = req.query.name;
      // 要执行的命令
      let cmd = "../main rule del -n " + name;
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
        delFilterRule(name, res);
      });
    }
  });
});

/**
 * @brief 设置默认策略
 */
filter_manager.get("/filter_manager/setact", urlencodedParser, (req, res) => {
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
      let act = req.query.act;
      let cmd;
      let sql;
      if (act == "1") {
        // 要执行的命令
        cmd = "../main rule default ac";
        sql = "UPDATE t_act SET create_time=NOW(),act=1 WHERE `index`='act'";
      } else {
        cmd = "../main rule default re";
        sql = "UPDATE t_act SET create_time=NOW(),act=0 WHERE `index`='act'";
      }
      // 更新数据库的默认策略
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
          } else {
            res.send({ msg: "更新成功" });
          }
        });
        // 释放连接
        connection.release();
      });
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
      });
    }
  });
});

/**
 * @brief 获取当前的默认策略
 */
filter_manager.get("/filter_manager/getact", urlencodedParser, (req, res) => {
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
      let sql = "SELECT * FROM t_act LIMIT 100";
      // 更新数据库的默认策略
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
          } else {
            res.send({ code: conf.REQ_SUCCESS, msg: "获取成功", data: result[0].act });
          }
        });
        // 释放连接
        connection.release();
      });
    }
  });
});

module.exports = filter_manager;
