// 配置
const conf = require("./modules/conf");
// 执行
const { exec } = require("child_process");

// 初始化过滤规则
function initFilterRules() {
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
      } else {
        // 如果没有错误，则输出查询结果
        if (result.length > 0) {
          // 遍历数据库查询结果
          for (let i = 0; i < result.length; i++) {
            let cmd =
              "../main rule add -n " +
              result[i].name +
              " -si " +
              result[i].src_ip +
              " -sp " +
              result[i].src_port +
              " -ti " +
              result[i].dst_ip +
              " -tp " +
              result[i].dst_port +
              " -p " +
              result[i].protocol +
              " -a " +
              result[i].act +
              " -l no";
            exec(cmd, (error, stdout, stderr) => {
              if (error) {
                console.log("执行命令发生错误：" + error.message);
                return;
              }
              if (stderr) {
                console.log(stderr);
                return;
              }
              console.log(stdout);
            });
          }
        }
      }
    });
    // 释放连接
    connection.release();
  });
}


function initNATRules() {
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
      } else {
        // 如果没有错误，则输出查询结果
        if (result.length > 0) {
          // 遍历数据库查询结果
          for (let i = 0; i < result.length; i++) {
            let cmd =
              "../main nat add -si " +
              result[i].src_ip +
              " -ti " +
              result[i].dst_ip +
              " -tp " +
              result[i].min_port +
              "-" +
              result[i].max_port;
            exec(cmd, (error, stdout, stderr) => {
              if (error) {
                console.log("执行命令发生错误：" + error.message);
                return;
              }
              if (stderr) {
                console.log(stderr);
                return;
              }
              console.log(stdout);
            });
          }
        }
      }
    });
    // 释放连接
    connection.release();
  });
}

function initDefaultAct() {
  conf.pool.getConnection((err, connection) => {
    if (err) {
      console.log(err);
      return;
    }
    // 执行sql语句
    let sql = "SELECT * FROM t_act LIMIT 100";
    connection.query(sql, [], function (err, result) {
      // 如果有错误，则输出错误信息
      if (err) {
        console.log(err);
      } else {
        let cmd;
        if (result[0].act == 1) {
          cmd = "../main rule default ac";
        } else {
          cmd = "../main rule default re";
        }
        // 执行命令
        exec(cmd, (error, stdout, stderr) => {
          if (error) {
            console.log("执行命令发生错误：" + error.message);
            return;
          }
          if (stderr) {
            console.log(stderr);
          } else {
            console.log(stdout);
          }

        });
      }
    });
    // 释放连接
    connection.release();
  });
}

module.exports = {
  initFilterRules: initFilterRules,
  initDefaultAct: initDefaultAct,
  initNATRules: initNATRules
}
