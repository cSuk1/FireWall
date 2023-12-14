// 导入express模块
const express = require("express");
var app = express();

app.use("/public", express.static("public"));
// 导入路由模块
const page = require("./modules/page");
const login = require("./modules/login");
const setEmail = require("./modules/email");
const filter_manager = require("./modules/filter");
const nat_manager = require("./modules/nat");
const conn_manager = require("./modules/getConn");
const init = require("./init");

// 注册路由模块，给路由模块添加访问前缀
app.use("/", page, login, setEmail, filter_manager, nat_manager, conn_manager);

var server = app.listen(9898, function () {
  // 初始化过滤规则
  init.initFilterRules();
  // 初始化默认行为
  init.initDefaultAct();
  // 初始化nat规则表
  init.initNATRules();
  var host = server.address().address;
  var port = server.address().port;

  console.log("应用实例，访问地址为 http://localhost:%s", port);
});
