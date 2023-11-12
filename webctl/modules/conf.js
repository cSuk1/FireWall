// 连接配置文件
var mysql = require("mysql");

// 连接池
const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "cx20030314",
  database: "db_firewall",
});

// 密钥
let key = "e0b6d6e8e7efce81d8a2b91b4f7b2d3c8f1c9e6b9a1d9e7f6a9a5b8c4d7f3d5a";
let LOGIIN_SUCCESS = 10000;
// 登录成功
let LOGIIN_FAIL = 10001;
// 登录失败
let ERROR_SERVER = 10002;
// 服务器错误
let ERROR_PARAM = 10003;
let UNINIT_EMAIL = 10004;
let INIT_SUCCESS = 10005;
let ADD_FILTER_RULE_SUCCESS=1006;
let ERROR_NODATA = 1007;
let DEL_FILTER_RULE_SUCCESS = 1008;
let REQ_SUCCESS = 1009;

module.exports = {
  pool: pool,
  key: key,
  LOGIIN_SUCCESS: LOGIIN_SUCCESS,
  LOGIIN_FAIL: LOGIIN_FAIL,
  ERROR_SERVER: ERROR_SERVER,
  ERROR_PARAM: ERROR_PARAM,
  UNINIT_EMAIL: UNINIT_EMAIL,
  INIT_SUCCESS: INIT_SUCCESS,
  ADD_FILTER_RULE_SUCCESS: ADD_FILTER_RULE_SUCCESS,
  ERROR_NODATA: ERROR_NODATA,
  DEL_FILTER_RULE_SUCCESS: DEL_FILTER_RULE_SUCCESS,
  REQ_SUCCESS: REQ_SUCCESS
};
