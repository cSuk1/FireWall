// 一个web服务器监听80端口返回hello world
const http = require('http');
http.createServer((req, res) => {
    res.end('hello world');
}).listen(80);