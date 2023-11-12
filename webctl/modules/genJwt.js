// 引入jwt
const jwt = require("jsonwebtoken");
const {
    key
  } = require("./conf");
/**
 * @brief 生成token
 * @param {*} username
 * @returns tokrn
 */
function generateToken(username) {
  // 生成token
  const token = jwt.sign(
    {
      username,
    },
    key,
    { expiresIn: "1h" }
  );
  return token;
}

module.exports = {
  generateToken: generateToken,
};
