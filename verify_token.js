import jwt from "jsonwebtoken";
import BlackList from "../models/blackListerToken.js";

export const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send({ msg: "Authorization header missing or invalid" });
  }
  let token = authHeader.split(" ")[1];
  let findBlock = await BlackList.findOne({ token: token });
  if (findBlock) {
    return res.status(401).send({ msg: "Token is blacklisted, please login again" });
  }
  jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
    if (err) {
      return res
        .status(401)
        .send({ msg: "You're not authenticated person", Error: err.message });
    }

    console.log(decoded);
    req.user = decoded;
    next();
  });
};
