import { NextFunction, Request, Response } from "express";
import jwt, { JwtPayload, SignOptions } from "jsonwebtoken";
import { COOKIE_NAME } from "./constants.js";

// Create JWT token
export const createToken = (id: string, email: string, expiresIn: string) => {
  const payload = { id, email };
  const token = jwt.sign(payload, process.env.JWT_SECRET as string, {
    expiresIn: expiresIn as SignOptions["expiresIn"],
  });
  return token;
};

// Middleware to verify JWT token
export const verifyToken = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const token = req.signedCookies[`${COOKIE_NAME}`];

  if (!token || token.trim() === "") {
    return res.status(401).json({ message: "Token Not Received" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as JwtPayload;
    res.locals.jwtData = decoded;
    return next();
  } catch (err) {
    return res.status(401).json({ message: "Token Expired" });
  }
};
