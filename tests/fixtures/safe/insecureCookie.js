export function login(res, userId) {
  res.cookie("session", userId, { httpOnly: true, secure: true, sameSite: "lax", path: "/" });
}
