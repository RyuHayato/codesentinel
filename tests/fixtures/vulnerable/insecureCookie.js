export function login(res, userId) {
  res.cookie("session", userId, { path: "/" });
  res.cookie("prefs", "dark", { httpOnly: false, secure: false });
}
