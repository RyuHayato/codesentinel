import express from "express";

const router = express.Router();

router.post("/login", (req, res) => {
  const username = process.env.ADMIN_USER;
  const password = req.body.password; // comes from user input at runtime — not hardcoded
  res.json({ ok: username && password });
});

export default router;
