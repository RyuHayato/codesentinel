import http from "http";

const API_BASE = "http://api.example.com/v1";

const server = http.createServer((req, res) => {
  res.end("hello");
});

export { API_BASE, server };
