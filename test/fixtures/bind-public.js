import http from "node:http";

const server = http.createServer((_req, res) => {
  res.writeHead(200, { "content-type": "text/plain" });
  res.end("ok");
});

// Public bind: should be flagged.
server.listen(3000, "0.0.0.0");

