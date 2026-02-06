export function example(req, res) {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
}
