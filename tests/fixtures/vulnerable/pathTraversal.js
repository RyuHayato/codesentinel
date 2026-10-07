import fs from "fs";
import path from "path";

export function serve(req, res) {
  const file = req.query.file;
  const data = fs.readFileSync(path.join(__dirname, "../" + file));
  fs.createReadStream("/var/www/" + req.params.name);
  res.send(data);
}
