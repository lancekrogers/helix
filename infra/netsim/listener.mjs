import net from "node:net";

for (const port of process.argv.slice(2)) {
  net.createServer((s) => s.end()).listen(Number(port), "0.0.0.0");
}
