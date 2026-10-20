import http from "node:http";

// Observe actual listener/close operations without adding production test hooks.
const listen = http.Server.prototype.listen;
http.Server.prototype.listen = function (...args) {
  this.once("listening", () => process.send({ event: "listening", port: this.address().port }));
  this.on("request", () => process.send({ event: "request" }));
  return listen.apply(this, args);
};
const close = http.Server.prototype.close;
http.Server.prototype.close = function (...args) {
  process.send({ event: "server-close" });
  return close.apply(this, args);
};
await import("../../src/server.js");
