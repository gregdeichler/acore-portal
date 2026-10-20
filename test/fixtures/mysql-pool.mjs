export default {
  createPool() {
    // Model an open database socket so a stalled cleanup cannot exit naturally.
    const keepAlive = setInterval(() => {}, 1000);
    return {
      async end() {
        process.send({ event: "pool-end" });
        await new Promise((resolve, reject) => {
          process.once("message", ({ action }) => {
            if (action === "reject-pool") reject(new Error("test pool failure"));
            else resolve();
          });
        });
        clearInterval(keepAlive);
      }
    };
  }
};
