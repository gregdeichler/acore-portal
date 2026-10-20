// Replace only MySQL; the child runs the real Express application and HTTP server.
export async function resolve(specifier, context, nextResolve) {
  if (specifier === "mysql2/promise") {
    return { url: new URL("./mysql-pool.mjs", import.meta.url).href, shortCircuit: true };
  }
  return nextResolve(specifier, context);
}
