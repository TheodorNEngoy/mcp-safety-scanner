import cors from "cors";

export function setup(app) {
  // Multi-line options object: scanner should still flag wildcard origin.
  app.use(
    cors({
      origin: "*",
    }),
  );
}

