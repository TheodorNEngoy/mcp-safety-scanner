import cors from "cors";

export function handler(app) {
  app.use(
    cors({
      origin: "*",
      credentials: true,
    })
  );
}

