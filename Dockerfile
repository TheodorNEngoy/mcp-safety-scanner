FROM node:20-alpine

WORKDIR /app

COPY package.json README.md LICENSE CHANGELOG.md ./
COPY docs ./docs
COPY src ./src

ENTRYPOINT ["node", "/app/src/cli.js"]

