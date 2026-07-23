FROM node:20-alpine

WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install --prod --frozen-lockfile
COPY src ./src
COPY public ./public

ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "src/server.js"]
