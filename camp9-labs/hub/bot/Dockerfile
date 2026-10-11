# bot/Dockerfile — headless Playwright Admin Bot (the victim, logged in as mayor)
FROM node:20-slim
WORKDIR /app
COPY package.json .
RUN npm install && npx playwright install --with-deps chromium
COPY bot.js .
CMD ["node", "bot.js"]
