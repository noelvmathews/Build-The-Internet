FROM node:20-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json ./
COPY src ./src
USER node
EXPOSE 3000
CMD ["npm", "start"]
