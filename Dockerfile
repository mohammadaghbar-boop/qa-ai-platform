FROM node:20-alpine

# Install k6 for performance testing
RUN apk add --no-cache bash curl \
  && curl -fsSL https://github.com/grafana/k6/releases/download/v0.50.0/k6-v0.50.0-linux-amd64.tar.gz \
     | tar -xz --strip-components=1 -C /usr/local/bin k6-v0.50.0-linux-amd64/k6 \
  && chmod +x /usr/local/bin/k6

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.js .
COPY index.html .

EXPOSE 3456

CMD ["node", "server.js"]
