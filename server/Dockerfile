# ScreenHarbor server: ID registry + relay + web viewer
#   docker build -t screenharbor-server server
#   docker run -d -p 8080:8080 -p 8443:8443 -v screenharbor-data:/data screenharbor-server
FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && mkdir /data && chown node /data
COPY index.js ./
COPY web ./web
USER node
EXPOSE 8080 8443
VOLUME /data
HEALTHCHECK CMD wget -qO- http://127.0.0.1:8080/api/status || exit 1
CMD ["node", "index.js", "--port", "8080", "--https-port", "8443", "--data-dir", "/data"]
