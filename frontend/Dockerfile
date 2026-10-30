# Build the SPA, then serve it with nginx, which also proxies /api to the backend (same origin => cookies just work).
FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
# BACKEND_URL is substituted into the template at container start (nginx image feature).
ENV BACKEND_URL=http://backend:8000
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=15s --timeout=4s CMD wget -qO- http://127.0.0.1/healthz || exit 1
