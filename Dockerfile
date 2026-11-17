# syntax=docker/dockerfile:1.7
# One image = API + web UI (same origin, no CORS). ~200 MB, runs as non-root.

# ---- 1. build the web app -------------------------------------------------
FROM node:22-alpine AS web
WORKDIR /src
COPY package.json package-lock.json ./
COPY packages/crypto/package.json packages/crypto/
COPY apps/web/package.json apps/web/
COPY apps/cli/package.json apps/cli/
RUN npm ci --no-audit --no-fund
COPY packages packages
COPY apps/web apps/web
RUN mkdir -p apps/server/src/main/resources && npm run build -w @keyvault/web

# ---- 2. build the server jar ----------------------------------------------
FROM eclipse-temurin:21-jdk-alpine AS server
WORKDIR /src
COPY apps/server/.mvn .mvn
COPY apps/server/mvnw apps/server/pom.xml ./
RUN chmod +x mvnw && ./mvnw -q -B dependency:go-offline
COPY apps/server/src src
COPY --from=web /src/apps/server/src/main/resources/static src/main/resources/static
RUN ./mvnw -q -B -DskipTests package && cp target/keyvault-server-*.jar /app.jar

# ---- 3. runtime ------------------------------------------------------------
FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S keyvault && adduser -S keyvault -G keyvault
USER keyvault
WORKDIR /app
COPY --from=server /app.jar app.jar
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError"
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s CMD wget -qO- http://127.0.0.1:8080/actuator/health || exit 1
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
