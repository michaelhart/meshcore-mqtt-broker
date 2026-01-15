FROM node:18-alpine

# Install build tools for native dependencies (better-sqlite3)
RUN apk add --no-cache python3 make g++

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY . .

# Create data directory for abuse detection persistence
RUN mkdir -p /data

# Expose WebSocket MQTT port
EXPOSE 8883

# Run the server directly with tsx
CMD ["npx", "tsx", "src/server.ts"]