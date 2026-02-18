FROM node:22

# Install ClamAV
RUN apt-get update && \
    apt-get install -y clamav clamav-daemon && \
    freshclam

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY . .

# Create folders
RUN mkdir -p vault quarantine temp

# Expose port
EXPOSE 5000

# Start server
CMD ["node", "src/server.js"]
