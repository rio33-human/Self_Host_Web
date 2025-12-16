# Use official Node.js runtime as base image
FROM node:18-alpine

# Set working directory in container
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy application files
COPY . .

# Expose the port the app runs on
EXPOSE 3000

# Set environment variable for port (optional, app uses hardcoded 3000)
ENV PORT=3000

# Start the application
CMD ["npm", "start"]

