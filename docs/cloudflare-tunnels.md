# Deploying MeshCore MQTT Broker with Cloudflare Tunnels

This guide shows you how to deploy the MQTT broker on a server (Dokploy, bare metal, VPS, etc.) and expose it securely over the internet with TLS using Cloudflare Tunnels.

## Overview

Cloudflare Tunnels provide a secure way to expose your MQTT broker to the internet without:
- Opening ports on your firewall (please, keep your ports closed!)
- Managing SSL/TLS certificates manually
- Dealing with dynamic IP addresses
- Exposing your server's IP address

The tunnel creates an encrypted connection from your server to Cloudflare's network, and Cloudflare handles all TLS termination.

## Prerequisites

- A server to run the MQTT broker (Linux recommended)
- A Cloudflare account with a domain configured
- Access to Cloudflare Zero Trust dashboard
- Node.js 22+ installed on your server

## Part 1: Deploy the MQTT Broker

### Option A: Deploying with Dokploy (Recommended)

Dokploy uses Nixpacks to automatically detect and build Node.js/TypeScript projects.

1. **Create a new application in Dokploy**
   - Go to your Dokploy dashboard
   - Create a new application
   - Connect your git repository

2. **Configure environment variables**
   
   In the Dokploy environment variables section, add:
   
   ```bash
   MQTT_WS_PORT=8883
   MQTT_HOST=0.0.0.0
   AUTH_EXPECTED_AUDIENCE=mqtt.yourdomain.com
   
   # Add your subscriber users (as many as you need)
   SUBSCRIBER_1=admin:your-secure-password-here
   SUBSCRIBER_2=viewer:another-password
   SUBSCRIBER_3=monitor:yet-another-password
   ```

3. **Deploy**
   
   Dokploy will automatically:
   - Install dependencies (`npm install`)
   - Build the TypeScript code (`npm run build`)
   - Start the server (`npm start`)

4. Expose the MQTT broker
   
   - Go to your Dokploy dashboard
   - Click on the application
   - Click on the **Advanced** tab
   - Under **Ports**, click **Add Port**
   - Published port: `8883`
   - Select Published Port Mode: **Ingress** 
   - Select Targeting Port: **`8883` over TCP**
   - Click **Create**

Note: In your firewall settings (whether on the server or part of your network), you should not open port 8883. The Cloudflare Tunnels daemon (cloudflared) running on your server will access the MQTT broker over localhost:8883. You should verify that if you try to hit this port via the LAN or WAN IP the connection is refused.

### Option B: Manual Deployment on Linux Server

1. **Clone the repository**
   
   ```bash
   git clone https://github.com/michaelhart/meshcore-mqtt-broker.git
   cd meshcore-mqtt-broker
   ```

2. **Install dependencies**
   
   ```bash
   npm install
   ```

3. **Create environment file**
   
   ```bash
   cp .env.example .env
   nano .env
   ```
   
   Edit the values:
   
   ```bash
   MQTT_WS_PORT=8883
   MQTT_HOST=0.0.0.0
   AUTH_EXPECTED_AUDIENCE=mqtt.yourdomain.com
   
   SUBSCRIBER_1=admin:your-secure-password
   SUBSCRIBER_2=viewer:another-password
   ```

4. **Build and start**
   
   ```bash
   npm run build
   npm start
   ```

5. **Run as a service (optional but recommended)**
   
   Create a systemd service file `/etc/systemd/system/meshcore-mqtt-broker.service`, along the lines of:
   
   ```ini
   [Unit]
   Description=MeshCore MQTT Broker
   After=network.target
   
   [Service]
   Type=simple
   User=nodejs
   WorkingDirectory=/opt/meshcore-mqtt-broker
   Environment=NODE_ENV=production
   ExecStart=/usr/bin/npm start
   Restart=always
   RestartSec=10
   
   [Install]
   WantedBy=multi-user.target
   ```
   
   Enable and start:
   
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable meshcore-mqtt-broker
   sudo systemctl start meshcore-mqtt-broker
   ```

6. **Verify it's running**
   
   ```bash
   sudo systemctl status meshcore-mqtt-broker
   # or check the logs
   sudo journalctl -u meshcore-mqtt-broker -f
   ```

## Part 2: Set Up Cloudflare Tunnel

### Step 1: Create a Cloudflare Tunnel

Follow the [Cloudflare Tunnel documentation](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/create-remote-tunnel/) to create a tunnel.

Quick summary:
1. Go to [Cloudflare Zero Trust dashboard](https://one.dash.cloudflare.com/)
2. Navigate to **Networks** > **Tunnels**
3. Click **Create a tunnel**
4. Choose **Cloudflared** as the tunnel type
5. Name your tunnel (e.g., `mqtt-broker`)
6. Install and run the connector on your server
7. Verify the tunnel shows as **Healthy**

### Step 2: Configure the Tunnel

1. Navigate to your tunnel in the Cloudflare Zero Trust dashboard
2. Click **"Configure"** on your tunnel
3. Click the **"Published application routes"** tab at the top
4. Click **"Add a published application route"**

### Step 3: Add Published Application Route

Configure the route with the following settings:

| Field | Value | Notes |
|-------|-------|-------|
| **Subdomain** | `mqtt` | Or your preferred subdomain (e.g., `mqtt-us`, `mqtt-prod`) |
| **Domain** | `yourdomain.com` | Select your domain from the dropdown |
| **Path** | _(leave empty)_ | No path needed for MQTT |
| **Service Type** | `HTTP` | **Important**: Use HTTP, not HTTPS |
| **URL** | `localhost:8883` | Your local MQTT broker address |

### Example Configuration

```
Hostname: mqtt.yourdomain.com
Service:  HTTP -> localhost:8883
```

This will create a public endpoint at `https://mqtt.yourdomain.com` that securely tunnels to your local MQTT broker running on port 8883.

### Step 4: Update Your Environment Variables

Update your `.env` file to match your tunnel hostname:

```bash
# MQTT Server Settings
MQTT_WS_PORT=8883
MQTT_HOST=0.0.0.0

# Authentication Settings
AUTH_EXPECTED_AUDIENCE=mqtt.yourdomain.com
```

The `AUTH_EXPECTED_AUDIENCE` setting ensures that JWT tokens must specify the correct audience claim to connect. This prevents tokens intended for one broker from being used on another.

## Part 3: Connect Clients

Clients should now connect using **WSS** (WebSocket Secure) protocol to your public Cloudflare Tunnel endpoint:

```
wss://mqtt.yourdomain.com
```

Make sure to set the `aud` claim in your auth tokens to match your `AUTH_EXPECTED_AUDIENCE` value.

See the main README for client connection examples.

## Important Notes

### TLS/SSL Certificate Management

**You don't need to configure any certificates on your MQTT broker!**

- The broker continues to run plain HTTP/WebSocket on `localhost:8883`
- Cloudflare Tunnels automatically handle TLS/SSL termination
- Cloudflare manages certificate renewal and updates
- Clients connect to Cloudflare via HTTPS/WSS
- Cloudflare forwards requests to your local broker via the encrypted tunnel

### Security Considerations

1. **Audience Validation**: Always set `AUTH_EXPECTED_AUDIENCE` to prevent token reuse across different broker instances
2. **Token Expiration**: Use `exp` claims in your JWT tokens to limit token lifetime
3. **Firewall**: Your MQTT broker never needs to be directly exposed to the internet
4. **Origin ID Validation**: The broker validates that the `origin_id` in published messages matches the authenticated public key

### Troubleshooting

**Connection refused / timeout:**
- Verify your tunnel status is "Healthy" in the Cloudflare dashboard
- Check that the service URL is correct: `localhost:8883`
- Ensure service type is set to `HTTP` (not HTTPS)

**Authentication failed:**
- Verify the `aud` claim in your token matches `AUTH_EXPECTED_AUDIENCE`
- Check that your public key is correctly formatted (64 uppercase hex characters)
- Ensure your token hasn't expired

**Publish denied:**
- Confirm the `origin_id` in your message matches your authenticated public key
- Verify your topic format is correct: `meshcore/{IATA_CODE}/subtopic`
- Check that your IATA code is valid (use "test" for testing)

## Multiple Regions

You can set up multiple tunnel endpoints for different regions:

```
mqtt-us.yourdomain.com  -> US broker
mqtt-eu.yourdomain.com  -> EU broker
mqtt-ap.yourdomain.com  -> Asia-Pacific broker
```

Each broker should have its own `AUTH_EXPECTED_AUDIENCE` value to prevent cross-region token usage.

