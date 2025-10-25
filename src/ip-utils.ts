import { IncomingMessage } from 'http';

/**
 * Extract the real client IP from an HTTP request, considering Cloudflare headers
 */
export function getClientIP(req: IncomingMessage): string {
  // Cloudflare provides the real IP in CF-Connecting-IP header
  const cfConnectingIP = req.headers['cf-connecting-ip'];
  if (cfConnectingIP) {
    return Array.isArray(cfConnectingIP) ? cfConnectingIP[0] : cfConnectingIP;
  }

  // Fallback to X-Forwarded-For (take first IP in chain)
  const xForwardedFor = req.headers['x-forwarded-for'];
  if (xForwardedFor) {
    const forwardedIPs = Array.isArray(xForwardedFor) 
      ? xForwardedFor[0] 
      : xForwardedFor;
    return forwardedIPs.split(',')[0].trim();
  }

  // Fallback to X-Real-IP
  const xRealIP = req.headers['x-real-ip'];
  if (xRealIP) {
    return Array.isArray(xRealIP) ? xRealIP[0] : xRealIP;
  }

  // Last resort: socket remote address
  return req.socket.remoteAddress || 'unknown';
}

