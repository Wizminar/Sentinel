/**
 * Netlify Function: runs the same request handler as the Cloudflare Worker,
 * so a Netlify deploy gets the full scan API and badges on the site's own
 * origin. No separate backend to host.
 */
import { handle } from "../../apps/worker/src/index";

export default (req: Request) =>
  handle(req, { ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS });

export const config = {
  path: ["/api/*", "/badge", "/badge.svg"],
  // Netlify's built-in rate limiting: 20 requests per minute per client IP.
  rateLimit: { windowLimit: 20, windowSize: 60, aggregateBy: ["ip", "domain"] },
};
