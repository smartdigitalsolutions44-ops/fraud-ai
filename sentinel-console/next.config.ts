import type { NextConfig } from "next";

// React's development build needs eval() for its debugging features; production never does.
const scriptSrc = process.env.NODE_ENV === "development" ? "'self' 'unsafe-inline' 'unsafe-eval'" : "'self' 'unsafe-inline'";

// Security headers for the console. The backend API key and signing secret never reach the
// browser: every call goes through the server-side /api routes (see ARCHITECTURE.md).
const securityHeaders = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=()" },
  {
    key: "Content-Security-Policy",
    // Next.js hydration needs inline scripts; everything else is same-origin only, and the
    // browser can only talk to this console's own server.
    value:
      `default-src 'self'; script-src ${scriptSrc}; style-src 'self' 'unsafe-inline'; ` +
      "img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; " +
      "base-uri 'none'; form-action 'self'; object-src 'none'",
  },
];

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
