import type { NextConfig } from "next";

// Build-time security gate: Reject production builds configured with demo authentication
const isProduction =
  process.env.NODE_ENV === "production" ||
  process.env.NEXT_PUBLIC_ENV === "production";

if (isProduction && process.env.NEXT_PUBLIC_DEMO_MODE === "true") {
  throw new Error(
    "BUILD ERROR: Production builds must not be configured with NEXT_PUBLIC_DEMO_MODE=true. " +
    "Production builds must strictly disable demo authentication shortcuts and one-click persona switching."
  );
}

const nextConfig: NextConfig = {
  /* config options here */
};

export default nextConfig;
