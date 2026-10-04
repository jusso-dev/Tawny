import { betterAuth } from "better-auth";
import { prismaAdapter } from "better-auth/adapters/prisma";
import { prisma } from "@/lib/prisma";

export const auth = betterAuth({
  database: prismaAdapter(prisma, {
    provider: "sqlserver",
  }),
  secret: process.env.BETTER_AUTH_SECRET!,
  baseURL: process.env.BETTER_AUTH_URL ?? "http://localhost:3000",
  user: {
    additionalFields: {
      role: {
        type: "string",
        required: true,
        // Least privilege: admins are created by the bootstrap script or promoted explicitly.
        defaultValue: "Viewer",
        input: false,
      },
    },
  },
  emailAndPassword: {
    enabled: true,
    // No self-service registration. Accounts are provisioned by an admin.
    disableSignUp: true,
  },
  socialProviders: process.env.GITHUB_CLIENT_ID
    ? {
        github: {
          clientId: process.env.GITHUB_CLIENT_ID,
          clientSecret: process.env.GITHUB_CLIENT_SECRET!,
          // GitHub may only sign in users that already exist.
          disableSignUp: true,
        },
      }
    : undefined,
});

export type Session = typeof auth.$Infer.Session;
