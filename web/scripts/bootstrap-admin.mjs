import { PrismaClient } from "@prisma/client";
import { hashPassword } from "better-auth/crypto";

const email = process.env.BOOTSTRAP_ADMIN_EMAIL;
const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
const name = process.env.BOOTSTRAP_ADMIN_NAME ?? "Tawny Admin";

if (!email || !password) {
  console.error("BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD are required.");
  process.exit(1);
}

const prisma = new PrismaClient();

try {
  const existingUsers = await prisma.user.count();
  if (existingUsers > 0) {
    console.log("Users already exist; bootstrap skipped.");
    process.exit(0);
  }

  const user = await prisma.user.create({
    data: {
      email: email.toLowerCase(),
      name,
      role: "Admin",
      emailVerified: true,
    },
  });

  await prisma.account.create({
    data: {
      userId: user.id,
      providerId: "credential",
      accountId: user.id,
      password: await hashPassword(password),
    },
  });

  console.log(`Created bootstrap admin ${user.email}.`);
} finally {
  await prisma.$disconnect();
}
