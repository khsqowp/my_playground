const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function main() {
  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;
  const name = process.env.ADMIN_NAME || "관리자";

  if (!email || !password) {
    console.error("❌ ADMIN_EMAIL or ADMIN_PASSWORD not set in environment.");
    process.exit(1);
  }

  const hashedPassword = await bcrypt.hash(password, 12);

  const admin = await prisma.user.upsert({
    where: { email: email },
    update: { password: hashedPassword },
    create: {
      email: email,
      password: hashedPassword,
      name: name,
      role: "OWNER",
    },
  });

  console.log(`✅ Admin account synced: ${admin.email}`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
