const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const admin = require("firebase-admin");

const app = express();

app.use(cors());
app.use(express.json({ limit: "20kb" }));

// Connect to your existing Firebase project.
const serviceAccount = JSON.parse(
  process.env.FIREBASE_SERVICE_ACCOUNT
);

admin.initializeApp({
  credential: admin.credential.cert({
    ...serviceAccount,
    private_key: serviceAccount.private_key.replace(/\\n/g, "\n")
  }),
  databaseURL: process.env.FIREBASE_DATABASE_URL
});

const db = admin.database();

function verifyTelegram(initData) {
  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");
  const authDate = Number(params.get("auth_date"));

  if (
    !receivedHash ||
    !/^[a-f0-9]{64}$/i.test(receivedHash) ||
    !Number.isSafeInteger(authDate)
  ) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);

  if (authDate > now + 30 || now - authDate > 3600) {
    return null;
  }

  params.delete("hash");

  const checkString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secretKey = crypto
    .createHmac("sha256", "WebAppData")
    .update(process.env.TELEGRAM_BOT_TOKEN)
    .digest();

  const expectedHash = crypto
    .createHmac("sha256", secretKey)
    .update(checkString)
    .digest();

  const suppliedHash = Buffer.from(receivedHash, "hex");

  if (!crypto.timingSafeEqual(expectedHash, suppliedHash)) {
    return null;
  }

  try {
    const user = JSON.parse(params.get("user") || "null");

    if (!user || !Number.isSafeInteger(user.id)) {
      return null;
    }

    return {
      id: user.id,
      first_name: String(user.first_name || "").slice(0, 100),
      username: user.username
        ? String(user.username).slice(0, 100)
        : null
    };
  } catch {
    return null;
  }
}

app.get("/", (req, res) => {
  res.json({
    online: true,
    name: "garden-game-api",
    version: "1.0.0"
  });
});

app.post("/telegram/verify", async (req, res) => {
  try {
    const initData = req.body?.initData;

    if (typeof initData !== "string" || initData.length > 10000) {
      return res.status(400).json({
        ok: false,
        error: "initData_required"
      });
    }

    const user = verifyTelegram(initData);

    if (!user) {
      return res.status(401).json({
        ok: false,
        error: "invalid_telegram_authorization"
      });
    }

    await db.ref(`telegramUsers/${user.id}`).update({
      id: user.id,
      first_name: user.first_name,
      username: user.username,
      last_seen: admin.database.ServerValue.TIMESTAMP
    });

    return res.json({
      ok: true,
      user: {
        id: user.id,
        first_name: user.first_name,
        username: user.username
      }
    });
  } catch (error) {
    console.error("API error:", error.message);

    return res.status(500).json({
      ok: false,
      error: "server_error"
    });
  }
});

const port = process.env.PORT || 3000;

app.listen(port, "0.0.0.0", () => {
  console.log(`API listening on port ${port}`);
});
