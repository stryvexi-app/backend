import "dotenv/config";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import admin from "firebase-admin";

const dir = path.dirname(fileURLToPath(import.meta.url));
if (!admin.apps.length) {
  let serviceAccount;
  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
  } else {
    const p = path.resolve(dir, process.env.FIREBASE_SERVICE_ACCOUNT_PATH || "./service-account.json");
    if (!fs.existsSync(p)) throw new Error("Firebase credentials missing: configure FIREBASE_SERVICE_ACCOUNT_JSON or service-account.json");
    serviceAccount = JSON.parse(fs.readFileSync(p, "utf8"));
  }
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL,
  });
}
export const db = admin.database();
