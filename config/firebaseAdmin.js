import fs from "node:fs";
import path from "node:path";
import admin from "firebase-admin";

function getCredential() {
  const inlineJson = process.env.FIREBASE_SERVICE_ACCOUNT_KEY;
  if (inlineJson) {
    return admin.credential.cert(JSON.parse(inlineJson));
  }

  const base64Json = process.env.FIREBASE_SERVICE_ACCOUNT_KEY_BASE64;
  if (base64Json) {
    const decoded = Buffer.from(base64Json, "base64").toString("utf8");
    return admin.credential.cert(JSON.parse(decoded));
  }

  const relativePath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH;
  if (relativePath) {
    const absolutePath = path.isAbsolute(relativePath)
      ? relativePath
      : path.join(process.cwd(), relativePath);
    const fileContent = fs.readFileSync(absolutePath, "utf8");
    return admin.credential.cert(JSON.parse(fileContent));
  }

  return admin.credential.applicationDefault();
}

if (!admin.apps.length) {
  admin.initializeApp({
    credential: getCredential(),
  });
}

export const firebaseAdmin = admin;
export const firebaseAuth = admin.auth();
