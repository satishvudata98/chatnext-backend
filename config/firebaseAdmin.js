import fs from "node:fs";
import path from "node:path";
import admin from "firebase-admin";

function normalizePrivateKey(privateKey) {
  if (!privateKey || typeof privateKey !== "string") return null;
  return privateKey.replace(/\\n/g, "\n");
}

function looksLikePlaceholder(value) {
  if (!value || typeof value !== "string") return true;
  return value.includes("your_private_key_here") || value.includes("your_private_key_id_here");
}

function getCredentialFromFlatEnv() {
  const projectId = process.env.FIREBASE_PROJECT_ID;
  const privateKey = normalizePrivateKey(process.env.FIREBASE_PRIVATE_KEY);
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;

  if (!projectId || !privateKey || !clientEmail) {
    return null;
  }

  if (looksLikePlaceholder(privateKey) || looksLikePlaceholder(clientEmail)) {
    return null;
  }

  return admin.credential.cert({
    projectId,
    privateKey,
    clientEmail,
  });
}

function getCredential() {
  const flatEnvCredential = getCredentialFromFlatEnv();
  if (flatEnvCredential) {
    return flatEnvCredential;
  }

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

  console.warn(
    "Firebase Admin is using application default credentials. " +
      "Set FIREBASE_PRIVATE_KEY/FIREBASE_CLIENT_EMAIL/FIREBASE_PROJECT_ID " +
      "or FIREBASE_SERVICE_ACCOUNT_KEY for reliable token verification.",
  );
  return admin.credential.applicationDefault();
}

if (!admin.apps.length) {
  admin.initializeApp({
    credential: getCredential(),
    projectId: process.env.FIREBASE_PROJECT_ID,
  });
}


export const firebaseAuth = admin.auth();

export {default as firebaseAdmin} from "firebase-admin";