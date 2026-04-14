import admin from "firebase-admin";

function getCredential() {
  if (
    process.env.FIREBASE_PROJECT_ID &&
    process.env.FIREBASE_PRIVATE_KEY &&
    process.env.FIREBASE_CLIENT_EMAIL
  ) {
    return admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    });
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

  return admin.credential.applicationDefault();
}

if (!admin.apps.length) {
  admin.initializeApp({
    credential: getCredential(),
  });
}

export const firebaseAdmin = admin;
export const firebaseAuth = admin.auth();
