import { firebaseAuth } from "../config/firebaseAdmin.js";

export function extractBearerToken(authorizationHeader) {
  if (!authorizationHeader || typeof authorizationHeader !== "string") {
    return null;
  }

  const [scheme, token] = authorizationHeader.split(" ");
  if (scheme !== "Bearer" || !token) {
    return null;
  }

  return token;
}

export async function verifyFirebaseToken(token) {
  if (!token) {
    const error = new Error("Missing authorization token");
    error.statusCode = 401;
    throw error;
  }

  try {
    return await firebaseAuth.verifyIdToken(token);
  } catch {
    const error = new Error("Invalid Firebase token");
    error.statusCode = 401;
    throw error;
  }
}

export async function authenticateRequest(req) {
  const token = extractBearerToken(req.headers.authorization);
  const decodedToken = await verifyFirebaseToken(token);
  req.firebaseUser = decodedToken;
  return decodedToken;
}
