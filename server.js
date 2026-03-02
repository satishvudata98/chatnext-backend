import dotenv from "dotenv";
dotenv.config();

import http from "node:http";
import url from "node:url";
import { WebSocketServer } from "ws";
import bcrypt from "bcrypt";
import { v4 as uuidv4 } from "uuid";
import supabase from "./supabaseClient.js";
import {
  authenticateRequest,
  verifyFirebaseToken,
} from "./middleware/firebaseAuth.js";

const PORT = process.env.PORT || 3000;
const clients = new Map();
const MEDIA_BUCKET = process.env.SUPABASE_MEDIA_BUCKET || "chat-media";
const MAX_MEDIA_SIZE_BYTES = 10 * 1024 * 1024;
const ALLOWED_MEDIA_TYPES = new Set(["image/jpeg", "image/jpg", "image/png"]);
const BUDDY_REQUEST_STATUS = {
  PENDING: "PENDING",
  ACCEPTED: "ACCEPTED",
  REJECTED: "REJECTED",
};

process.on("uncaughtException", (err) => {
  console.error("UNCAUGHT EXCEPTION:", err);
});

process.on("unhandledRejection", (err) => {
  console.error("UNHANDLED REJECTION:", err);
});

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin;

  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }

  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const protocol = req.headers["x-forwarded-proto"] || "http";
  const host = req.headers.host || "localhost";

  let parsedUrl;
  try {
    parsedUrl = new url.URL(req.url, `${protocol}://${host}`);
  } catch (err) {
    console.error("URL parse error:", err);
    return sendJSON(res, 400, { success: false, message: "Invalid URL" });
  }

  const pathname = parsedUrl.pathname;

  if (req.method === "GET" && pathname === "/") {
    return sendJSON(res, 200, {
      success: true,
      message: "ChatNext backend running",
    });
  }

  // Legacy routes retained for compatibility with previous frontend clients.
  if (
    (req.method === "POST" && pathname === "/api/auth/register") ||
    (req.method === "POST" && pathname === "/api/auth/login") ||
    (req.method === "POST" && pathname === "/api/auth/refresh")
  ) {
    return sendJSON(res, 410, {
      success: false,
      message: "Direct auth endpoints are deprecated. Use Firebase Authentication from the frontend.",
    });
  }

  if (req.method === "GET" && pathname === "/api/auth/verify") {
    const authContext = await requireAuthContext(req, res);
    if (!authContext) return;

    const { firebaseUser, internalUser } = authContext;
    sendJSON(res, 200, {
      success: true,
      user: formatUserForClient(internalUser),
      firebaseUser: {
        uid: firebaseUser.uid,
        email: firebaseUser.email || null,
        name: firebaseUser.name || null,
        picture: firebaseUser.picture || null,
      },
    });
    return;
  }

  if (req.method === "POST" && pathname === "/api/user/public-key") {
    const authContext = await requireAuthContext(req, res);
    if (!authContext) return;

    let body = "";
    req.on("data", (chunk) => (body += chunk));

    req.on("end", async () => {
      try {
        const { publicKey } = JSON.parse(body);

        const { error } = await supabase
          .from("users")
          .update({ public_key: publicKey })
          .eq("id", authContext.internalUser.id);

        if (error) return sendJSON(res, 500, { success: false, message: error.message });

        sendJSON(res, 200, { success: true });
      } catch (err) {
        sendJSON(res, 500, { success: false, message: err.message });
      }
    });

    return;
  }

  if (req.method === "GET" && pathname === "/api/user/public-key") {
    const authContext = await requireAuthContext(req, res);
    if (!authContext) return;

    const userId = parsedUrl.searchParams.get("userId");
    if (!userId) {
      return sendJSON(res, 400, { success: false, message: "Missing userId" });
    }

    const canAccessPublicKey = await areUsersConfirmedBuddies(authContext.internalUser.id, userId);
    if (!canAccessPublicKey) {
      return sendJSON(res, 403, { success: false, message: "Public key is available for buddies only" });
    }

    const { data: user, error } = await supabase
      .from("users")
      .select("public_key")
      .eq("id", userId)
      .single();

    if (error || !user) return sendJSON(res, 404, { success: false, message: "User not found" });

    sendJSON(res, 200, { success: true, publicKey: user.public_key });
    return;
  }

  if (req.method === "POST" && pathname === "/api/user/encrypted-private-key") {
    const authContext = await requireAuthContext(req, res);
    if (!authContext) return;

    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });

    req.on("end", async () => {
      try {
        const { encryptedKey, salt, iv } = JSON.parse(body);

        if (!encryptedKey || !salt || !iv) {
          return sendJSON(res, 400, { success: false, message: "Missing encrypted key data" });
        }

        const { error } = await supabase
          .from("users")
          .update({
            encrypted_private_key: encryptedKey,
            private_key_salt: salt,
            private_key_iv: iv,
          })
          .eq("id", authContext.internalUser.id);

        if (error) {
          console.error("Error storing encrypted private key:", error);
          return sendJSON(res, 500, { success: false, message: "Failed to store encrypted key" });
        }

        sendJSON(res, 200, { success: true, message: "Encrypted private key stored" });
      } catch (e) {
        console.error("Error:", e);
        sendJSON(res, 400, { success: false, message: "Invalid request" });
      }
    });
    return;
  }

  if (req.method === "GET" && pathname === "/api/user/encrypted-private-key") {
    const authContext = await requireAuthContext(req, res);
    if (!authContext) return;

    const { data: user, error } = await supabase
      .from("users")
      .select("encrypted_private_key, private_key_salt, private_key_iv, public_key")
      .eq("id", authContext.internalUser.id)
      .single();

    if (error || !user) {
      return sendJSON(res, 404, { success: false, message: "User not found" });
    }

    if (!user.encrypted_private_key) {
      return sendJSON(res, 404, { success: false, message: "No encrypted private key found" });
    }

    sendJSON(res, 200, {
      success: true,
      encryptedKey: user.encrypted_private_key,
      salt: user.private_key_salt,
      iv: user.private_key_iv,
      publicKey: user.public_key,
    });
    return;
  }

  if (req.method === "POST" && pathname === "/api/user/conversation-keys") {
    const authContext = await requireAuthContext(req, res);
    if (!authContext) return;

    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", async () => {
      try {
        const { conversationId, encryptedKey, salt, iv } = JSON.parse(body);

        if (!conversationId || !encryptedKey || !salt || !iv) {
          return sendJSON(res, 400, { success: false, message: "Missing conversation key data" });
        }

        const { data: user } = await supabase
          .from("users")
          .select("conversation_keys")
          .eq("id", authContext.internalUser.id)
          .single();

        let conversationKeys = {};
        if (user && user.conversation_keys) {
          try {
            conversationKeys = JSON.parse(user.conversation_keys);
          } catch {
            conversationKeys = {};
          }
        }

        conversationKeys[conversationId] = {
          encryptedKey,
          salt,
          iv,
          storedAt: getCurrentTimestamp(),
        };

        const { error } = await supabase
          .from("users")
          .update({
            conversation_keys: JSON.stringify(conversationKeys),
          })
          .eq("id", authContext.internalUser.id);

        if (error) {
          console.error("Error storing conversation key:", error);
          return sendJSON(res, 500, { success: false, message: "Failed to store conversation key" });
        }

        sendJSON(res, 200, { success: true, message: "Conversation key stored" });
      } catch (e) {
        console.error("Error:", e);
        sendJSON(res, 400, { success: false, message: "Invalid request" });
      }
    });
    return;
  }

  if (req.method === "GET" && pathname === "/api/user/conversation-keys") {
    const authContext = await requireAuthContext(req, res);
    if (!authContext) return;

    const { data: user, error } = await supabase
      .from("users")
      .select("conversation_keys")
      .eq("id", authContext.internalUser.id)
      .single();

    if (error || !user) {
      return sendJSON(res, 404, { success: false, message: "User not found" });
    }

    let conversationKeys = {};
    if (user.conversation_keys) {
      try {
        conversationKeys = JSON.parse(user.conversation_keys);
      } catch (e) {
        console.error("Error parsing conversation keys:", e);
      }
    }

    sendJSON(res, 200, {
      success: true,
      conversationKeys,
    });
    return;
  }

  if (req.method === "POST" && pathname === "/api/media/upload") {
    const authContext = await requireAuthContext(req, res);
    if (!authContext) return;

    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > MAX_MEDIA_SIZE_BYTES * 2) {
        req.destroy();
      }
    });

    req.on("end", async () => {
      try {
        const {
          conversationId,
          fileName,
          mimeType,
          encryptedData,
          byteSize,
        } = JSON.parse(body);

        if (!conversationId || !fileName || !mimeType || !encryptedData) {
          return sendJSON(res, 400, { success: false, message: "Missing media upload fields" });
        }

        if (!ALLOWED_MEDIA_TYPES.has(mimeType)) {
          return sendJSON(res, 400, { success: false, message: "Unsupported image type" });
        }

        const access = await validateConversationAccess(authContext.internalUser.id, conversationId);
        if (!access.allowed) {
          return sendJSON(res, 403, { success: false, message: access.reason });
        }

        const encryptedBuffer = Buffer.from(encryptedData, "base64");
        const bufferSize = encryptedBuffer.byteLength;

        if (!bufferSize || Number.isNaN(bufferSize)) {
          return sendJSON(res, 400, { success: false, message: "Invalid encrypted image data" });
        }

        if (bufferSize > MAX_MEDIA_SIZE_BYTES) {
          return sendJSON(res, 413, { success: false, message: "Image exceeds size limit" });
        }

        const mediaId = uuidv4();
        const storagePath = `${conversationId}/${mediaId}.bin`;

        const { error: uploadError } = await supabase.storage
          .from(MEDIA_BUCKET)
          .upload(storagePath, encryptedBuffer, {
            upsert: false,
            contentType: "application/octet-stream",
          });

        if (uploadError) {
          console.error("Media upload failed:", uploadError);
          return sendJSON(res, 500, { success: false, message: "Failed to upload encrypted image" });
        }

        const { error: insertError } = await supabase
          .from("media_files")
          .insert({
            id: mediaId,
            conversation_id: conversationId,
            uploader_user_id: authContext.internalUser.id,
            storage_path: storagePath,
            byte_size: byteSize || bufferSize,
            created_at: getCurrentTimestamp(),
          });

        if (insertError) {
          console.error("Media metadata insert failed:", insertError);
          await supabase.storage.from(MEDIA_BUCKET).remove([storagePath]);
          return sendJSON(res, 500, { success: false, message: "Failed to save image metadata" });
        }

        sendJSON(res, 201, { success: true, mediaId });
      } catch (error) {
        console.error("Media upload parse/processing error:", error);
        sendJSON(res, 400, { success: false, message: "Invalid media upload request" });
      }
    });
    return;
  }

  if (req.method === "GET" && pathname === "/api/media/download-url") {
    const authContext = await requireAuthContext(req, res);
    if (!authContext) return;

    try {
      const mediaId = parsedUrl.searchParams.get("mediaId");
      if (!mediaId) {
        return sendJSON(res, 400, { success: false, message: "Missing mediaId" });
      }

      const { data: mediaFile, error: mediaError } = await supabase
        .from("media_files")
        .select("id, conversation_id, storage_path")
        .eq("id", mediaId)
        .single();

      if (mediaError || !mediaFile) {
        return sendJSON(res, 404, { success: false, message: "Image not found" });
      }

      const access = await validateConversationAccess(
        authContext.internalUser.id,
        mediaFile.conversation_id,
      );

      if (!access.allowed) {
        return sendJSON(res, 403, { success: false, message: "Not allowed to access this image" });
      }

      const { data: signedData, error: signedError } = await supabase.storage
        .from(MEDIA_BUCKET)
        .createSignedUrl(mediaFile.storage_path, 60);

      if (signedError || !signedData?.signedUrl) {
        console.error("Create signed download URL failed:", signedError);
        return sendJSON(res, 500, { success: false, message: "Failed to generate image URL" });
      }

      sendJSON(res, 200, { success: true, url: signedData.signedUrl });
    } catch (error) {
      console.error("Media download URL error:", error);
      sendJSON(res, 500, { success: false, message: "Failed to access encrypted image" });
    }
    return;
  }

  if (req.method === "GET" && pathname === "/api/users") {
    const authContext = await requireAuthContext(req, res);
    if (!authContext) return;

    const buddyIds = await getConfirmedBuddyIds(authContext.internalUser.id);
    if (buddyIds.length === 0) {
      sendJSON(res, 200, { success: true, users: [] });
      return;
    }

    const { data, error } = await supabase
      .from("users")
      .select("id, username, email, last_seen, public_key")
      .in("id", buddyIds)
      .order("username");

    if (error) {
      return sendJSON(res, 500, {
        success: false,
        message: error.message,
      });
    }

    const users = (data || []).map((u) => ({
      ...u,
      online: clients.has(u.id),
    }));

    sendJSON(res, 200, { success: true, users });
    return;
  }

  if (req.method === "GET" && pathname === "/api/users/search") {
    const authContext = await requireAuthContext(req, res);
    if (!authContext) return;

    const query = (parsedUrl.searchParams.get("username") || "").trim();
    if (!query) {
      return sendJSON(res, 200, { success: true, users: [] });
    }

    const excludedUserIds = await getExcludedSearchUserIds(authContext.internalUser.id);

    const { data, error } = await supabase
      .from("users")
      .select("id, username, email, last_seen")
      .ilike("username", `%${query}%`)
      .neq("id", authContext.internalUser.id)
      .order("username")
      .limit(20);

    if (error) {
      return sendJSON(res, 500, {
        success: false,
        message: error.message,
      });
    }

    const users = (data || [])
      .filter((candidate) => !excludedUserIds.has(candidate.id))
      .map((candidate) => ({
        ...candidate,
        online: clients.has(candidate.id),
      }));

    sendJSON(res, 200, { success: true, users });
    return;
  }

  if (req.method === "GET" && pathname === "/api/buddy-requests") {
    const authContext = await requireAuthContext(req, res);
    if (!authContext) return;

    const { data: requests, error: requestsError } = await supabase
      .from("buddy_requests")
      .select("id, requester_id, receiver_id, status, created_at")
      .eq("receiver_id", authContext.internalUser.id)
      .eq("status", BUDDY_REQUEST_STATUS.PENDING)
      .order("created_at", { ascending: false });

    if (requestsError) {
      return sendJSON(res, 500, {
        success: false,
        message: requestsError.message,
      });
    }

    const requesterIds = [...new Set((requests || []).map((request) => request.requester_id))];
    let usersById = new Map();

    if (requesterIds.length > 0) {
      const { data: requesterUsers, error: usersError } = await supabase
        .from("users")
        .select("id, username, email")
        .in("id", requesterIds);

      if (usersError) {
        return sendJSON(res, 500, {
          success: false,
          message: usersError.message,
        });
      }

      usersById = new Map((requesterUsers || []).map((requester) => [requester.id, requester]));
    }

    const incomingRequests = (requests || [])
      .map((request) => ({
        id: request.id,
        requester_id: request.requester_id,
        receiver_id: request.receiver_id,
        status: request.status,
        created_at: request.created_at,
        requester: usersById.get(request.requester_id) || null,
      }))
      .filter((request) => request.requester);

    sendJSON(res, 200, {
      success: true,
      incomingRequests,
    });
    return;
  }

  if (req.method === "POST" && pathname === "/api/buddy-requests") {
    const authContext = await requireAuthContext(req, res);
    if (!authContext) return;

    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });

    req.on("end", async () => {
      try {
        const { toUserId } = JSON.parse(body);

        if (!toUserId) {
          return sendJSON(res, 400, { success: false, message: "Missing toUserId" });
        }

        if (toUserId === authContext.internalUser.id) {
          return sendJSON(res, 400, { success: false, message: "Cannot add yourself as buddy" });
        }

        const { data: targetUser, error: targetUserError } = await supabase
          .from("users")
          .select("id, username")
          .eq("id", toUserId)
          .maybeSingle();

        if (targetUserError || !targetUser) {
          return sendJSON(res, 404, { success: false, message: "User not found" });
        }

        const { data: existing, error: existingError } = await supabase
          .from("buddy_requests")
          .select("id, status")
          .or(
            `and(requester_id.eq.${authContext.internalUser.id},receiver_id.eq.${toUserId}),and(requester_id.eq.${toUserId},receiver_id.eq.${authContext.internalUser.id})`,
          )
          .in("status", [BUDDY_REQUEST_STATUS.PENDING, BUDDY_REQUEST_STATUS.ACCEPTED])
          .limit(1);

        if (existingError) {
          return sendJSON(res, 500, { success: false, message: existingError.message });
        }

        if (existing && existing.length > 0) {
          return sendJSON(res, 409, {
            success: false,
            message: "Buddy request already exists or users are already buddies",
          });
        }

        const now = getCurrentTimestamp();
        const requestId = uuidv4();
        const insertPayload = {
          id: requestId,
          requester_id: authContext.internalUser.id,
          receiver_id: toUserId,
          status: BUDDY_REQUEST_STATUS.PENDING,
          created_at: now,
          updated_at: now,
        };

        const { error: insertError } = await supabase.from("buddy_requests").insert(insertPayload);
        if (insertError) {
          return sendJSON(res, 500, { success: false, message: insertError.message });
        }

        const targetClient = clients.get(toUserId);
        if (targetClient?.ws?.readyState === 1) {
          targetClient.ws.send(
            JSON.stringify({
              type: "buddy_request_incoming",
              request: {
                id: requestId,
                requester_id: authContext.internalUser.id,
                receiver_id: toUserId,
                status: BUDDY_REQUEST_STATUS.PENDING,
                created_at: now,
                requester: {
                  id: authContext.internalUser.id,
                  username: authContext.internalUser.username,
                  email: authContext.internalUser.email,
                },
              },
            }),
          );
        }

        sendJSON(res, 201, { success: true });
      } catch (error) {
        console.error("Buddy request create failed:", error);
        sendJSON(res, 400, { success: false, message: "Invalid request payload" });
      }
    });
    return;
  }

  if (req.method === "POST" && pathname === "/api/buddy-requests/respond") {
    const authContext = await requireAuthContext(req, res);
    if (!authContext) return;

    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });

    req.on("end", async () => {
      try {
        const { requestId, action } = JSON.parse(body);
        if (!requestId || !action) {
          return sendJSON(res, 400, { success: false, message: "Missing requestId or action" });
        }

        if (action !== "accept" && action !== "reject") {
          return sendJSON(res, 400, { success: false, message: "Invalid action" });
        }

        const { data: request, error: requestError } = await supabase
          .from("buddy_requests")
          .select("id, requester_id, receiver_id, status")
          .eq("id", requestId)
          .maybeSingle();

        if (requestError || !request) {
          return sendJSON(res, 404, { success: false, message: "Buddy request not found" });
        }

        if (request.receiver_id !== authContext.internalUser.id) {
          return sendJSON(res, 403, { success: false, message: "Not allowed to respond to this request" });
        }

        if (request.status !== BUDDY_REQUEST_STATUS.PENDING) {
          return sendJSON(res, 409, { success: false, message: "Buddy request already processed" });
        }

        const now = getCurrentTimestamp();
        const nextStatus = action === "accept" ? BUDDY_REQUEST_STATUS.ACCEPTED : BUDDY_REQUEST_STATUS.REJECTED;
        const { error: updateError } = await supabase
          .from("buddy_requests")
          .update({
            status: nextStatus,
            responded_at: now,
            updated_at: now,
          })
          .eq("id", request.id);

        if (updateError) {
          return sendJSON(res, 500, { success: false, message: updateError.message });
        }

        const requesterClient = clients.get(request.requester_id);
        if (requesterClient?.ws?.readyState === 1) {
          requesterClient.ws.send(
            JSON.stringify({
              type: "buddy_request_updated",
              requestId: request.id,
              status: nextStatus,
              fromUserId: authContext.internalUser.id,
            }),
          );
        }

        if (action === "accept") {
          await notifyBuddyStatus(authContext.internalUser.id, true);
          await notifyBuddyStatus(request.requester_id, Boolean(clients.has(request.requester_id)));
        }

        sendJSON(res, 200, { success: true, status: nextStatus });
      } catch (error) {
        console.error("Buddy request respond failed:", error);
        sendJSON(res, 400, { success: false, message: "Invalid request payload" });
      }
    });
    return;
  }

  if (req.method === "GET" && pathname === "/api/conversations") {
    const authContext = await requireAuthContext(req, res);
    if (!authContext) return;

    const otherUserId = parsedUrl.searchParams.get("userId");

    if (!otherUserId) {
      return sendJSON(res, 400, {
        success: false,
        message: "Missing userId parameter",
      });
    }

    if (otherUserId === authContext.internalUser.id) {
      return sendJSON(res, 400, {
        success: false,
        message: "Cannot create conversation with yourself",
      });
    }

    const canChat = await areUsersConfirmedBuddies(authContext.internalUser.id, otherUserId);
    if (!canChat) {
      return sendJSON(res, 403, {
        success: false,
        message: "You can only chat with confirmed buddies",
      });
    }

    const { data: sharedMemberships, error: searchError } = await supabase
      .from("conversation_members")
      .select("conversation_id, user_id")
      .in("user_id", [authContext.internalUser.id, otherUserId]);

    if (searchError) {
      return sendJSON(res, 500, {
        success: false,
        message: searchError.message,
      });
    }

    const membershipCountByConversation = new Map();
    for (const member of sharedMemberships || []) {
      if (!membershipCountByConversation.has(member.conversation_id)) {
        membershipCountByConversation.set(member.conversation_id, new Set());
      }
      membershipCountByConversation.get(member.conversation_id).add(member.user_id);
    }

    let conversationId = null;
    for (const [candidateConversationId, memberUserIds] of membershipCountByConversation.entries()) {
      if (
        memberUserIds.has(authContext.internalUser.id)
        && memberUserIds.has(otherUserId)
        && memberUserIds.size === 2
      ) {
        conversationId = candidateConversationId;
        break;
      }
    }

    if (conversationId) {
      return sendJSON(res, 200, {
        success: true,
        conversation: { id: conversationId },
      });
    }

    conversationId = uuidv4();
    const now = getCurrentTimestamp();

    const { error: insertConvError } = await supabase.from("conversations").insert({
      id: conversationId,
      created_at: now,
      updated_at: now,
    });

    if (insertConvError) {
      return sendJSON(res, 500, {
        success: false,
        message: insertConvError.message,
      });
    }

    const { error: insertMembersError } = await supabase.from("conversation_members").insert([
      {
        conversation_id: conversationId,
        user_id: authContext.internalUser.id,
        joined_at: now,
      },
      {
        conversation_id: conversationId,
        user_id: otherUserId,
        joined_at: now,
      },
    ]);

    if (insertMembersError) {
      return sendJSON(res, 500, {
        success: false,
        message: insertMembersError.message,
      });
    }

    sendJSON(res, 201, { success: true, conversation: { id: conversationId } });
    return;
  }

  if (req.method === "GET" && pathname === "/api/messages") {
    const authContext = await requireAuthContext(req, res);
    if (!authContext) return;

    const conversationId = parsedUrl.searchParams.get("conversationId");
    if (!conversationId) {
      return sendJSON(res, 400, { success: false, message: "Missing conversationId" });
    }

    const access = await validateConversationAccess(authContext.internalUser.id, conversationId);
    if (!access.allowed) {
      return sendJSON(res, 403, { success: false, message: access.reason });
    }

    const { data, error } = await supabase
      .from("messages")
      .select(
        `
          id,
          conversation_id,
          from_user_id,
          encrypted_message,
          created_at,
          users(username)
        `,
      )
      .eq("conversation_id", conversationId)
      .order("created_at");

    if (error) {
      return sendJSON(res, 500, { success: false, message: error.message });
    }

    sendJSON(res, 200, { success: true, messages: data || [] });
    return;
  }

  sendJSON(res, 404, { success: false, message: "Not found" });
});

function sendJSON(res, statusCode, obj) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
  });
  res.end(JSON.stringify(obj));
}

function getCurrentTimestamp() {
  return Math.floor(Date.now() / 1000);
}

async function isUserConversationMember(userId, conversationId) {
  const { data, error } = await supabase
    .from("conversation_members")
    .select("conversation_id")
    .eq("conversation_id", conversationId)
    .eq("user_id", userId)
    .maybeSingle();

  if (error && !isNoRowsError(error)) {
    console.error("Failed to verify conversation membership:", error);
    return false;
  }

  return Boolean(data);
}

async function getConversationParticipants(conversationId) {
  const { data, error } = await supabase
    .from("conversation_members")
    .select("user_id")
    .eq("conversation_id", conversationId);

  if (error) {
    console.error("Failed to load conversation participants:", error);
    return [];
  }

  return (data || []).map((member) => member.user_id);
}

async function areUsersConfirmedBuddies(userAId, userBId) {
  if (!userAId || !userBId || userAId === userBId) return false;

  const { data, error } = await supabase
    .from("buddy_requests")
    .select("id")
    .or(
      `and(requester_id.eq.${userAId},receiver_id.eq.${userBId}),and(requester_id.eq.${userBId},receiver_id.eq.${userAId})`,
    )
    .eq("status", BUDDY_REQUEST_STATUS.ACCEPTED)
    .limit(1);

  if (error) {
    console.error("Failed to validate buddy relation:", error);
    return false;
  }

  return Boolean(data && data.length > 0);
}

async function getConfirmedBuddyIds(userId) {
  const { data, error } = await supabase
    .from("buddy_requests")
    .select("requester_id, receiver_id")
    .or(`requester_id.eq.${userId},receiver_id.eq.${userId}`)
    .eq("status", BUDDY_REQUEST_STATUS.ACCEPTED);

  if (error) {
    console.error("Failed to load confirmed buddies:", error);
    return [];
  }

  const buddyIds = new Set();
  for (const row of data || []) {
    if (row.requester_id === userId) {
      buddyIds.add(row.receiver_id);
    } else if (row.receiver_id === userId) {
      buddyIds.add(row.requester_id);
    }
  }

  return [...buddyIds];
}

async function getExcludedSearchUserIds(userId) {
  const excluded = new Set([userId]);

  const { data, error } = await supabase
    .from("buddy_requests")
    .select("requester_id, receiver_id, status")
    .or(`requester_id.eq.${userId},receiver_id.eq.${userId}`)
    .in("status", [BUDDY_REQUEST_STATUS.PENDING, BUDDY_REQUEST_STATUS.ACCEPTED]);

  if (error) {
    console.error("Failed to compute search exclusions:", error);
    return excluded;
  }

  for (const row of data || []) {
    if (row.requester_id === userId) {
      excluded.add(row.receiver_id);
    } else if (row.receiver_id === userId) {
      excluded.add(row.requester_id);
    }
  }

  return excluded;
}

async function validateConversationAccess(userId, conversationId) {
  const isMember = await isUserConversationMember(userId, conversationId);
  if (!isMember) {
    return { allowed: false, reason: "Not a member of this conversation" };
  }

  const participants = await getConversationParticipants(conversationId);
  if (participants.length !== 2) {
    return { allowed: false, reason: "Invalid direct conversation" };
  }

  const otherUserId = participants.find((participantId) => participantId !== userId);
  if (!otherUserId) {
    return { allowed: false, reason: "Invalid conversation membership" };
  }

  const areBuddies = await areUsersConfirmedBuddies(userId, otherUserId);
  if (!areBuddies) {
    return { allowed: false, reason: "Conversation is not between confirmed buddies" };
  }

  return { allowed: true, otherUserId };
}

async function notifyBuddyStatus(userId, online) {
  const buddyIds = await getConfirmedBuddyIds(userId);
  for (const buddyId of buddyIds) {
    const buddyClient = clients.get(buddyId);
    if (buddyClient?.ws?.readyState === 1) {
      buddyClient.ws.send(
        JSON.stringify({
          type: "user_status",
          userId,
          online,
        }),
      );
    }
  }
}

function isNoRowsError(error) {
  return error?.code === "PGRST116";
}

function formatUserForClient(user) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    avatar_url: user.avatar_url || null,
  };
}

async function requireAuthContext(req, res) {
  try {
    const firebaseUser = await authenticateRequest(req);
    const internalUser = await getOrCreateInternalUser(firebaseUser);
    req.user = internalUser;
    return { firebaseUser, internalUser };
  } catch (error) {
    const statusCode = error.statusCode || 500;
    const message = error.message || "Authentication failed";
    sendJSON(res, statusCode, { success: false, message });
    return null;
  }
}

function sanitizeUsername(rawValue) {
  const normalized = (rawValue || "user")
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, "")
    .slice(0, 24);

  if (!normalized) return "user";
  if (normalized.length < 3) return `${normalized}user`.slice(0, 24);
  return normalized;
}

async function isUsernameTaken(username) {
  const { data, error } = await supabase
    .from("users")
    .select("id")
    .eq("username", username)
    .maybeSingle();

  if (error && !isNoRowsError(error)) {
    throw new Error(`Failed to validate username: ${error.message}`);
  }

  return Boolean(data);
}

async function generateUniqueUsername(rawValue) {
  const base = sanitizeUsername(rawValue);
  let candidate = base;
  let suffix = 0;

  while (await isUsernameTaken(candidate)) {
    suffix += 1;
    const suffixText = String(suffix);
    const maxBaseLength = Math.max(3, 24 - suffixText.length);
    candidate = `${base.slice(0, maxBaseLength)}${suffixText}`;
  }

  return candidate;
}

function buildMissingColumnError(columnName) {
  const error = new Error(
    `Database column '${columnName}' is missing. Run the Firebase auth migration SQL before using this build.`,
  );
  error.statusCode = 500;
  return error;
}

async function getOrCreateInternalUser(decodedToken) {
  const firebaseUid = decodedToken.uid;
  const firebaseEmail = decodedToken.email || null;
  const firebaseName = decodedToken.name || null;
  const firebasePicture = decodedToken.picture || null;
  const now = getCurrentTimestamp();

  const { data: byFirebaseUid, error: byFirebaseUidError } = await supabase
    .from("users")
    .select("*")
    .eq("firebase_uid", firebaseUid)
    .maybeSingle();

  if (byFirebaseUidError && !isNoRowsError(byFirebaseUidError)) {
    if (byFirebaseUidError.message?.includes("firebase_uid")) {
      throw buildMissingColumnError("firebase_uid");
    }
    throw new Error(byFirebaseUidError.message);
  }

  if (byFirebaseUid) {
    const updates = {
      last_seen: now,
      updated_at: now,
      auth_provider: "firebase",
      avatar_url: firebasePicture || byFirebaseUid.avatar_url || null,
      email: byFirebaseUid.email || firebaseEmail,
    };

    const { error } = await supabase.from("users").update(updates).eq("id", byFirebaseUid.id);
    if (error) {
      if (error.message?.includes("auth_provider")) throw buildMissingColumnError("auth_provider");
      if (error.message?.includes("avatar_url")) throw buildMissingColumnError("avatar_url");
      throw new Error(error.message);
    }

    return {
      ...byFirebaseUid,
      ...updates,
    };
  }

  if (firebaseEmail) {
    const { data: byEmail, error: byEmailError } = await supabase
      .from("users")
      .select("*")
      .eq("email", firebaseEmail)
      .maybeSingle();

    if (byEmailError && !isNoRowsError(byEmailError)) {
      throw new Error(byEmailError.message);
    }

    if (byEmail) {
      const updates = {
        firebase_uid: firebaseUid,
        auth_provider: "firebase",
        avatar_url: firebasePicture || byEmail.avatar_url || null,
        last_seen: now,
        updated_at: now,
      };

      const { error } = await supabase.from("users").update(updates).eq("id", byEmail.id);
      if (error) {
        if (error.message?.includes("firebase_uid")) throw buildMissingColumnError("firebase_uid");
        if (error.message?.includes("auth_provider")) throw buildMissingColumnError("auth_provider");
        if (error.message?.includes("avatar_url")) throw buildMissingColumnError("avatar_url");
        throw new Error(error.message);
      }

      return {
        ...byEmail,
        ...updates,
      };
    }
  }

  const usernameSeed = firebaseName || firebaseEmail?.split("@")[0] || `user_${firebaseUid.slice(0, 8)}`;
  const username = await generateUniqueUsername(usernameSeed);
  const passwordPlaceholderHash = await bcrypt.hash(uuidv4(), 12);

  const { data: newUser, error: insertError } = await supabase
    .from("users")
    .insert({
      id: uuidv4(),
      username,
      email: firebaseEmail || `${firebaseUid}@firebase.local`,
      password: passwordPlaceholderHash,
      firebase_uid: firebaseUid,
      auth_provider: "firebase",
      avatar_url: firebasePicture,
      created_at: now,
      updated_at: now,
      last_seen: now,
    })
    .select("*")
    .single();

  if (insertError) {
    if (insertError.message?.includes("firebase_uid")) throw buildMissingColumnError("firebase_uid");
    if (insertError.message?.includes("auth_provider")) throw buildMissingColumnError("auth_provider");
    if (insertError.message?.includes("avatar_url")) throw buildMissingColumnError("avatar_url");
    throw new Error(insertError.message);
  }

  return newUser;
}

async function getUnreadCount(userId, conversationId) {
  const { count, error } = await supabase
    .from("messages")
    .select("*", { count: "exact", head: true })
    .eq("conversation_id", conversationId)
    .neq("from_user_id", userId)
    .neq("status", "seen");

  if (error) {
    console.error("Error getting unread count:", error);
    return 0;
  }
  return count || 0;
}

const wss = new WebSocketServer({ server });

wss.on("connection", (ws) => {
  let userId;
  let username;

  ws.on("message", async (msg) => {
    let data;
    try {
      data = JSON.parse(msg);
    } catch {
      ws.send(JSON.stringify({ type: "error", message: "Invalid websocket payload" }));
      return;
    }

    if (data.type === "connect") {
      try {
        const firebaseUser = await verifyFirebaseToken(data.token);
        const internalUser = await getOrCreateInternalUser(firebaseUser);

        userId = internalUser.id;
        username = internalUser.username;

        clients.set(userId, { ws, username });

        ws.send(
          JSON.stringify({
            type: "connected",
            userId,
          }),
        );

        await notifyBuddyStatus(userId, true);
      } catch {
        ws.close();
      }

      return;
    }

    if (!userId || !username) {
      ws.send(JSON.stringify({ type: "error", message: "Unauthorized websocket client" }));
      return;
    }

    if (data.type === "message") {
      try {
        if (!data?.conversationId || !data?.toUserId || !data?.encryptedMessage) {
          ws.send(JSON.stringify({ type: "error", message: "Invalid message payload" }));
          return;
        }

        const isBuddy = await areUsersConfirmedBuddies(userId, data.toUserId);
        if (!isBuddy) {
          ws.send(JSON.stringify({ type: "error", message: "Messaging is only allowed between buddies" }));
          return;
        }

        const participants = await getConversationParticipants(data.conversationId);
        const isValidConversation =
          participants.length === 2
          && participants.includes(userId)
          && participants.includes(data.toUserId);

        if (!isValidConversation) {
          ws.send(JSON.stringify({ type: "error", message: "Invalid conversation for this buddy" }));
          return;
        }

        const messageId = uuidv4();
        const now = getCurrentTimestamp();

        const { error } = await supabase.from("messages").insert({
          id: messageId,
          conversation_id: data.conversationId,
          from_user_id: userId,
          encrypted_message: JSON.stringify(data.encryptedMessage),
          created_at: now,
          status: "sent",
        });

        if (error) {
          console.error("Error saving message:", error);
          return;
        }

        let messageStatus = "sent";
        let deliveredAt = null;

        if (clients.has(data.toUserId)) {
          deliveredAt = getCurrentTimestamp();
          messageStatus = "delivered";

          const { error: updateError } = await supabase
            .from("messages")
            .update({
              status: "delivered",
              delivered_at: deliveredAt,
            })
            .eq("id", messageId);

          if (updateError) {
            console.error("Error updating message status:", updateError);
          }
        }

        const messageToSend = {
          type: "message",
          id: messageId,
          conversationId: data.conversationId,
          fromUserId: userId,
          fromUsername: username,
          encryptedMessage: data.encryptedMessage,
          createdAt: now,
          status: messageStatus,
        };

        if (clients.has(data.toUserId)) {
          clients.get(data.toUserId).ws.send(JSON.stringify(messageToSend));

          ws.send(
            JSON.stringify({
              type: "message_delivered",
              messageId,
              conversationId: data.conversationId,
              deliveredAt,
            }),
          );

          const unreadCount = await getUnreadCount(data.toUserId, data.conversationId);
          clients.get(data.toUserId).ws.send(
            JSON.stringify({
              type: "unread_count_update",
              conversationId: data.conversationId,
              fromUserId: userId,
              count: unreadCount,
            }),
          );
        } else {
          ws.send(JSON.stringify(messageToSend));
        }
      } catch (error) {
        console.error("Error handling websocket message event:", error);
        ws.send(JSON.stringify({ type: "error", message: "Failed to send message" }));
      }
    }

    if (data.type === "message_seen") {
      try {
        const conversationId = data.conversationId;
        const messageIds = data.messageIds || [];
        const now = getCurrentTimestamp();

        if (!conversationId) {
          ws.send(JSON.stringify({ type: "error", message: "Missing conversationId" }));
          return;
        }

        const access = await validateConversationAccess(userId, conversationId);
        if (!access.allowed) {
          ws.send(JSON.stringify({ type: "error", message: access.reason }));
          return;
        }

        if (messageIds.length === 0) {
          const { error: updateError } = await supabase
            .from("messages")
            .update({
              status: "seen",
              seen_at: now,
            })
            .eq("conversation_id", conversationId)
            .neq("from_user_id", userId)
            .neq("status", "seen");

          if (updateError) {
            console.error("Error updating message seen status:", updateError);
            return;
          }
        } else {
          const { error: updateError } = await supabase
            .from("messages")
            .update({
              status: "seen",
              seen_at: now,
            })
            .in("id", messageIds)
            .neq("from_user_id", userId);

          if (updateError) {
            console.error("Error updating message seen status:", updateError);
            return;
          }
        }

        const recipients = [userId];
        if (access.otherUserId) {
          recipients.push(access.otherUserId);
        }

        recipients.forEach((recipientId) => {
          const recipientClient = clients.get(recipientId);
          if (recipientClient?.ws?.readyState === 1) {
            recipientClient.ws.send(
              JSON.stringify({
                type: "message_seen",
                conversationId,
                userId,
                seenAt: now,
                messageIds,
              }),
            );
          }
        });
      } catch (error) {
        console.error("Error handling websocket seen event:", error);
        ws.send(JSON.stringify({ type: "error", message: "Failed to mark message as seen" }));
      }
    }
  });

  ws.on("close", () => {
    clients.delete(userId);

    if (userId) {
      notifyBuddyStatus(userId, false).catch((error) => {
        console.error("Failed to notify buddy status:", error);
      });
    }
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
