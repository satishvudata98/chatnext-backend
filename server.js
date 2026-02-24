import dotenv from "dotenv";
dotenv.config();
import http from "node:http";
import fs from "node:fs";
import { WebSocketServer } from "ws";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import url from "node:url";
import supabase from "./supabaseClient.js";

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET || JWT_SECRET; // Use different secret if available
const ACCESS_EXPIRY = "15m"; // Short-lived access token
const REFRESH_EXPIRY = "7d"; // Long-lived refresh token

const clients = new Map();


process.on("uncaughtException", err => {
  console.error("UNCAUGHT EXCEPTION:", err);
});

process.on("unhandledRejection", err => {
  console.error("UNHANDLED REJECTION:", err);
});

// HTTP SERVER
const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin;

  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }

  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, OPTIONS",
  );
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

  // Healthcheck route (required for Railway)
  if (req.method === "GET" && pathname === "/") {
    return sendJSON(res, 200, {
      success: true,
      message: "ChatNext backend running",
    });
  }

  // REGISTER
  if (req.method === "POST" && pathname === "/api/auth/register") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));

    req.on("end", async () => {
      try {
        const { username, email, password } = JSON.parse(body);

        if (!username || !email || !password)
          return sendJSON(res, 400, {
            success: false,
            message: "Missing fields",
          });

        const hash = await bcrypt.hash(password, 12);
        const now = getCurrentTimestamp();
        const userId = uuidv4();

        const { error } = await supabase.from("users").insert({
          id: userId,
          username,
          email,
          password: hash,
          created_at: now,
          updated_at: now,
        });

        if (error)
          return sendJSON(res, 400, { success: false, message: error.message });

        const accessToken = generateAccessToken(userId, username);
        const refreshToken = generateRefreshToken(userId);

        // Store refresh token in database
        const refreshExpiry = Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60; // 7 days
        const { error: refreshError } = await supabase.from("refresh_tokens").insert({
          user_id: userId,
          token: refreshToken,
          expires_at: refreshExpiry,
          created_at: now,
        });

        if (refreshError) {
          console.error("Error storing refresh token:", refreshError);
          // Continue anyway, as access token is still valid
        }

        sendJSON(res, 201, {
          success: true,
          accessToken,
          refreshToken,
          user: { id: userId, username, email },
        });
      } catch (err) {
        sendJSON(res, 500, { success: false, message: err.message });
      }
    });

    return;
  }

  // LOGIN
  if (req.method === "POST" && pathname === "/api/auth/login") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));

    req.on("end", async () => {
      let data;
      try {
        data = JSON.parse(body);
      } catch {
        return sendJSON(res, 400, { success: false, message: "Invalid JSON" });
      }

      const { username, password } = data;

      const { data: user, error } = await supabase
        .from("users")
        .select("*")
        .eq("username", username)
        .single();

      if (error || !user)
        return sendJSON(res, 401, {
          success: false,
          message: "Invalid credentials",
        });

      const valid = await bcrypt.compare(password, user.password);

      if (!valid) return sendJSON(res, 401, { success: false });

      await supabase
        .from("users")
        .update({ last_seen: getCurrentTimestamp() })
        .eq("id", user.id);

      const accessToken = generateAccessToken(user.id, user.username);
      const refreshToken = generateRefreshToken(user.id);

      // Delete old refresh tokens for this user
      await supabase.from("refresh_tokens").delete().eq("user_id", user.id);

      // Store new refresh token
      const refreshExpiry = Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60;
      const { error: refreshError } = await supabase.from("refresh_tokens").insert({
        user_id: user.id,
        token: refreshToken,
        expires_at: refreshExpiry,
        created_at: getCurrentTimestamp(),
      });

      if (refreshError) {
        console.error("Error storing refresh token:", refreshError);
      }

      sendJSON(res, 200, {
        success: true,
        accessToken,
        refreshToken,
        user,
      });
    });

    return;
  }

  // REFRESH TOKEN
  if (req.method === "POST" && pathname === "/api/auth/refresh") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));

    req.on("end", async () => {
      try {
        const { refreshToken } = JSON.parse(body);

        if (!refreshToken) {
          return sendJSON(res, 400, { success: false, message: "Refresh token required" });
        }

        const decoded = verifyRefreshToken(refreshToken);
        if (!decoded) {
          return sendJSON(res, 401, { success: false, message: "Invalid refresh token" });
        }

        // Check if refresh token exists in DB and not expired
        const { data: tokenData, error } = await supabase
          .from("refresh_tokens")
          .select("*")
          .eq("token", refreshToken)
          .eq("user_id", decoded.userId)
          .single();

        if (error || !tokenData || tokenData.expires_at < getCurrentTimestamp()) {
          return sendJSON(res, 401, { success: false, message: "Refresh token expired or invalid" });
        }

        // Get user data
        const { data: user, error: userError } = await supabase
          .from("users")
          .select("id, username, email")
          .eq("id", decoded.userId)
          .single();

        if (userError || !user) {
          return sendJSON(res, 401, { success: false, message: "User not found" });
        }

        // Generate new tokens
        const newAccessToken = generateAccessToken(user.id, user.username);
        const newRefreshToken = generateRefreshToken(user.id);

        // Delete old refresh token and store new one
        await supabase.from("refresh_tokens").delete().eq("token", refreshToken);
        const refreshExpiry = Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60;
        await supabase.from("refresh_tokens").insert({
          user_id: user.id,
          token: newRefreshToken,
          expires_at: refreshExpiry,
          created_at: getCurrentTimestamp(),
        });

        sendJSON(res, 200, {
          success: true,
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
        });
      } catch (err) {
        sendJSON(res, 500, { success: false, message: err.message });
      }
    });

    return;
  }

  // VERIFY TOKEN
  if (req.method === "GET" && pathname === "/api/auth/verify") {
    const token = req.headers.authorization?.split(" ")[1];
    const decoded = verifyAccessToken(token);

    if (!decoded) {
      return sendJSON(res, 401, { success: false, message: "Invalid token" });
    }

    // Get user data
    const { data: user, error } = await supabase
      .from("users")
      .select("id, username, email")
      .eq("id", decoded.userId)
      .single();

    if (error || !user) {
      return sendJSON(res, 401, { success: false, message: "User not found" });
    }

    sendJSON(res, 200, { success: true, user });
    return;
  }

  // UPDATE PUBLIC KEY
  if (req.method === "POST" && pathname === "/api/user/public-key") {
    const token = req.headers.authorization?.split(" ")[1];
    const decoded = verifyAccessToken(token);

    if (!decoded) return sendJSON(res, 401, { success: false });

    let body = "";
    req.on("data", (chunk) => (body += chunk));

    req.on("end", async () => {
      try {
        const { publicKey } = JSON.parse(body);

        const { error } = await supabase
          .from("users")
          .update({ public_key: publicKey })
          .eq("id", decoded.userId);

        if (error) return sendJSON(res, 500, { success: false, message: error.message });

        sendJSON(res, 200, { success: true });
      } catch (err) {
        sendJSON(res, 500, { success: false, message: err.message });
      }
    });

    return;
  }

  // GET USER PUBLIC KEY
  if (req.method === "GET" && pathname === "/api/user/public-key") {
    const token = req.headers.authorization?.split(" ")[1];
    const decoded = verifyAccessToken(token);

    if (!decoded) return sendJSON(res, 401, { success: false });

    const userId = parsedUrl.searchParams.get("userId");

    const { data: user, error } = await supabase
      .from("users")
      .select("public_key")
      .eq("id", userId)
      .single();

    if (error || !user) return sendJSON(res, 404, { success: false, message: "User not found" });

    sendJSON(res, 200, { success: true, publicKey: user.public_key });
    return;
  }

  // GET USERS
  if (req.method === "GET" && pathname === "/api/users") {
    const token = req.headers.authorization?.split(" ")[1];
    const decoded = verifyToken(token);

    if (!decoded) return sendJSON(res, 401, { success: false });

    const { data, error } = await supabase
      .from("users")
      .select("id, username, email, last_seen, public_key")
      .neq("id", decoded.userId)
      .order("username");

    if (error) return sendJSON(res, 500, error);

    const users = data.map((u) => ({
      ...u,
      online: clients.has(u.id),
    }));

    sendJSON(res, 200, { success: true, users });

    return;
  }

  // GET OR CREATE CONVERSATION
  if (req.method === "GET" && pathname === "/api/conversations") {
    const token = req.headers.authorization?.split(" ")[1];
    const decoded = verifyToken(token);

    if (!decoded) return sendJSON(res, 401, { success: false });

    const otherUserId = parsedUrl.searchParams.get("userId");

    if (!otherUserId)
      return sendJSON(res, 400, {
        success: false,
        message: "Missing userId parameter",
      });

    // Check if conversation exists between these two users using conversation_members
    const { data: existingConversations, error: searchError } = await supabase
      .from("conversation_members")
      .select("conversation_id")
      .eq("user_id", decoded.userId);

    if (searchError)
      return sendJSON(res, 500, {
        success: false,
        message: searchError.message,
      });

    // Check which of those conversations contains the other user
    let conversationId = null;

    if (existingConversations && existingConversations.length > 0) {
      for (const conv of existingConversations) {
        const { data: memberCheck } = await supabase
          .from("conversation_members")
          .select("conversation_id")
          .eq("conversation_id", conv.conversation_id)
          .eq("user_id", otherUserId)
          .single();

        if (memberCheck) {
          conversationId = conv.conversation_id;
          break;
        }
      }
    }

    // If conversation exists, return it
    if (conversationId) {
      return sendJSON(res, 200, {
        success: true,
        conversation: { id: conversationId },
      });
    }

    // Create new conversation
    conversationId = uuidv4();
    const now = getCurrentTimestamp();

    const { error: insertConvError } = await supabase
      .from("conversations")
      .insert({
        id: conversationId,
        created_at: now,
        updated_at: now,
      });

    if (insertConvError)
      return sendJSON(res, 500, {
        success: false,
        message: insertConvError.message,
      });

    // Add both users to conversation_members
    const { error: insertMembersError } = await supabase
      .from("conversation_members")
      .insert([
        {
          conversation_id: conversationId,
          user_id: decoded.userId,
          joined_at: now,
        },
        {
          conversation_id: conversationId,
          user_id: otherUserId,
          joined_at: now,
        },
      ]);

    if (insertMembersError)
      return sendJSON(res, 500, {
        success: false,
        message: insertMembersError.message,
      });

    sendJSON(res, 201, { success: true, conversation: { id: conversationId } });

    return;
  }

  // GET MESSAGES
  if (req.method === "GET" && pathname === "/api/messages") {
    const token = req.headers.authorization?.split(" ")[1];
    const decoded = verifyToken(token);

    if (!decoded) return sendJSON(res, 401, { success: false });

    const conversationId = parsedUrl.searchParams.get("conversationId");

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

    if (error) return sendJSON(res, 500, error);

    sendJSON(res, 200, { success: true, messages: data });

    return;
  }
});

// Utility functions
function sendJSON(res, statusCode, obj) {

  res.writeHead(statusCode, {
    "Content-Type": "application/json"
  });

  res.end(JSON.stringify(obj));
}

function getCurrentTimestamp() {
    return Math.floor(Date.now() / 1000);
}

// Get unread count for a user in a conversation (where they are the receiver and message is not seen)
async function getUnreadCount(userId, conversationId) {
    // Query messages where 'from_user_id' is NOT the userId (they are the receiver)
    // and status is not 'seen'
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

// JWT
function generateAccessToken(userId, username) {
    return jwt.sign({ userId, username, type: 'access' }, JWT_SECRET, {
        expiresIn: ACCESS_EXPIRY
    });
}

function generateRefreshToken(userId) {
    return jwt.sign({ userId, type: 'refresh', jti: uuidv4() }, REFRESH_SECRET, {
        expiresIn: REFRESH_EXPIRY
    });
}

function verifyAccessToken(token) {
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.type !== 'access') return null;
        return decoded;
    } catch {
        return null;
    }
}

function verifyRefreshToken(token) {
    try {
        const decoded = jwt.verify(token, REFRESH_SECRET);
        if (decoded.type !== 'refresh') return null;
        return decoded;
    } catch {
        return null;
    }
}

// For backward compatibility, keep generateToken as access token
function generateToken(userId, username) {
    return generateAccessToken(userId, username);
}

function verifyToken(token) {
    return verifyAccessToken(token);
}


// WEBSOCKET
const wss = new WebSocketServer({ server });

wss.on("connection", ws => {

    let userId;
    let username;

    ws.on("message", async msg => {

        const data = JSON.parse(msg);

        if (data.type === "connect") {

            const decoded = verifyToken(data.token);

            if (!decoded) return ws.close();

            userId = decoded.userId;
            username = decoded.username;

            clients.set(userId, { ws, username });

            ws.send(JSON.stringify({
                type: "connected",
                userId
            }));

            // Broadcast to all other clients that this user is now online
            wss.clients.forEach(client => {
                if (client.readyState === 1) { // 1 = OPEN
                    client.send(JSON.stringify({
                        type: "user_status",
                        userId: userId,
                        online: true
                    }));
                }
            });

            return;
        }

        if (data.type === "message") {

            const messageId = uuidv4();
            const now = getCurrentTimestamp();

            // Insert message with encrypted content
            const { error } = await supabase
                .from("messages")
                .insert({
                    id: messageId,
                    conversation_id: data.conversationId,
                    from_user_id: userId,
                    encrypted_message: JSON.stringify(data.encryptedMessage), // Store encrypted data as JSON
                    created_at: now,
                    status: "sent"
                });

            if (error) {
                console.error("Error saving message:", error);
                return;
            }

            let messageStatus = "sent";
            let deliveredAt = null;

            // Check if recipient is online
            if (clients.has(data.toUserId)) {
                // Recipient is online, immediately mark as delivered
                deliveredAt = getCurrentTimestamp();
                messageStatus = "delivered";

                // Update message status in database
                const { error: updateError } = await supabase
                    .from("messages")
                    .update({
                        status: "delivered",
                        delivered_at: deliveredAt
                    })
                    .eq("id", messageId);

                if (updateError) {
                    console.error("Error updating message status:", updateError);
                }
            }

            // Prepare message object to broadcast
            const messageToSend = {
                type: "message",
                id: messageId,
                conversationId: data.conversationId,
                fromUserId: userId,
                fromUsername: username,
                encryptedMessage: data.encryptedMessage, // Send encrypted data
                createdAt: now,
                status: messageStatus
            };

            // Send to recipient if they're online
            if (clients.has(data.toUserId)) {
                clients.get(data.toUserId).ws.send(JSON.stringify(messageToSend));

                // Send delivery confirmation to sender
                ws.send(JSON.stringify({
                    type: "message_delivered",
                    messageId: messageId,
                    conversationId: data.conversationId,
                    deliveredAt: deliveredAt
                }));

                // Send unread count update to recipient
                const unreadCount = await getUnreadCount(data.toUserId, data.conversationId);
                clients.get(data.toUserId).ws.send(JSON.stringify({
                    type: "unread_count_update",
                    conversationId: data.conversationId,
                    fromUserId: userId,
                    count: unreadCount
                }));
            } else {
                // Recipient is offline, just send confirmation back to sender
                ws.send(JSON.stringify(messageToSend));
            }

        }

        if (data.type === "message_seen") {
            // Handle message seen event - batch update all messages as seen
            const conversationId = data.conversationId;
            const messageIds = data.messageIds || [];
            const now = getCurrentTimestamp();

            if (messageIds.length === 0) {
                // No specific messages, update all unseen messages in this conversation
                const { error: updateError } = await supabase
                    .from("messages")
                    .update({
                        status: "seen",
                        seen_at: now
                    })
                    .eq("conversation_id", conversationId)
                    .neq("from_user_id", userId)
                    .neq("status", "seen");

                if (updateError) {
                    console.error("Error updating message seen status:", updateError);
                    return;
                }
            } else {
                // Update specific messages
                const { error: updateError } = await supabase
                    .from("messages")
                    .update({
                        status: "seen",
                        seen_at: now
                    })
                    .in("id", messageIds)
                    .neq("from_user_id", userId);

                if (updateError) {
                    console.error("Error updating message seen status:", updateError);
                    return;
                }
            }

            // Notify all connected clients about seen status for this conversation
            wss.clients.forEach(client => {
                if (client.readyState === 1) { // 1 = OPEN
                    client.send(JSON.stringify({
                        type: "message_seen",
                        conversationId: conversationId,
                        userId: userId,
                        seenAt: now,
                        messageIds: messageIds
                    }));
                }
            });
        }

    });

    ws.on("close", () => {

        clients.delete(userId);

        // Broadcast to all clients that this user is now offline
        if (userId) {
            wss.clients.forEach(client => {
                if (client.readyState === 1) { // 1 = OPEN
                    client.send(JSON.stringify({
                        type: "user_status",
                        userId: userId,
                        online: false
                    }));
                }
            });
        }

    });

});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});