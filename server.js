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
const JWT_EXPIRY = "7d";

const clients = new Map();

// HTTP SERVER
const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin;

  res.setHeader("Access-Control-Allow-Origin", origin || "*");
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
  const parsedUrl = new url.URL(req.url, `${protocol}://${req.headers.host}`);
  const pathname = parsedUrl.pathname;

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

        const token = generateToken(userId, username);

        sendJSON(res, 201, {
          success: true,
          token,
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
      const { username, password } = JSON.parse(body);

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

      const token = generateToken(user.id, user.username);

      sendJSON(res, 200, {
        success: true,
        token,
        user,
      });
    });

    return;
  }

  // GET USERS
  if (req.method === "GET" && pathname === "/api/users") {
    const token = req.headers.authorization?.split(" ")[1];
    const decoded = verifyToken(token);

    if (!decoded) return sendJSON(res, 401, { success: false });

    const { data, error } = await supabase
      .from("users")
      .select("id, username, email, last_seen")
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
                message,
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

  // STATIC
  if (req.method === "GET") {
    try {
      const filePath = "./public" + (req.url === "/" ? "/index.html" : req.url);

      const data = fs.readFileSync(filePath);

      res.writeHead(200);
      res.end(data);
    } catch {
      sendJSON(res, 404, { success: false });
    }

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

// JWT
function generateToken(userId, username) {
    return jwt.sign({ userId, username }, JWT_SECRET, {
        expiresIn: JWT_EXPIRY
    });
}

function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch {
        return null;
    }
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

            const { error } = await supabase
                .from("messages")
                .insert({
                    id: messageId,
                    conversation_id: data.conversationId,
                    from_user_id: userId,
                    message: data.message,
                    created_at: now
                });

            if (error) {
                console.error("Error saving message:", error);
                return;
            }

            // Prepare message object to broadcast
            const messageToSend = {
                type: "message",
                id: messageId,
                conversationId: data.conversationId,
                fromUserId: userId,
                fromUsername: username,
                message: data.message,
                createdAt: now
            };

            // Send to recipient if they're online
            if (clients.has(data.toUserId)) {
                clients.get(data.toUserId).ws.send(JSON.stringify(messageToSend));
            }

            // Send confirmation back to sender
            ws.send(JSON.stringify(messageToSend));

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

server.listen(PORT, () => {

    console.log(`Server running on http://localhost:${PORT}`);

});