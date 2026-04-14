-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. users
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    firebase_uid TEXT UNIQUE,
    auth_provider TEXT,
    avatar_url TEXT,
    email TEXT UNIQUE,
    username TEXT UNIQUE,
    password TEXT,
    public_key TEXT,
    encrypted_private_key TEXT,
    private_key_salt TEXT,
    private_key_iv TEXT,
    conversation_keys TEXT,
    created_at BIGINT,
    updated_at BIGINT,
    last_seen BIGINT
);

-- 2. buddy_requests
CREATE TABLE IF NOT EXISTS buddy_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    requester_id UUID REFERENCES users(id) ON DELETE CASCADE,
    receiver_id UUID REFERENCES users(id) ON DELETE CASCADE,
    status TEXT CHECK (status IN ('PENDING', 'ACCEPTED', 'REJECTED')),
    created_at BIGINT,
    updated_at BIGINT,
    responded_at BIGINT,
    UNIQUE(requester_id, receiver_id)
);

-- 3. conversations
CREATE TABLE IF NOT EXISTS conversations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at BIGINT,
    updated_at BIGINT
);

-- 4. conversation_members
CREATE TABLE IF NOT EXISTS conversation_members (
    conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    joined_at BIGINT,
    PRIMARY KEY (conversation_id, user_id)
);

-- 5. messages
CREATE TABLE IF NOT EXISTS messages (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
    from_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    encrypted_message TEXT NOT NULL,
    status TEXT DEFAULT 'sent',
    created_at BIGINT,
    delivered_at BIGINT,
    seen_at BIGINT
);

-- 6. media_files
CREATE TABLE IF NOT EXISTS media_files (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
    uploader_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    storage_path TEXT NOT NULL,
    byte_size BIGINT,
    created_at BIGINT
);

-- INDEXES FOR OPTIMIZING ACTUAL QUERIES --
-- Speed up buddy lookups
CREATE INDEX IF NOT EXISTS idx_buddy_req_users ON buddy_requests(requester_id, receiver_id);
-- Speed up participant retrieval
CREATE INDEX IF NOT EXISTS idx_conversation_members_conv ON conversation_members(conversation_id);
-- Speed up user conversation map
CREATE INDEX IF NOT EXISTS idx_conversation_members_user ON conversation_members(user_id);
-- Speed up chat loading
CREATE INDEX IF NOT EXISTS idx_messages_conversation_created ON messages(conversation_id, created_at);
-- Speed up unread count calculation
CREATE INDEX IF NOT EXISTS idx_messages_unread ON messages(conversation_id, status) WHERE status != 'seen';
-- Lookup user by Firebase UID and Email
CREATE INDEX IF NOT EXISTS idx_users_firebase_uid ON users(firebase_uid);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
