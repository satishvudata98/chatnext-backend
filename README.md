# ChatNext — Backend

A minimal Node.js backend for the ChatNext project.

## Description

This folder contains a lightweight server and helpers used by the ChatNext app.

## Files

- `server.js` — main server entry
- `db.js` — database helpers
- `supabaseClient.js` — Supabase client configuration
- `test.js` — quick local test script

## Requirements

- Node.js (20+)

## Setup

1. Install dependencies:

```
npm install
```

2. Start the server:

```
node server.js
```

3. Run quick tests (if present):

```
node test.js
```

## Notes

- This project uses Supabase via `supabaseClient.js`.
- Update environment variables or config in the same directory as needed.

If you want a more detailed README (architecture, endpoints, env vars), tell me what to include.
