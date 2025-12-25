/* =====================================================
   CONFIG
===================================================== */

const BOOTSTRAP_ADMIN_EMAIL = "admin@bumpx.fr";

/* =====================================================
   WORKER
===================================================== */

export default {
  async fetch(req, env) {
    try {
      const url = new URL(req.url);

      /* ================= AUTH ================= */

      if (url.pathname === "/auth/login" && req.method === "POST") {
        return login(req, env);
      }

      const auth = req.headers.get("Authorization");
      if (!auth) return res("Unauthorized", 401);

      const token = auth.replace("Bearer ", "");
      const payload = await verifyJWT(token, env.JWT_SECRET);
      if (!payload) return res("Invalid token", 401);

      const user = await getUserById(env, payload.id);
      if (!user) return res("User not found", 401);

      // 🚀 bootstrap chef
      if (user.email === BOOTSTRAP_ADMIN_EMAIL && user.role !== "chef") {
        await env.DB.prepare(
          "UPDATE users SET role = 'chef' WHERE id = ?"
        ).bind(user.id).run();
        user.role = "chef";
      }

      /* ================= ROUTES ================= */

      // 👑 CREATE USER (CHEF)
      if (url.pathname === "/admin/users/create" && req.method === "POST") {
        requireChef(user);
        return createUser(req, env, user);
      }

      // 👀 LIST USERS (CHEF)
      if (url.pathname === "/admin/users" && req.method === "GET") {
        requireChef(user);
        return listUsers(env);
      }

      // 🔁 RESET PASSWORD (CHEF)
      if (url.pathname === "/admin/users/reset-password" && req.method === "POST") {
        requireChef(user);
        return resetPassword(req, env);
      }

      // 🧩 CHANGE ROLE (CHEF)
      if (url.pathname === "/admin/users/set-role" && req.method === "POST") {
        requireChef(user);
        return setUserRole(req, env);
      }

      // 📜 LOGS (CHEF)
      if (url.pathname === "/logs" && req.method === "GET") {
        requireChef(user);
        return json(await getLogs(env));
      }

      return res("Not found", 404);
    } catch (e) {
      if (e instanceof Response) return e;
      return res("Internal error", 500);
    }
  }
};

/* =====================================================
   AUTH
===================================================== */

async function login(req, env) {
  const { username, password } = await req.json();

  const user = await env.DB
    .prepare("SELECT * FROM users WHERE username = ?")
    .bind(username)
    .first();

  if (!user) return res("Invalid credentials", 401);

  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) return res("Invalid credentials", 401);

  const token = await signJWT(
    { id: user.id, email: user.email },
    env.JWT_SECRET
  );

  return json({
    token,
    must_change_password: !!user.must_change_password
  });
}

/* =====================================================
   ADMIN ACTIONS
===================================================== */

async function createUser(req, env, actor) {
  const { email, role } = await req.json();

  const id = crypto.randomUUID();
  const username = `user_${Math.floor(Math.random() * 10000)}`;
  const tempPassword = generatePassword();
  const hash = await hashPassword(tempPassword);

  await env.DB.prepare(`
    INSERT INTO users (id, username, email, role, password_hash, must_change_password, created_at)
    VALUES (?, ?, ?, ?, ?, 1, ?)
  `).bind(
    id, username, email, role, hash, Date.now()
  ).run();

  await addLog(env, actor.id, "CREATE_USER", username);

  return json({
    username,
    temporary_password: tempPassword // affiché UNE FOIS
  });
}

async function listUsers(env) {
  const users = await env.DB
    .prepare("SELECT id, username, email, role, must_change_password FROM users")
    .all();

  return json(users.results);
}

async function resetPassword(req, env) {
  const { userId } = await req.json();

  const tempPassword = generatePassword();
  const hash = await hashPassword(tempPassword);

  await env.DB.prepare(`
    UPDATE users
    SET password_hash = ?, must_change_password = 1
    WHERE id = ?
  `).bind(hash, userId).run();

  return json({
    temporary_password: tempPassword
  });
}

async function setUserRole(req, env) {
  const { userId, role } = await req.json();

  await env.DB.prepare(
    "UPDATE users SET role = ? WHERE id = ?"
  ).bind(role, userId).run();

  return res("Role updated");
}

/* =====================================================
   UTILS
===================================================== */

function requireChef(user) {
  if (user.role !== "chef") {
    throw new Response("Forbidden", { status: 403 });
  }
}

async function getUserById(env, id) {
  return env.DB
    .prepare("SELECT * FROM users WHERE id = ?")
    .bind(id)
    .first();
}

/* ================= JWT ================= */

async function signJWT(payload, secret) {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = btoa(JSON.stringify(payload));
  const data = `${header}.${body}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );

  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return `${data}.${sigB64}`;
}

async function verifyJWT(token, secret) {
  const [h, p, s] = token.split(".");
  if (!s) return null;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const ok = await crypto.subtle.verify(
    "HMAC",
    key,
    Uint8Array.from(atob(s), c => c.charCodeAt(0)),
    new TextEncoder().encode(`${h}.${p}`)
  );

  if (!ok) return null;
  return JSON.parse(atob(p));
}

/* ================= PASSWORD ================= */

async function hashPassword(pwd) {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(pwd)
  );
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

async function verifyPassword(pwd, hash) {
  return (await hashPassword(pwd)) === hash;
}

function generatePassword() {
  return Math.random().toString(36).slice(-10) + "!";
}

/* ================= LOGS ================= */

async function addLog(env, actorId, action, target) {
  await env.LOGS.put(
    `log:${Date.now()}`,
    JSON.stringify({ actorId, action, target, time: Date.now() })
  );
}

async function getLogs(env) {
  const list = await env.LOGS.list({ prefix: "log:" });
  return Promise.all(
    list.keys.map(k => env.LOGS.get(k.name, "json"))
  );
}

function res(msg, status = 200) {
  return new Response(msg, { status });
}

function json(data) {
  return new Response(JSON.stringify(data), {
    headers: { "Content-Type": "application/json" }
  });
}
