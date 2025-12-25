import jwt from "@tsndr/cloudflare-worker-jwt";

/* =====================
   ROLES & PERMISSIONS
===================== */

const ROLE_HIERARCHY = {
  "modérateur": 1,
  "sous-chef": 2,
  "chef": 3
};

const PERMISSIONS = {
  VIEW_SERVERS: 1,
  SUSPEND_SERVER: 2,
  RENAME_SERVER: 2,
  DELETE_USER: 2,
  MANAGE_ROLES: 3,
  VIEW_LOGS: 3
};

/* =====================
   WORKER
===================== */

export default {
  async fetch(req, env) {
    try {
      const url = new URL(req.url);

      /* ========= AUTH ========= */
      const auth = req.headers.get("Authorization");
      if (!auth) return res("Unauthorized", 401);

      const token = auth.replace("Bearer ", "");
      if (!(await jwt.verify(token, env.JWT_SECRET))) {
        return res("Invalid token", 401);
      }

      const payload = jwt.decode(token);
      const userId = payload.id;

      const userData = await env.ROLES.get(`user:${userId}`, "json");
      if (!userData) return res("No role assigned", 403);

      const role = userData.role;

      /* ========= ROUTES ========= */

      // 🔍 Voir serveurs
      if (url.pathname === "/servers" && req.method === "GET") {
        requirePerm(role, "VIEW_SERVERS");
        return proxyPtero("/api/application/servers", env);
      }

      // ⏸️ Suspendre serveur
      if (url.pathname === "/servers/suspend" && req.method === "POST") {
        requirePerm(role, "SUSPEND_SERVER");

        const { serverId } = await req.json();

        await addLog(env, userId, role, "SUSPEND_SERVER", `server:${serverId}`);

        return proxyPtero(
          `/api/application/servers/${serverId}/suspend`,
          env,
          "POST"
        );
      }

      // ✏️ Renommer serveur
      if (url.pathname === "/servers/rename" && req.method === "POST") {
        requirePerm(role, "RENAME_SERVER");

        const { serverId, name } = await req.json();

        await addLog(env, userId, role, "RENAME_SERVER", `server:${serverId}`);

        return proxyPtero(
          `/api/application/servers/${serverId}/details`,
          env,
          "PATCH",
          { name }
        );
      }

      // ❌ Supprimer utilisateur (sauf chef)
      if (url.pathname === "/users/delete" && req.method === "DELETE") {
        requirePerm(role, "DELETE_USER");

        const { targetUserId } = await req.json();
        const target = await env.ROLES.get(`user:${targetUserId}`, "json");

        if (!target) return res("User not found", 404);
        if (target.role === "chef") return res("Cannot delete chef", 403);

        await env.ROLES.delete(`user:${targetUserId}`);

        await addLog(
          env,
          userId,
          role,
          "DELETE_USER",
          `user:${targetUserId}`
        );

        return proxyPtero(
          `/api/application/users/${targetUserId}`,
          env,
          "DELETE"
        );
      }

      // 👑 Assigner rôle (CHEF)
      if (url.pathname === "/roles/set" && req.method === "POST") {
        requirePerm(role, "MANAGE_ROLES");

        const { targetUserId, newRole } = await req.json();
        if (!ROLE_HIERARCHY[newRole]) return res("Invalid role", 400);

        const target = await env.ROLES.get(`user:${targetUserId}`, "json");

        if (target?.role === "chef" && newRole !== "chef") {
          return res("Chef immutable", 403);
        }

        await env.ROLES.put(
          `user:${targetUserId}`,
          JSON.stringify({ role: newRole })
        );

        await addLog(
          env,
          userId,
          role,
          "SET_ROLE",
          `user:${targetUserId} => ${newRole}`
        );

        return res("Role updated");
      }

      // 📜 LOGS (CHEF ONLY)
      if (url.pathname === "/logs" && req.method === "GET") {
        requirePerm(role, "VIEW_LOGS");

        const logs = await getLogs(env, 50);
        return json(logs);
      }

      return res("Not found", 404);
    } catch (err) {
      if (err instanceof Response) return err;
      return res("Internal error", 500);
    }
  }
};

/* =====================
   UTILS
===================== */

function requirePerm(role, perm) {
  if (ROLE_HIERARCHY[role] < PERMISSIONS[perm]) {
    throw new Response("Forbidden", { status: 403 });
  }
}

async function proxyPtero(path, env, method = "GET", body) {
  const r = await fetch(env.PTERO_URL + path, {
    method,
    headers: {
      "Authorization": `Bearer ${env.PTERO_KEY}`,
      "Accept": "Application/vnd.pterodactyl.v1+json",
      "Content-Type": "application/json"
    },
    body: body ? JSON.stringify(body) : undefined
  });

  return new Response(await r.text(), {
    status: r.status,
    headers: { "Content-Type": "application/json" }
  });
}

async function addLog(env, actorId, actorRole, action, target) {
  const timestamp = Date.now();

  await env.LOGS.put(
    `log:${timestamp}`,
    JSON.stringify({
      actorId,
      actorRole,
      action,
      target,
      timestamp
    })
  );
}

async function getLogs(env, limit = 50) {
  const list = await env.LOGS.list({ prefix: "log:" });

  return Promise.all(
    list.keys
      .sort((a, b) => b.name.localeCompare(a.name))
      .slice(0, limit)
      .map(k => env.LOGS.get(k.name, "json"))
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
