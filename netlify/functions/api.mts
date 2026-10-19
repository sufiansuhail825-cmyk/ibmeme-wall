import type { Context, Config } from "@netlify/functions"; //v2
import { getStore } from "@netlify/blobs";

const MAX_BYTES = 4 * 1024 * 1024; // keep under the ~6MB function payload limit
const HIDE_AT = 3; // reports needed to auto-hide a meme
const UPLOADS_PER_HOUR = 5;
const WINDOW_MS = 60 * 60 * 1000;
const TAGS = ["General", "TOK", "Extended Essay", "IA", "CAS", "Exams", "Sleep", "Teachers"];
const EXT: Record<string, string> = {
  "image/jpeg": "jpg",
  "image/png": "png",
  "image/webp": "webp",
  "image/gif": "gif",
};

type Meme = {
  id: string;
  caption: string;
  tag: string;
  type: string;
  createdAt: number;
  likes: number;
  reports: number;
};

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

// Check the real file signature, not just the type the browser claims.
function sniffType(b: Uint8Array): string | null {
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "image/jpeg";
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "image/png";
  if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) return "image/gif";
  if (
    b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
    b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50
  )
    return "image/webp";
  return null;
}

async function sha256(text: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf))
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 32);
}

export default async (req: Request, context: Context) => {
  const url = new URL(req.url);
  const parts = url.pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean);
  const route = parts[0] || "";
  const id = parts[1] || "";

  const images = getStore("meme-images");
  const metas = getStore({ name: "meme-meta", consistency: "strong" });
  const limits = getStore({ name: "meme-limits", consistency: "strong" });

  // ---- admin session helpers (credentials live in Netlify env vars, never in code) ----
  const secret = Netlify.env.get("SESSION_SECRET") || "";
  const hmac = async (msg: string) => {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
    return Array.from(new Uint8Array(sig))
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("");
  };
  const safeEqual = (a: string, b: string) => {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return d === 0;
  };
  const isAdmin = async () => {
    if (!secret) return false;
    const m = /(?:^|;\s*)admin_session=([^;]+)/.exec(req.headers.get("cookie") || "");
    if (!m) return false;
    const [exp, sig] = m[1].split(".");
    if (!exp || !sig || !(Number(exp) > Date.now())) return false;
    return safeEqual(sig, await hmac("admin." + exp));
  };
  const COOKIE = "HttpOnly; Secure; SameSite=Strict; Path=/";

  try {
    // ---------- list ----------
    if (route === "memes" && req.method === "GET") {
      const sort = url.searchParams.get("sort") === "top" ? "top" : "new";
      const tag = url.searchParams.get("tag") || "All";
      const offset = Math.max(0, parseInt(url.searchParams.get("offset") || "0", 10) || 0);
      const limit = Math.min(30, Math.max(1, parseInt(url.searchParams.get("limit") || "18", 10) || 18));

      const { blobs } = await metas.list();
      // keys start with a zero-padded timestamp, so the tail is the newest
      const keys = blobs.map((b) => b.key).sort().slice(-300);
      const all = (await Promise.all(keys.map((k) => metas.get(k, { type: "json" })))) as (Meme | null)[];

      let list = all.filter((m): m is Meme => !!m && m.reports < HIDE_AT);
      if (tag !== "All") list = list.filter((m) => m.tag === tag);
      list.sort((a, b) => (sort === "top" ? b.likes - a.likes || b.createdAt - a.createdAt : b.createdAt - a.createdAt));

      const page = list.slice(offset, offset + limit).map(({ reports, ...pub }) => pub);
      return json({ memes: page, hasMore: offset + limit < list.length, total: list.length });
    }

    // ---------- upload ----------
    if (route === "upload" && req.method === "POST") {
      const ip = context.ip || "unknown";
      const rlKey = "ip-" + (await sha256(ip));
      const now = Date.now();
      const prev = ((await limits.get(rlKey, { type: "json" })) as number[] | null) || [];
      const recent = prev.filter((t) => now - t < WINDOW_MS);
      if (recent.length >= UPLOADS_PER_HOUR) {
        return json({ error: `Slow down. Max ${UPLOADS_PER_HOUR} uploads per hour.` }, 429);
      }

      const form = await req.formData();
      const file = form.get("file");
      if (!(file instanceof File)) return json({ error: "No image received." }, 400);
      if (file.size === 0) return json({ error: "That file is empty." }, 400);
      if (file.size > MAX_BYTES) return json({ error: "Image is too big. Keep it under 4MB." }, 413);

      const bytes = new Uint8Array(await file.arrayBuffer());
      const type = sniffType(bytes);
      if (!type) return json({ error: "Only JPG, PNG, GIF or WebP images are allowed." }, 415);

      const rawCaption = String(form.get("caption") || "").replace(/\s+/g, " ").trim();
      const caption = rawCaption.slice(0, 120);
      const rawTag = String(form.get("tag") || "General");
      const tag = TAGS.includes(rawTag) ? rawTag : "General";

      const memeId = now.toString().padStart(13, "0") + "-" + crypto.randomUUID().slice(0, 8);
      await images.set(memeId, bytes.buffer as ArrayBuffer);
      const meme: Meme = { id: memeId, caption, tag, type, createdAt: now, likes: 0, reports: 0 };
      await metas.setJSON(memeId, meme);
      await limits.setJSON(rlKey, [...recent, now]);

      const { reports, ...pub } = meme;
      return json({ meme: pub }, 201);
    }

    // ---------- image (view or download) ----------
    if (route === "img" && id && req.method === "GET") {
      const meta = (await metas.get(id, { type: "json" })) as Meme | null;
      if (!meta || (meta.reports >= HIDE_AT && !(await isAdmin()))) {
        return new Response("Not found", { status: 404 });
      }
      const data = await images.get(id, { type: "arrayBuffer" });
      if (!data) return new Response("Not found", { status: 404 });
      const headers: Record<string, string> = {
        "content-type": meta.type,
        // short cache so a deleted or hidden meme disappears quickly
        "cache-control": meta.reports >= HIDE_AT ? "private, no-store" : "public, max-age=300",
      };
      if (url.searchParams.get("download") === "1") {
        headers["content-disposition"] = `attachment; filename="ib-meme-${id.slice(-8)}.${EXT[meta.type] || "jpg"}"`;
      }
      return new Response(data, { headers });
    }

    // ---------- like ----------
    if (route === "like" && id && req.method === "POST") {
      const meta = (await metas.get(id, { type: "json" })) as Meme | null;
      if (!meta) return json({ error: "Not found" }, 404);
      const body = await req.json().catch(() => ({}));
      meta.likes = Math.max(0, meta.likes + (body.undo ? -1 : 1));
      await metas.setJSON(id, meta);
      return json({ likes: meta.likes });
    }

    // ---------- report ----------
    if (route === "report" && id && req.method === "POST") {
      const meta = (await metas.get(id, { type: "json" })) as Meme | null;
      if (!meta) return json({ error: "Not found" }, 404);
      meta.reports += 1;
      await metas.setJSON(id, meta);
      return json({ ok: true, hidden: meta.reports >= HIDE_AT });
    }

    // ---------- admin ----------
    if (route === "admin") {
      // custom header blocks cross-site form posts (CSRF)
      if (req.method === "POST" && req.headers.get("x-admin") !== "1") return json({ error: "Bad request." }, 400);

      if (id === "login" && req.method === "POST") {
        const adminUser = Netlify.env.get("ADMIN_USER") || "";
        const adminPass = Netlify.env.get("ADMIN_PASS") || "";
        if (!adminUser || !adminPass || !secret) return json({ error: "Admin login is not configured." }, 503);

        const rlKey = "login-" + (await sha256(context.ip || "unknown"));
        const now = Date.now();
        const fails = (((await limits.get(rlKey, { type: "json" })) as number[] | null) || []).filter(
          (t) => now - t < 15 * 60 * 1000,
        );
        if (fails.length >= 5) return json({ error: "Too many attempts. Try again in 15 minutes." }, 429);

        const body = await req.json().catch(() => ({}));
        const okUser = safeEqual(await sha256(String(body.user ?? "")), await sha256(adminUser));
        const okPass = safeEqual(await sha256(String(body.pass ?? "")), await sha256(adminPass));
        if (!(okUser && okPass)) {
          await limits.setJSON(rlKey, [...fails, now]);
          return json({ error: "Wrong login id or password." }, 401);
        }
        await limits.delete(rlKey);
        const exp = String(now + 8 * 60 * 60 * 1000); // 8 hour session
        const token = exp + "." + (await hmac("admin." + exp));
        return new Response(JSON.stringify({ ok: true }), {
          headers: {
            "content-type": "application/json",
            "cache-control": "no-store",
            "set-cookie": `admin_session=${token}; ${COOKIE}; Max-Age=28800`,
          },
        });
      }
      if (id === "logout" && req.method === "POST") {
        return new Response(JSON.stringify({ ok: true }), {
          headers: {
            "content-type": "application/json",
            "cache-control": "no-store",
            "set-cookie": `admin_session=; ${COOKIE}; Max-Age=0`,
          },
        });
      }
      if (id === "me" && req.method === "GET") return json({ admin: await isAdmin() });

      if (!(await isAdmin())) return json({ error: "Please log in as admin." }, 401);

      if (id === "list" || (!id && req.method === "GET")) {
        const { blobs } = await metas.list();
        const keys = blobs.map((b) => b.key).sort().reverse().slice(0, 300);
        const all = (await Promise.all(keys.map((k) => metas.get(k, { type: "json" })))) as (Meme | null)[];
        return json({ memes: all.filter(Boolean), hideAt: HIDE_AT });
      }
      if (parts[1] === "delete" && parts[2] && req.method === "POST") {
        await images.delete(parts[2]);
        await metas.delete(parts[2]);
        return json({ ok: true });
      }
      if (parts[1] === "clear" && parts[2] && req.method === "POST") {
        const meta = (await metas.get(parts[2], { type: "json" })) as Meme | null;
        if (!meta) return json({ error: "Not found" }, 404);
        meta.reports = 0;
        await metas.setJSON(parts[2], meta);
        return json({ ok: true });
      }
    }

    return json({ error: "Not found" }, 404);
  } catch (err) {
    console.error(err);
    return json({ error: "Something broke on our side. Try again." }, 500);
  }
};

export const config: Config = {
  path: "/api/*",
};
