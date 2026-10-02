const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 10000;
const BASE_URL = (process.env.APP_BASE_URL || "").replace(/\/+$/, "");
const META_APP_ID = process.env.META_APP_ID;
const META_CONFIG_ID = process.env.META_CONFIG_ID; 
const META_APP_SECRET = process.env.META_APP_SECRET;
const META_GRAPH_VERSION = process.env.META_GRAPH_VERSION || "v26.0";
const STATE_SECRET = process.env.STATE_SECRET || crypto.randomBytes(32).toString("hex");

if (!BASE_URL || !META_APP_ID || !META_APP_SECRET) {
  console.warn("Missing APP_BASE_URL, META_APP_ID or META_APP_SECRET. OAuth will not work until they are set.");
}

function b64url(input) {
  return Buffer.from(input).toString("base64url");
}
function makeState(payload) {
  const body = b64url(JSON.stringify({ ...payload, iat: Date.now() }));
  const sig = crypto.createHmac("sha256", STATE_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}
function readState(state) {
  const [body, sig] = String(state || "").split(".");
  if (!body || !sig) throw new Error("Invalid OAuth state.");
  const expected = crypto.createHmac("sha256", STATE_SECRET).update(body).digest("base64url");
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) throw new Error("Invalid OAuth state signature.");
  const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  if (!payload.iat || Date.now() - payload.iat > 10 * 60 * 1000) throw new Error("OAuth state expired.");
  return payload;
}

async function metaGet(endpoint, params) {
  const url = new URL(`https://graph.facebook.com/${META_GRAPH_VERSION}/${endpoint.replace(/^\/+/, "")}`);
  Object.entries(params || {}).forEach(([k, v]) => url.searchParams.set(k, v));
  const r = await fetch(url);
  const data = await r.json();
  if (!r.ok || data.error) {
    const msg = data?.error?.message || `Meta API error ${r.status}`;
    const err = new Error(msg);
    err.meta = data;
    throw err;
  }
  return data;
}

app.get("/health", (_req, res) => res.json({ ok: true, service: "Page Doctor" }));

app.get("/auth/meta", (req, res) => {
  if (!META_APP_ID || !BASE_URL) return res.status(500).send("Meta OAuth is not configured yet.");
  const returnUrl = String(req.query.return || "/");
  const state = makeState({ returnUrl });
  const redirectUri = `${BASE_URL}/auth/meta/callback`;
  const url = new URL(`https://www.facebook.com/${META_GRAPH_VERSION}/dialog/oauth`);
  url.searchParams.set("client_id", META_APP_ID);
  url.searchParams.set("config_id", META_CONFIG_ID);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("state", state);
  
  url.searchParams.set("response_type", "code");
  url.searchParams.set("override_default_response_type", "true");
  res.redirect(url.toString());
});

app.get("/auth/meta/callback", async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;
    if (error) throw new Error(error_description || error);
    const payload = readState(state);
    if (!code) throw new Error("Meta did not return an authorization code.");

    const redirectUri = `${BASE_URL}/auth/meta/callback`;
    let token;

try {
  token = await metaGet("oauth/access_token", {
    client_id: META_APP_ID,
    client_secret: META_APP_SECRET,
    redirect_uri: redirectUri,
    code
  });

  console.log("STEP 1 OK: short-lived token received");
} catch (e) {
  console.error("STEP 1 FAILED: code exchange", e.meta || e);
  throw new Error(`STEP 1 - Code exchange failed: ${e.message}`);
}

let longToken;

try {
  longToken = await metaGet("oauth/access_token", {
    grant_type: "fb_exchange_token",
    client_id: META_APP_ID,
    client_secret: META_APP_SECRET,
    fb_exchange_token: token.access_token
  });

  console.log("STEP 2 OK: long-lived token received");
} catch (e) {
  console.error("STEP 2 FAILED: long-lived token exchange", e.meta || e);
  throw new Error(`STEP 2 - Long-lived token exchange failed: ${e.message}`);
}

    const activeToken = longToken.access_token || token.access_token;
    const perms = await metaGet("/me/permissions", {
  access_token: activeToken
});

console.log(
  "META PERMISSIONS:",
  (perms.data || []).map(p => ({
    permission: p.permission,
    status: p.status
  }))
);

const me = await metaGet("/me", {
  access_token: activeToken,
 fields: "id,name"
});

console.log("META USER:", {
  id: me.id,
  name: me.name
});

const pages = await metaGet("/me/accounts", {
  access_token: activeToken,
  fields: "id,name,access_token,tasks"
});

console.log("META PAGES:", (pages.data || []).map(p => ({
  id: p.id,
  name: p.name,
  tasks: p.tasks || []
})));
    // Do not put access tokens in the browser URL. For the first version,
    // the selected Page data is encoded into a short-lived server-side handoff.
    // A production version should persist encrypted sessions in a database.
    const handoff = makeState({
      kind: "pages",
      returnUrl: payload.returnUrl || "/",
      userToken: longToken.access_token || token.access_token,
      pages: (pages.data || []).map(p => ({
        id: p.id, name: p.name, access_token: p.access_token, tasks: p.tasks || []
      }))
    });
    res.redirect(`/select-page?state=${encodeURIComponent(handoff)}`);
  } catch (e) {
    console.error("OAuth callback error:", e.meta || e);
    res.status(400).send(`
      <html><body style="font-family:Arial;padding:40px">
      <h2>Nu am putut conecta Meta</h2>
      <p>${escapeHtml(e.message)}</p>
      <p><a href="/">Înapoi la Page Doctor</a></p>
      </body></html>`);
  }
});

app.get("/select-page", (req, res) => {
  try {
    const payload = readState(req.query.state);
    if (payload.kind !== "pages") throw new Error("Invalid page selection state.");
    const safe = {
      returnUrl: payload.returnUrl,
      pages: payload.pages.map(p => ({ id: p.id, name: p.name, tasks: p.tasks }))
    };
    res.send(renderPageSelector(safe, req.query.state));
  } catch (e) {
    res.status(400).send("Invalid or expired selection link.");
  }
});

app.post("/api/analyze", async (req, res) => {
  try {
    const { state, pageId } = req.body || {};
    const payload = readState(state);
    if (payload.kind !== "pages") throw new Error("Invalid selection state.");
    const page = payload.pages.find(p => p.id === pageId);
    if (!page) throw new Error("Page not found in this authorization.");
    const token = page.access_token;

    const pageInfo = await metaGet(page.id, {
      access_token: token,
      fields: "id,name,about,followers_count,fan_count,category,website"
    }).catch(async () => metaGet(page.id, {
      access_token: token,
      fields: "id,name,about,category,website"
    }));

    const result = {
      page: pageInfo,
      tasks: page.tasks || [],
      insights: [],
      posts: [],
      diagnostic: {}
    };

    // Analizăm o fereastră reală de 28 de zile, nu doar ultimul punct disponibil.
    const until = Math.floor(Date.now() / 1000);
    const since = until - 28 * 24 * 60 * 60;
    const metricCandidates = [
      "page_total_media_view_unique",
      "page_media_view",
      "page_follows"
    ];

    for (const metric of metricCandidates) {
      try {
        const data = await metaGet(`${page.id}/insights/${metric}`, {
          access_token: token,
          period: "day",
          since: String(since),
          until: String(until)
        });
        result.insights.push({ metric, data: data.data || [] });
      } catch (e) {
        result.insights.push({ metric, unavailable: true, error: e.message });
      }
    }

    // Luăm postările recente împreună cu semnalele publice de engagement.
    try {
      const feed = await metaGet(`${page.id}/feed`, {
        access_token: token,
        fields: "id,message,created_time,permalink_url,reactions.summary(true),comments.summary(true),shares",
        limit: "50"
      });
      result.posts = feed.data || [];
    } catch (e) {
      result.posts_error = e.message;
      try {
        const feed = await metaGet(`${page.id}/feed`, {
          access_token: token,
          fields: "id,message,created_time,permalink_url",
          limit: "50"
        });
        result.posts = feed.data || [];
      } catch (fallbackError) {
        result.posts_error = fallbackError.message;
      }
    }

    result.diagnostic = buildDiagnostic(result.insights, result.posts);
    res.json(result);
  } catch (e) {
    console.error("Analyze error:", e.meta || e);
    res.status(400).json({ error: e.message });
  }
});

function getInsightTotal(insight) {
  if (!insight || insight.unavailable) return null;
  const values = (insight.data || []).flatMap(x => Array.isArray(x.values) ? x.values : []);
  const nums = values.map(x => typeof x.value === "number" ? x.value : null).filter(x => x !== null);
  return nums.length ? nums.reduce((a, b) => a + b, 0) : null;
}

function getPostEngagement(post) {
  const reactions = Number(post?.reactions?.summary?.total_count || 0);
  const comments = Number(post?.comments?.summary?.total_count || 0);
  const shares = Number(post?.shares?.count || 0);
  return { reactions, comments, shares, total: reactions + comments + shares };
}

function buildDiagnostic(insights, posts = []) {
  const available = insights.filter(x => !x.unavailable);
  const hasData = available.some(x => Array.isArray(x.data) && x.data.length);
  const analyzedPosts = posts.map(p => ({ ...p, engagement: getPostEngagement(p) }));
  const withEngagement = analyzedPosts.filter(p => p.engagement.total > 0);
  const totalEngagement = analyzedPosts.reduce((sum, p) => sum + p.engagement.total, 0);
  const avgEngagement = analyzedPosts.length ? totalEngagement / analyzedPosts.length : 0;
  const topPosts = [...analyzedPosts].sort((a, b) => b.engagement.total - a.engagement.total).slice(0, 3);

  const mediaViews = getInsightTotal(insights.find(x => x.metric === "page_media_view"));
  const uniqueViews = getInsightTotal(insights.find(x => x.metric === "page_total_media_view_unique"));
  const follows = getInsightTotal(insights.find(x => x.metric === "page_follows"));

  const priorities = [];
  const strengths = [];
  const blockers = [];

  if (mediaViews !== null) strengths.push(`Pagina a avut aproximativ ${Math.round(mediaViews).toLocaleString("ro-RO")} vizualizări cumulate în perioada analizată.`);
  if (uniqueViews !== null) strengths.push(`Am primit și date despre aproximativ ${Math.round(uniqueViews).toLocaleString("ro-RO")} persoane unice care au văzut conținutul.`);
  if (withEngagement.length) strengths.push(`${withEngagement.length} dintre cele ${analyzedPosts.length} postări analizate au primit cel puțin o interacțiune publică.`);
  if (!withEngagement.length && analyzedPosts.length) blockers.push("Postările recente nu au furnizat suficiente semnale publice de engagement pentru a identifica un format câștigător.");

  if (analyzedPosts.length < 10) blockers.push("Meta a returnat un eșantion mic de postări; concluziile despre conținut trebuie tratate ca orientative.");
  if (follows === null) blockers.push("Nu avem încă o serie completă pentru urmăririle paginii, deci nu calculăm artificial o rată de creștere.");
  if (mediaViews !== null && analyzedPosts.length) priorities.push("Compară vizibilitatea totală cu tipurile de postări care au generat cele mai multe interacțiuni.");
  if (withEngagement.length) priorities.push("Repetă temele și formatele postărilor din topul de engagement, fără să copiezi mecanic conținutul.");
  priorities.push("În următoarele 7 zile testează o singură ipoteză de conținut și urmărește vizibilitatea + reacțiile + comentariile.");
  if (!priorities.length) priorities.push("Mai întâi trebuie să strângem suficiente date Meta pentru o analiză comparativă.");

  const plan = [
    "Ziua 1: alege o temă principală și un obiectiv clar pentru conținut.",
    "Ziua 2: publică o postare utilă sau educativă și urmărește reacțiile.",
    "Ziua 3: publică un Reel/video scurt și notează vizibilitatea.",
    "Ziua 4: publică o postare de poveste sau din culise pentru conversații.",
    "Ziua 5: publică o ofertă/produs cu un singur CTA clar.",
    "Ziua 6: repetă formatul care a primit cele mai bune semnale în primele zile.",
    "Ziua 7: compară rezultatele și păstrează pentru săptămâna următoare ce a funcționat mai bine."
  ];

  return {
    dataAvailable: hasData || analyzedPosts.length > 0,
    status: hasData ? "Am primit date reale de la Meta" : "Am primit date publice, dar Insights sunt limitate",
    windowDays: 28,
    postsAnalyzed: analyzedPosts.length,
    totalEngagement,
    avgEngagement,
    strengths,
    blockers,
    priorities,
    plan,
    topPosts: topPosts.map(p => ({
      id: p.id,
      message: String(p.message || "").slice(0, 180),
      created_time: p.created_time,
      engagement: p.engagement,
      permalink_url: p.permalink_url || null
    }))
  };
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
}

function renderPageSelector(data, state) {
  const items = data.pages.length
    ? data.pages.map(p => `<button class="page-option" data-id="${escapeHtml(p.id)}"><strong>${escapeHtml(p.name)}</strong><span>${escapeHtml((p.tasks||[]).join(", "))}</span></button>`).join("")
    : `<p>Nu a fost returnată nicio pagină pentru acest cont.</p>`;
  return `<!doctype html><html lang="ro"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Page Doctor — Alege pagina</title>
  <style>
  body{margin:0;background:#fbf7f2;color:#292525;font-family:Arial,sans-serif}.box{max-width:720px;margin:60px auto;padding:28px;background:#fff;border:1px solid #eadfd7;border-radius:22px;box-shadow:0 12px 35px #0000000a}h1{margin-top:0}.page-option{display:block;width:100%;text-align:left;padding:18px;margin:12px 0;border:1px solid #eadfd7;border-radius:14px;background:#fff;cursor:pointer}.page-option:hover{border-color:#d9777b}.page-option span{display:block;color:#756d68;font-size:13px;margin-top:6px}.status{margin-top:18px;padding:14px;border-radius:12px;background:#fff8eb;display:none}.btn{margin-top:18px;border:0;border-radius:12px;padding:14px 20px;background:#d9777b;color:#fff;font-weight:800;cursor:pointer}
  </style></head><body><div class="box"><h1>🔐 Alege pagina pentru analiză</h1><p>Meta a returnat paginile pe care contul tău le poate accesa. Alege pagina pe care vrei să o analizezi.</p><div id="pages">${items}</div><div id="status" class="status"></div></div>
  <script>
  const state=${JSON.stringify(state)};
  document.querySelectorAll(".page-option").forEach(btn=>btn.addEventListener("click",async()=>{
    document.querySelectorAll(".page-option").forEach(x=>x.disabled=true);
    const s=document.getElementById("status"); s.style.display="block"; s.textContent="Se preiau datele reale de la Meta...";
    try{
      const r=await fetch("/api/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({state,pageId:btn.dataset.id})});
      const d=await r.json(); if(!r.ok) throw new Error(d.error||"Eroare");
      sessionStorage.setItem("pageDoctorResult",JSON.stringify(d));
      location.href="/?connected=1";
    }catch(e){s.textContent=e.message;document.querySelectorAll(".page-option").forEach(x=>x.disabled=false)}
  }));
  </script></body></html>`;
}

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => console.log(`Page Doctor listening on ${PORT}`));
