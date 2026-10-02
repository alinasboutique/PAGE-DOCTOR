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
        fields: "id,message,created_time,permalink_url,type,status_type,likes.limit(0).summary(true),comments.limit(0).summary(true),shares",
        limit: "50"
      });
      result.posts = feed.data || [];
    } catch (e) {
      result.posts_error = e.message;
      try {
        const feed = await metaGet(`${page.id}/feed`, {
          access_token: token,
          fields: "id,message,created_time,permalink_url,type,status_type",
          limit: "50"
        });
        result.posts = feed.data || [];
        result.posts_engagement_source = "per-post";

        for (const post of result.posts) {
          const engagement = { reactions: null, comments: null, shares: null, total: null, available: false };
          try {
            const d = await metaGet(post.id, {
              access_token: token,
              fields: "likes.limit(0).summary(true),comments.limit(0).summary(true),shares"
            });
            const likes = d?.likes?.summary?.total_count;
            const comments = d?.comments?.summary?.total_count;
            const shares = d?.shares?.count;
            engagement.reactions = typeof likes === "number" ? likes : null;
            engagement.comments = typeof comments === "number" ? comments : null;
            engagement.shares = typeof shares === "number" ? shares : null;
          } catch (postError) {
            console.error("POST ENGAGEMENT FAILED:", post.id, postError.meta || postError);
          }
          engagement.available = [engagement.reactions, engagement.comments, engagement.shares].some(v => v !== null);
          if (engagement.available) {
            engagement.total = [engagement.reactions, engagement.comments, engagement.shares]
              .filter(v => typeof v === "number")
              .reduce((sum, v) => sum + v, 0);
          }
          post.engagement = engagement;
        }
      } catch (fallbackError) {
        result.posts_error = fallbackError.message;
      }
    }

    result.diagnostic = buildDiagnostic(result.insights, result.posts, result.page);
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
  const hasLikes = typeof post?.likes?.summary?.total_count === "number";
  const hasReactions = typeof post?.reactions?.summary?.total_count === "number";
  const hasComments = typeof post?.comments?.summary?.total_count === "number";
  const hasShares = typeof post?.shares?.count === "number";

  const reactions = hasReactions
    ? post.reactions.summary.total_count
    : hasLikes ? post.likes.summary.total_count : null;
  const comments = hasComments ? post.comments.summary.total_count : null;
  const shares = hasShares ? post.shares.count : null;
  const available = [reactions, comments, shares].some(v => v !== null);

  return {
    reactions,
    comments,
    shares,
    total: available
      ? [reactions, comments, shares].filter(v => v !== null).reduce((sum, v) => sum + v, 0)
      : null,
    available
  };
}

function classifyPost(post) {
  const text = String(post?.message || "").toLowerCase();
  const type = String(post?.type || "").toLowerCase();
  const status = String(post?.status_type || "").toLowerCase();

  if (type.includes("video") || status.includes("video") || type.includes("reel")) return "Reels / Video";
  if (/\b(comand|comenzi|preț|pret|ofert|disponibil|livrare|cumpăr|cumpar|personalizat|set|produs|catalog|rezerv)/i.test(text)) return "Vânzare / Produs";
  if (/\b(cum |cum să|cum sa|tutorial|sfat|tips|idee|învață|invata|pas cu pas|truc)/i.test(text)) return "Educațional";
  if (/\b(eu |noi |poveste|culise|atelier|azi am|astăzi|astazi|munca mea|în spatele|in spatele)/i.test(text)) return "Poveste / Culise";
  if (/\b(voi|tu ce|ce preferi|spune-mi|spune mi|alege|comentează|comenteaza|întrebare|intrebare|părere|parere)/i.test(text)) return "Comunitate / Conversație";
  return "Inspirație / Prezentare";
}

function score10(value, thresholds) {
  for (const t of thresholds) if (value <= t.max) return t.score;
  return 10;
}

function buildDiagnostic(insights, posts = [], pageInfo = {}) {
  const available = insights.filter(x => !x.unavailable);
  const hasData = available.some(x => Array.isArray(x.data) && x.data.length);
  const followers = Number(pageInfo?.followers_count || pageInfo?.fan_count || 0);

  const analyzedPosts = posts.map(p => ({
    ...p,
    category: classifyPost(p),
    engagement: getPostEngagement(p)
  }));

  const engagementPosts = analyzedPosts.filter(p => p.engagement.available && p.engagement.total !== null);
  const totalEngagement = engagementPosts.reduce((sum, p) => sum + p.engagement.total, 0);
  const avgEngagement = engagementPosts.length ? totalEngagement / engagementPosts.length : null;
  const postsWithEngagement = engagementPosts.filter(p => p.engagement.total > 0).length;
  const conversationPosts = engagementPosts.filter(p =>
    (p.engagement.comments !== null && p.engagement.comments > 0) ||
    (p.engagement.shares !== null && p.engagement.shares > 0)
  ).length;

  const byCategory = {};
  analyzedPosts.forEach(p => {
    if (!byCategory[p.category]) byCategory[p.category] = { count: 0, engagementCount: 0, engagement: 0, comments: 0, shares: 0 };
    byCategory[p.category].count++;
    if (p.engagement.available && p.engagement.total !== null) {
      byCategory[p.category].engagementCount++;
      byCategory[p.category].engagement += p.engagement.total;
      if (p.engagement.comments !== null) byCategory[p.category].comments += p.engagement.comments;
      if (p.engagement.shares !== null) byCategory[p.category].shares += p.engagement.shares;
    }
  });

  const categoryStats = Object.entries(byCategory)
    .map(([category, v]) => ({
      category,
      count: v.count,
      avgEngagement: v.engagementCount ? v.engagement / v.engagementCount : null,
      comments: v.comments,
      shares: v.shares
    }))
    .sort((a,b) => (b.avgEngagement ?? -1) - (a.avgEngagement ?? -1));

  const eligibleCategories = categoryStats.filter(x => x.engagementCount >= 2 && x.avgEngagement !== null);
  const bestCategory = eligibleCategories[0] || null;
  const weakestCategory = eligibleCategories.length > 1 ? [...eligibleCategories].sort((a,b) => a.avgEngagement - b.avgEngagement)[0] : null;

  const recentDates = analyzedPosts.map(p => new Date(p.created_time)).filter(d => !Number.isNaN(d.getTime())).sort((a,b) => a-b);
  const activeWeeks = new Set(recentDates.map(d => {
    const day = d.getUTCDay() || 7;
    const monday = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() - day + 1));
    return monday.toISOString().slice(0,10);
  })).size;
  const consistencyScore = Math.min(10, Math.max(1, activeWeeks * 2.5));

  const engagementPerFollower = followers && avgEngagement !== null ? (avgEngagement / followers) * 100 : null;
  const engagementScore = followers
    ? score10(engagementPerFollower, [
        {max:0.05,score:3},{max:0.10,score:4},{max:0.20,score:5},{max:0.40,score:6},
        {max:0.70,score:7},{max:1.20,score:8},{max:2.00,score:9}
      ])
    : null;

  const commentsSharesRate = engagementPosts.length ? (conversationPosts / engagementPosts.length) * 100 : null;
  const conversationScore = commentsSharesRate === null ? null : score10(commentsSharesRate, [
    {max:5,score:2},{max:10,score:3},{max:20,score:4},{max:30,score:5},
    {max:40,score:6},{max:55,score:7},{max:70,score:8},{max:85,score:9}
  ]);

  const contentMixScore = Math.min(10, Math.max(2, Object.keys(byCategory).length * 2));

  const dailyUnique = (insights.find(x => x.metric === "page_total_media_view_unique")?.data || [])
    .flatMap(x => Array.isArray(x.values) ? x.values : [])
    .map(x => typeof x.value === "number" ? x.value : null).filter(x => x !== null);
  const medianUnique = dailyUnique.length ? [...dailyUnique].sort((a,b)=>a-b)[Math.floor(dailyUnique.length/2)] : null;
  const visibilityPerFollower = followers && medianUnique !== null ? (medianUnique / followers) * 100 : null;
  const visibilityScore = visibilityPerFollower === null ? null : score10(visibilityPerFollower, [
    {max:2,score:3},{max:5,score:4},{max:10,score:5},{max:20,score:6},
    {max:35,score:7},{max:50,score:8},{max:75,score:9}
  ]);

  const scores = [
    { label: "Vizibilitate", score: visibilityScore, reason: visibilityScore === null ? "Nu avem suficiente date pentru un scor sigur." : "Bazat pe vizibilitatea zilnică disponibilă raportată la baza de urmăritori." },
    { label: "Reacția publicului", score: engagementScore, reason: engagementScore === null ? "Numărul de urmăritori nu este disponibil pentru calcul." : "Bazat pe interacțiunile publice medii raportate la baza de urmăritori." },
    { label: "Consecvență", score: consistencyScore, reason: "Bazat pe distribuția postărilor în perioada analizată." },
    { label: "Conversație", score: conversationScore, reason: "Bazat pe proporția postărilor care au primit comentarii sau distribuiri." },
    { label: "Diversitatea conținutului", score: contentMixScore, reason: "Bazat pe tipurile de conținut identificate în postările analizate." }
  ].filter(x => x.score !== null);

  const overallScore = scores.length ? Math.round((scores.reduce((a,b)=>a+b.score,0)/scores.length)*10)/10 : null;

  const strengths = [];
  const blockers = [];
  const priorities = [];

  if (bestCategory && bestCategory.avgEngagement !== null) strengths.push(`În eșantionul analizat, „${bestCategory.category}” are cea mai mare medie de interacțiuni: ${Math.round(bestCategory.avgEngagement).toLocaleString("ro-RO")} / postare.`);
  if (postsWithEngagement && analyzedPosts.length) strengths.push(`${postsWithEngagement} din ${analyzedPosts.length} postări au primit cel puțin o interacțiune publică.`);
  if (conversationPosts) strengths.push(`${conversationPosts} postări au generat comentarii sau distribuiri — acestea sunt semnale mai puternice de conversație decât simpla reacție.`);

  if (weakestCategory && avgEngagement > 0 && weakestCategory.avgEngagement < avgEngagement * 0.7) {
    const pct = Math.round((1 - weakestCategory.avgEngagement / avgEngagement) * 100);
    blockers.push(`„${weakestCategory.category}” este cu aproximativ ${pct}% sub media de interacțiuni a paginii în acest eșantion. Merită testat alt unghi, hook sau format înainte să continui aceeași abordare.`);
  }
  if (!conversationPosts && analyzedPosts.length) blockers.push("Postările analizate generează reacții, dar foarte puține comentarii sau distribuiri. Asta sugerează că merită testate CTA-uri care cer un răspuns sau o alegere.");
  if (!engagementPosts.length && analyzedPosts.length) blockers.push("Meta nu a furnizat engagement pentru postările analizate. Nu îl tratăm ca 0.");
  if (analyzedPosts.length < 20) blockers.push("Eșantionul este mai mic de 20 de postări, deci concluziile despre ce prinde cel mai bine sunt încă orientative.");

  if (bestCategory) priorities.push(`Crește ponderea testată a „${bestCategory.category}”, dar verifică rezultatul pe încă 5–10 postări înainte de a trage concluzia finală.`);
  if (weakestCategory && weakestCategory.category !== bestCategory?.category) priorities.push(`Nu repeta mecanic formatul „${weakestCategory.category}”; schimbă hook-ul, structura sau CTA-ul și compară din nou rezultatele.`);
  priorities.push("Construiește următoarele 7 zile în jurul unui singur obiectiv: vizibilitate, conversații sau comenzi — nu toate simultan.");

  const plan = [
    "Ziua 1: păstrează un format apropiat de categoria care a avut cea mai bună medie.",
    "Ziua 2: testează un hook diferit pe aceeași temă.",
    "Ziua 3: publică un Reel/video scurt și urmărește reacția.",
    "Ziua 4: publică o postare care cere explicit o opinie sau alegere.",
    "Ziua 5: prezintă produsul/oferta cu un singur CTA.",
    "Ziua 6: repetă varianta care a generat cele mai multe comentarii sau distribuiri.",
    "Ziua 7: compară rezultatele și decide ce merită repetat în săptămâna următoare."
  ];

  const topPosts = [...engagementPosts].sort((a,b) => b.engagement.total - a.engagement.total).slice(0,5);

  return {
    dataAvailable: hasData || analyzedPosts.length > 0,
    status: hasData ? "Am primit date reale de la Meta" : "Am primit date publice, dar Insights sunt limitate",
    windowDays: 28,
    postsAnalyzed: analyzedPosts.length,
    totalEngagement,
    avgEngagement,
    scores,
    overallScore,
    contentCategories: categoryStats,
    bestCategory,
    weakestCategory,
    strengths,
    blockers,
    priorities: priorities.slice(0,3),
    plan,
    topPosts: topPosts.map(p => ({
      id: p.id,
      message: String(p.message || "").slice(0, 180),
      created_time: p.created_time,
      category: p.category,
      type: p.type || null,
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
