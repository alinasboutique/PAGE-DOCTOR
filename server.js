const express = require("express");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

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
    const { state, pageId, niche, goal, timezone } = req.body || {};
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

    // Luăm postările publicate de pagină; folosim /posts deoarece /feed poate declanșa câmpuri Meta depreciate.
    // Meta poate returna datele cu succes chiar dacă
    // nu include toate câmpurile de engagement, așa că îmbogățim separat fiecare
    // postare atunci când engagement-ul nu este deja disponibil.
    const feedFields = "id,message,created_time,permalink_url";
    try {
      const feed = await metaGet(`${page.id}/posts`, {
        access_token: token,
        fields: feedFields,
        since: String(since),
        until: String(until),
        limit: "50"
      });
      result.posts = feed.data || [];
      result.posts_engagement_source = "feed";
      console.log("POSTS OK:", {
        count: result.posts.length,
      });
    } catch (e) {
      result.posts_error = e.message;
      console.error("FEED WITH ENGAGEMENT FAILED:", e.meta || e);

      try {
        const feed = await metaGet(`${page.id}/posts`, {
          access_token: token,
          fields: feedFields,
          since: String(since),
          until: String(until),
          limit: "50"
        });
        result.posts = feed.data || [];
        result.posts_engagement_source = "per-post";
      } catch (fallbackError) {
        result.posts_error = fallbackError.message;
        console.error("FEED FALLBACK FAILED:", fallbackError.meta || fallbackError);
      }
    }

    // Enrichment is intentional even when the main /feed request succeeded:
    // this is the path that makes the "top post" and content-type comparison real.
    let enrichedCount = 0;
    for (const post of result.posts) {
      const current = getPostEngagement(post);
      if (current.available) {
        post.engagement = current;
        continue;
      }

      try {
        const d = await metaGet(post.id, {
          access_token: token,
          fields: "reactions.limit(0).summary(true),comments.limit(0).summary(true),shares"
        });
        const reactions = d?.reactions?.summary?.total_count;
        const comments = d?.comments?.summary?.total_count;
        const shares = d?.shares?.count;
        const engagement = {
          reactions: typeof reactions === "number" ? reactions : null,
          comments: typeof comments === "number" ? comments : null,
          shares: typeof shares === "number" ? shares : null,
          total: null,
          available: false
        };
        engagement.available = [engagement.reactions, engagement.comments, engagement.shares].some(v => v !== null);
        if (engagement.available) {
          engagement.total = [engagement.reactions, engagement.comments, engagement.shares]
            .filter(v => typeof v === "number")
            .reduce((sum, v) => sum + v, 0);
          enrichedCount++;
        }
        post.engagement = engagement;
      } catch (postError) {
        console.error("POST ENGAGEMENT FAILED:", post.id, postError.meta || postError);
        post.engagement = { reactions: null, comments: null, shares: null, total: null, available: false };
      }
    }

    console.log("POST ENGAGEMENT SUMMARY:", {
      posts: result.posts.length,
      enriched: enrichedCount,
      available: result.posts.filter(p => p?.engagement?.available).length
    });

    result.diagnostic = buildDiagnostic(result.insights, result.posts, result.page, { niche, goal, timezone });
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
  // If engagement was fetched separately in the fallback path, use that real data.
  if (post?.engagement && typeof post.engagement === "object") {
    const reactions = typeof post.engagement.reactions === "number" ? post.engagement.reactions : null;
    const comments = typeof post.engagement.comments === "number" ? post.engagement.comments : null;
    const shares = typeof post.engagement.shares === "number" ? post.engagement.shares : null;
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

function buildDiagnostic(insights, posts = [], pageInfo = {}, prefs = {}) {
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
      engagementCount: v.engagementCount,
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

  const dominantCategory = [...categoryStats].sort((a,b) => b.count - a.count)[0] || null;
  const dominantShare = dominantCategory && analyzedPosts.length ? dominantCategory.count / analyzedPosts.length : 0;

  if (bestCategory && bestCategory.avgEngagement !== null) strengths.push(`În eșantionul analizat, „${bestCategory.category}” are cea mai mare medie de interacțiuni: ${Math.round(bestCategory.avgEngagement).toLocaleString("ro-RO")} / postare.`);
  if (postsWithEngagement && analyzedPosts.length) strengths.push(`${postsWithEngagement} din ${analyzedPosts.length} postări au primit cel puțin o interacțiune publică.`);
  if (conversationPosts) strengths.push(`${conversationPosts} postări au generat comentarii sau distribuiri — acestea sunt semnale mai puternice de conversație decât simpla reacție.`);

  if (weakestCategory && avgEngagement > 0 && weakestCategory.avgEngagement < avgEngagement * 0.7) {
    const pct = Math.round((1 - weakestCategory.avgEngagement / avgEngagement) * 100);
    blockers.push(`„${weakestCategory.category}” este cu aproximativ ${pct}% sub media de interacțiuni a paginii în acest eșantion. Merită testat alt unghi, hook sau format înainte să continui aceeași abordare.`);
  }
  if (!conversationPosts && engagementPosts.length) blockers.push("Postările analizate generează puține comentarii sau distribuiri. Testează CTA-uri care cer un răspuns simplu: o alegere, o opinie sau o experiență.");
  if (!engagementPosts.length && analyzedPosts.length) blockers.push("Meta nu a furnizat engagement pentru postările analizate. Nu îl tratăm ca 0, deci nu pretindem că știm ce tip de postare funcționează cel mai bine.");
  if (dominantCategory && dominantShare >= 0.5) blockers.push(`„${dominantCategory.category}” reprezintă aproximativ ${Math.round(dominantShare * 100)}% din postările analizate. Asta poate limita ce putem învăța despre ce preferă publicul; merită testate intenționat și alte formate.`);
  if (analyzedPosts.length < 20) blockers.push("Eșantionul este mai mic de 20 de postări, deci concluziile despre ce prinde cel mai bine sunt încă orientative.");

  if (bestCategory) priorities.push(`Repetă „${bestCategory.category}” în 2–3 variante noi și schimbă hook-ul, nu doar imaginea. Compară rezultatele după fiecare postare.`);
  else if (dominantCategory) priorities.push(`Ai multe postări de tip „${dominantCategory.category}”. În următoarele 7 zile testează intenționat cel puțin 2 formate diferite pentru a afla ce provoacă reacții.`);
  if (!conversationPosts && engagementPosts.length) priorities.push("Adaugă 2 postări cu CTA conversațional: o întrebare concretă și o alegere între două variante.");
  else if (weakestCategory && weakestCategory.category !== bestCategory?.category) priorities.push(`Schimbă abordarea pentru „${weakestCategory.category}”: alt hook, alt format sau alt CTA, apoi compară cu media paginii.`);
  if (priorities.length < 3) priorities.push("Alege un singur obiectiv pentru următoarele 7 zile și urmărește același tip de rezultat de la o postare la alta.");

  const plan = bestCategory ? [
    `Ziua 1: publică „${bestCategory.category}” într-o variantă nouă și păstrează un singur obiectiv.`,
    "Ziua 2: publică un Reel/video scurt cu un hook clar în primele secunde.",
    "Ziua 3: arată partea din spatele produsului, procesului sau serviciului.",
    "Ziua 4: pune o întrebare la care se poate răspunde în câteva cuvinte.",
    "Ziua 5: prezintă oferta/produsul, dar cu un singur CTA clar.",
    "Ziua 6: repetă unghiul care a primit cele mai bune semnale și schimbă doar hook-ul.",
    "Ziua 7: compară postările și notează ce merită repetat săptămâna următoare."
  ] : [
    "Ziua 1: publică o postare de prezentare cu un hook clar și un singur obiectiv.",
    "Ziua 2: testează un Reel/video scurt.",
    "Ziua 3: arată procesul sau partea din culise.",
    "Ziua 4: publică o întrebare sau o alegere pentru comunitate.",
    "Ziua 5: prezintă un produs/serviciu cu un singur CTA.",
    "Ziua 6: repetă formatul care a primit cele mai bune semnale disponibile.",
    "Ziua 7: compară rezultatele și păstrează ce merită testat din nou."
  ];

  const topPosts = [...engagementPosts].sort((a,b) => b.engagement.total - a.engagement.total).slice(0,5);
  const topPost = topPosts[0] || null;
  const audienceInsights = buildAudienceInsights({ analyzedPosts, engagementPosts, categoryStats, bestCategory, weakestCategory, avgEngagement, topPosts: [...engagementPosts].sort((a,b) => b.engagement.total - a.engagement.total).slice(0,5) });
  const contentPlan = generateContentPlan({ niche: prefs.niche, goal: prefs.goal, bestCategory, topPost });
  const nextPosts = generateNextPosts({ niche: prefs.niche, goal: prefs.goal, topPost, pageInfo, bestCategory, avgEngagement });
  const repurposedPosts = generateRepurposedPosts({ topPost });

  const pageAvg = avgEngagement || 0;
  const topTotal = topPost?.engagement?.total ?? null;
  const topPostAnalysis = topPost ? {
    engagement: topTotal,
    vsPageAverage: pageAvg > 0 && topTotal !== null ? Math.round((topTotal / pageAvg) * 10) / 10 : null,
    category: classifyPost(topPost),
    reactions: topPost.engagement.reactions,
    comments: topPost.engagement.comments,
    shares: topPost.engagement.shares,
    format: String(topPost.type || topPost.status_type || "Postare"),
    hasQuestion: /\\?|\\b(cum|ce|care|alege|spune-mi|părere|parere)\\b/i.test(String(topPost.message || "")),
    hasSalesSignal: /\\b(comand|comenzi|preț|pret|ofert|disponibil|livrare|personalizat|rezerv)/i.test(String(topPost.message || "")),
    message: String(topPost.message || "").replace(/\\s+/g, " ").trim().slice(0, 500),
    permalink_url: topPost.permalink_url || null
  } : null;


  const postingTimes = buildPostingTimeInsights({
    analyzedPosts,
    engagementPosts,
    timezone: prefs.timezone
  });

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
    contentPlan,
    postingTimes,
    audienceInsights,
    topPostAnalysis,
    nextPosts,
    repurposedPosts,
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


function buildPostingTimeInsights({ analyzedPosts = [], engagementPosts = [], timezone }) {
  const tz = typeof timezone === "string" && timezone.trim()
    ? timezone.trim()
    : "UTC";

  const weekdayNames = ["Duminică","Luni","Marți","Miercuri","Joi","Vineri","Sâmbătă"];
  const slots = {};
  const days = {};

  const getParts = (date) => {
    try {
      const parts = new Intl.DateTimeFormat("en-GB", {
        timeZone: tz,
        weekday: "short",
        hour: "2-digit",
        hour12: false
      }).formatToParts(date);
      const map = Object.fromEntries(parts.map(p => [p.type, p.value]));
      const weekdayMap = { Sun:0, Mon:1, Tue:2, Wed:3, Thu:4, Fri:5, Sat:6 };
      const weekday = weekdayMap[map.weekday];
      let hour = Number(map.hour);
      if (hour === 24) hour = 0;
      if (!Number.isInteger(weekday) || !Number.isFinite(hour)) return null;
      return { weekday, hour };
    } catch {
      return null;
    }
  };

  engagementPosts.forEach(post => {
    if (!post?.created_time || !post?.engagement?.available || post.engagement.total === null) return;
    const parts = getParts(new Date(post.created_time));
    if (!parts) return;

    const slotStart = Math.floor(parts.hour / 2) * 2;
    const key = parts.weekday + "-" + slotStart;
    if (!slots[key]) slots[key] = {
      weekday: parts.weekday,
      start: slotStart,
      end: slotStart + 2,
      count: 0,
      total: 0
    };
    slots[key].count++;
    slots[key].total += post.engagement.total;

    const dayKey = String(parts.weekday);
    if (!days[dayKey]) days[dayKey] = { weekday: parts.weekday, count: 0, total: 0 };
    days[dayKey].count++;
    days[dayKey].total += post.engagement.total;
  });

  const slotRows = Object.values(slots)
    .filter(x => x.count >= 2)
    .map(x => ({
      weekday: weekdayNames[x.weekday],
      weekdayIndex: x.weekday,
      start: x.start,
      end: x.end,
      count: x.count,
      avgEngagement: x.total / x.count
    }))
    .sort((a,b) => b.avgEngagement - a.avgEngagement);

  const dayRows = Object.values(days)
    .filter(x => x.count >= 2)
    .map(x => ({
      weekday: weekdayNames[x.weekday],
      weekdayIndex: x.weekday,
      count: x.count,
      avgEngagement: x.total / x.count
    }))
    .sort((a,b) => b.avgEngagement - a.avgEngagement);

  const engagementCount = engagementPosts.length;

  if (!engagementCount || !slotRows.length) {
    return {
      available: false,
      timezone: tz,
      title: "Când să postezi?",
      summary: "Nu avem încă suficiente postări cu engagement disponibil în intervale comparabile pentru a recomanda responsabil o oră.",
      recommendations: [],
      bestDays: dayRows.slice(0,3),
      sampleSize: engagementCount,
      confidence: engagementCount >= 10 ? "medie" : "scăzută"
    };
  }

  const recommendations = slotRows.slice(0, 3).map((x, i) => ({
    rank: i + 1,
    weekday: x.weekday,
    start: x.start,
    end: x.end,
    label: String(x.start).padStart(2,"0") + ":00–" + String(x.end).padStart(2,"0") + ":00",
    avgEngagement: Math.round(x.avgEngagement * 10) / 10,
    posts: x.count
  }));

  const best = recommendations[0];
  const confidence =
    engagementCount >= 20 ? "ridicată" :
    engagementCount >= 10 ? "medie" : "orientativă";

  return {
    available: true,
    timezone: tz,
    title: "Când să postezi?",
    summary: "Intervalele de mai jos sunt calculate din performanța reală a postărilor analizate. Nu sunt ore universale și nu reprezintă activitatea live a urmăritorilor.",
    recommendations,
    bestDays: dayRows.slice(0,3),
    sampleSize: engagementCount,
    confidence
  };
}

function buildAudienceInsights({ analyzedPosts, engagementPosts, categoryStats, bestCategory, weakestCategory, avgEngagement, topPosts }) {
  if (!engagementPosts.length) return {
    available:false,
    title:"Ce vrea publicul meu?",
    summary:"Nu avem suficiente date publice de engagement pentru a identifica tipare fără să ghicim.",
    signals:[],
    actions:["Publică câteva formate diferite și revino după ce apar suficiente interacțiuni.","Nu tratăm lipsa engagement-ului ca 0."],
    confidence:"scăzută"
  };

  const conversation=engagementPosts.filter(p=>(p.engagement.comments??0)>0||(p.engagement.shares??0)>0);
  const questionPosts=engagementPosts.filter(p=>/\?|\b(cum|ce|care|alege|spune-mi|părere|parere|voi ce)\b/i.test(String(p.message||"")));
  const nonQuestion=engagementPosts.filter(p=>!questionPosts.includes(p));
  const questionAvg=questionPosts.length?questionPosts.reduce((s,p)=>s+p.engagement.total,0)/questionPosts.length:null;
  const nonQuestionAvg=nonQuestion.length?nonQuestion.reduce((s,p)=>s+p.engagement.total,0)/nonQuestion.length:null;
  const signals=[],actions=[],evidence=[];

  if(bestCategory){
    signals.push({type:"atractie",title:"Publicul reacționează cel mai bine la "+bestCategory.category,detail:"Această categorie are cea mai mare medie dintre categoriile cu cel puțin 2 postări cu engagement disponibil.",value:Math.round(bestCategory.avgEngagement)});
    evidence.push(bestCategory.category+": "+Math.round(bestCategory.avgEngagement)+" interacțiuni medii/postare");
    actions.push("Repetă "+bestCategory.category+" de 2 ori în următoarele 7 zile, cu exemple și hook-uri diferite.");
  }

  if(questionAvg!==null&&nonQuestionAvg!==null&&questionPosts.length>=2&&nonQuestion.length>=2){
    if(questionAvg>nonQuestionAvg){
      signals.push({type:"conversatie",title:"Postările care cer un răspuns au primit mai mult engagement",detail:"În eșantionul analizat, postările cu întrebări sau alegeri au avut o medie mai mare. Este o asociere, nu dovada că întrebarea a cauzat rezultatul.",value:Math.round(questionAvg)});
      evidence.push("Cu întrebare: "+Math.round(questionAvg)+" vs. fără: "+Math.round(nonQuestionAvg)+" interacțiuni medii");
      actions.push("Testează o postare cu o întrebare simplă sau o alegere A/B.");
    } else {
      signals.push({type:"conversatie",title:"Întrebările nu au depășit clar restul conținutului",detail:"Datele actuale nu arată un avantaj clar pentru postările cu întrebări. Nu forțăm CTA-uri conversaționale fără semnal.",value:Math.round(questionAvg)});
      evidence.push("Cu întrebare: "+Math.round(questionAvg)+" vs. fără: "+Math.round(nonQuestionAvg)+" interacțiuni medii");
    }
  } else {
    signals.push({type:"conversatie",title:conversation.length?"Există semnale de conversație, dar nu suficiente pentru o comparație sigură":"Conversația este încă un semnal slab",detail:conversation.length?"Unele postări au primit comentarii sau distribuiri, dar eșantionul nu permite o comparație solidă.":"Postările analizate au primit puține sau deloc comentarii ori distribuiri.",value:conversation.length});
    actions.push(conversation.length?"Repetă o temă care a generat comentarii și schimbă doar hook-ul.":"Testează o postare A/B care cere un răspuns foarte simplu.");
  }

  if(topPosts.length){
    const topCategories=[...new Set(topPosts.slice(0,3).map(p=>classifyPost(p)))];
    signals.push({type:"top",title:"Cele mai puternice semnale vin din "+topCategories.join(", "),detail:"Primele postări sunt ordonate după interacțiunile publice disponibile.",value:topPosts[0].engagement.total});
    evidence.push("Top post: "+String(topPosts[0].message||"").replace(/\s+/g," ").slice(0,120));
  }

  if(weakestCategory&&bestCategory&&weakestCategory.category!==bestCategory.category){
    const gap=avgEngagement>0?Math.round((1-weakestCategory.avgEngagement/avgEngagement)*100):null;
    signals.push({type:"frictiune",title:"Un tip de conținut nu ține pasul cu restul",detail:"„"+weakestCategory.category+"” are o medie mai mică decât media paginii. Asta indică un format de testat diferit, nu că publicul îl respinge definitiv.",value:gap!==null?gap+"% sub media paginii":null});
    actions.push("Nu abandona "+weakestCategory.category+" după un singur rezultat; schimbă hook-ul sau formatul și testează din nou.");
  }

  const confidence=engagementPosts.length>=20?"ridicată":engagementPosts.length>=10?"medie":"orientativă";
  const summary=bestCategory?"Semnalul principal din ultimele 28 de zile este „"+bestCategory.category+"”. Publicul a reacționat mai mult la acest tip de conținut decât la celelalte categorii comparabile.":"Avem câteva semnale de engagement, dar nu suficient de clare pentru o concluzie puternică.";
  return {available:true,title:"Ce vrea publicul meu?",summary,signals:signals.slice(0,4),actions:[...new Set(actions)].slice(0,4),evidence,confidence};
}

function generateNextPosts({ niche, goal, topPost, pageInfo, bestCategory, avgEngagement }) {
  if (!topPost) return [];
  const base = String(topPost.message || "").replace(/\s+/g, " ").trim();
  const category = classifyPost(topPost);
  const pageName = String(pageInfo?.name || "pagina ta").trim();
  const topEngagement = Number(topPost?.engagement?.total || 0);
  const ratio = avgEngagement > 0 ? Math.round((topEngagement / avgEngagement) * 10) / 10 : null;
  const evidence = ratio ? "Postarea a avut " + ratio + "× media de interacțiuni a paginii." : "Postarea are cel mai bun semnal de engagement dintre postările comparabile.";

  const goalText = String(goal || "").toLowerCase();
  const actionCta = goalText.includes("comenzi")
    ? "Dacă vrei detalii pentru o comandă, scrie-mi în privat."
    : goalText.includes("comentarii")
      ? "Tu cum ai alege? Spune-mi în comentarii."
      : goalText.includes("urmăritori")
        ? "Dacă vrei să vezi și următoarea parte, urmărește pagina."
        : "Tu ce variantă ai alege? Spune-mi în comentarii.";

  const newPosts = [
    {
      title: "1 · Continuă semnalul câștigător",
      objective: "Confirmă dacă tema care a funcționat poate produce încă o postare bună.",
      reason: evidence + " Păstrăm tema „" + category + "”, dar nu copiem postarea.",
      hook: "Postarea despre „" + base.slice(0, 95) + (base.length > 95 ? "…" : "") + "” a atras atenția. Dar partea interesantă abia acum începe.",
      caption: "Ai văzut deja " + (base ? "povestea aceasta" : "ideea aceasta") + ". Acum vreau să-ți arăt o altă perspectivă asupra ei.\n\nÎn loc să repet exact ce am postat, aleg un exemplu nou și îți arăt detaliul care face diferența.\n\nUneori nu produsul sau subiectul în sine este cel care oprește scroll-ul, ci felul în care îl prezentăm.\n\n" + actionCta,
      cta: actionCta,
      evidence
    },
    {
      title: "2 · Testează ce lipsește",
      objective: topPost.engagement.comments === 0 ? "Testează dacă interesul din reacții poate deveni conversație." : "Testează dacă tema performantă poate genera și distribuiri sau recomandări.",
      reason: topPost.engagement.comments === 0
        ? "Postarea performantă a avut reacții, dar nu a avut comentarii disponibile. Următorul test schimbă intenționat CTA-ul."
        : "Postarea performantă a generat deja conversație. Următorul test urmărește un comportament diferit: distribuirea.",
      hook: topPost.engagement.comments === 0 ? "Am nevoie de părerea ta înainte să aleg următoarea variantă." : "Pe cine ai trimite să vadă asta?",
      caption: topPost.engagement.comments === 0
        ? "Pornesc de la aceeași temă care a funcționat pe " + pageName + ", dar de data aceasta nu vreau doar să o vezi. Vreau să alegi.\n\nVarianta A sau varianta B? Spune-mi ce ai alege și, mai important, de ce.\n\nRăspunsurile voastre mă ajută să aleg ce dezvolt mai departe."
        : "Tema aceasta a atras deja atenție. Acum vreau să aflu dacă este și genul de conținut pe care l-ai trimite unei persoane care ar avea nevoie de el.\n\nDacă îți vine cineva în minte, trimite-i postarea. Iar dacă ai o idee pentru următoarea variantă, spune-mi în comentarii.",
      cta: topPost.engagement.comments === 0 ? "Alege A sau B și spune-mi de ce." : "Trimite postarea unei persoane pentru care ar fi utilă.",
      evidence
    },
    {
      title: "3 · Transformă interesul în acțiune",
      objective: "Leagă tema performantă de obiectivul ales pentru pagină.",
      reason: "Folosim tema care a atras deja atenție, dar introducem un pas clar spre obiectivul „" + (goal || "engagement") + "”.",
      hook: goalText.includes("comenzi")
        ? "Ți-a plăcut ideea? Uite cum poate deveni o comandă personalizată."
        : "Dacă ți-a atras atenția, uite ce poți face mai departe.",
      caption: "Tema aceasta a funcționat deja pe această pagină, așa că nu o abandonăm. O ducem mai aproape de ceea ce poate face omul concret.\n\nÎți arăt ce variantă este disponibilă, pentru cine se potrivește și ce poate fi personalizat. Fără să complicăm lucrurile.\n\n" + (goalText.includes("comenzi")
        ? "Dacă ai o ocazie sau un produs anume în minte, spune-mi ce cauți și îți spun ce variante pot realiza."
        : goalText.includes("urmăritori")
          ? "Dacă vrei să vezi și următoarele exemple din aceeași temă, urmărește pagina."
          : "Dacă ți se potrivește tema, spune-mi ce ai vrea să vezi în continuare."),
      cta: goalText.includes("comenzi") ? "Scrie-mi DETALII și îți spun variantele disponibile." : actionCta,
      evidence
    }
  ];

  return newPosts;
}

function generateRepurposedPosts({ topPost }) {
  if (!topPost) return [];
  const base = String(topPost.message || "").replace(/\s+/g, " ").trim();
  const hook = base ? base.slice(0, 140) : "Ideea postării care a funcționat";
  return [
    {
      title: "1 · Carusel",
      format: "5 slide-uri · text gata de pus pe design",
      slides: [
        "SLIDE 1 · " + hook,
        "SLIDE 2 · „De ce merită să te oprești aici?” — explică ideea principală a postării în 1–2 propoziții.",
        "SLIDE 3 · „Detaliul pe care poate nu l-ai observat” — arată partea concretă care a făcut postarea interesantă.",
        "SLIDE 4 · „Și dacă ai face asta diferit?” — adaugă o perspectivă nouă, fără să schimbi tema originală.",
        "SLIDE 5 · „Tu ce alegi?” — cere un răspuns simplu sau invită la salvare."
      ],
      caption: "Aceeași idee care a funcționat, prezentată într-un format pe care oamenii îl pot parcurge și salva.",
      cta: "Salvează caruselul dacă vrei să revii la idee."
    },
    {
      title: "2 · Reel",
      format: "15 secunde · scenariu complet",
      frames: [
        "0–2s · TEXT PE ECRAN: „" + hook.slice(0, 85) + "”",
        "2–5s · VIDEO: arată produsul / rezultatul / momentul central al postării originale.",
        "5–9s · TEXT PE ECRAN: „Detaliul pe care nu îl vezi din prima.” + arată un close-up.",
        "9–12s · VOICE-OVER: explică într-o propoziție de ce merită atenție.",
        "12–15s · TEXT PE ECRAN: „Tu ce ai alege?” + CTA."
      ],
      caption: "Postarea care a mers nu trebuie să rămână o singură postare. Aceeași idee poate fi consumată și în video.",
      cta: "Dacă vrei partea a doua, scrie DA."
    },
    {
      title: "3 · Stories",
      format: "4 cadre · text gata de publicat",
      stories: [
        "STORY 1: „Ții minte postarea aceasta? A fost una dintre cele mai apreciate de pe pagină.”",
        "STORY 2: „Ideea ei, pe scurt: " + hook.slice(0, 120) + "”",
        "STORY 3: „Acum vreau să știu: ai prefera varianta A sau B?” + sticker POLL.",
        "STORY 4: „Vrei să continui tema aceasta? Scrie-mi DA / răspunde la Story.”"
      ],
      caption: "Stories mută aceeași idee din feed într-o conversație mai directă.",
      cta: "Folosește poll-ul pentru a testa rapid reacția."
    }
  ];
}

function generateContentPlan({ niche, goal, bestCategory, topPost }) {
  const n = String(niche || "Other").toLowerCase();
  let key = "other";
  if (n.includes("handmade")) key = "handmade";
  else if (n.includes("wedding")) key = "wedding";
  else if (n.includes("botez") || n.includes("baby")) key = "baby";
  else if (n.includes("cadouri")) key = "gifts";
  else if (n.includes("beauty")) key = "beauty";
  else if (n.includes("food")) key = "food";
  else if (n.includes("home")) key = "home";
  else if (n.includes("servicii")) key = "services";

  const common = {
    handmade: [
      ["ZIUA 1 · CARUSEL", "HOOK: Nu ai nevoie de inca un produs. Ai nevoie de unul care sa aiba povestea ta.", "Arata 3 creatii reale si explica pe scurt cui i se potriveste fiecare.", "CTA: Care dintre cele 3 ti s-ar potrivi? Scrie 1, 2 sau 3."],
      ["ZIUA 2 · REEL", "HOOK: Uite ce nu vezi atunci cand primesti o creatie handmade gata ambalata.", "Filmeaza 5-7 cadre din proces: materiale, personalizare, detaliu, ambalare, produs final.", "CTA: Scrie-mi ce produs ai vrea sa vezi in urmatorul Reel."],
      ["ZIUA 3 · EDUCATIV", "HOOK: 3 greseli pe care le faci cand alegi un produs personalizat.", "Explica 3 greseli reale din nisa si arata ce alegere este mai buna.", "CTA: Salveaza postarea pentru urmatoarea comanda."],
      ["ZIUA 4 · CONVERSATIE", "HOOK: Am nevoie de ajutorul vostru: A sau B?", "Arata doua modele, culori sau finisaje reale.", "CTA: Voteaza A sau B si spune de ce."],
      ["ZIUA 5 · VANZARE", "HOOK: Daca ai nevoie de un cadou care sa nu para ales in graba, uita-te la acesta.", "Prezinta un produs real, ce poate fi personalizat, pretul si timpul de executie.", "CTA: Scrie-mi DETALII si iti spun variantele disponibile."],
      ["ZIUA 6 · DOVADA", "HOOK: Momentul in care vezi produsul final si iti dai seama ca toate detaliile au meritat.", "Arata o comanda finalizata sau un feedback real. Nu inventa testimoniale.", "CTA: Spune-mi ocazia si iti propun variante."],
      ["ZIUA 7 · REPETA CE A DAT SEMNAL", "HOOK: Tema care a atras cele mai multe reactii merita o continuare.", "Reia categoria cu cea mai buna medie din analiza, dar schimba hook-ul si exemplul.", "CTA: Scrie DA daca vrei partea a doua."]
    ],
    wedding: [
      ["ZIUA 1 · CARUSEL", "HOOK: 3 detalii mici care pot face o nunta sa para cu adevarat a voastra.", "Arata 3 produse reale din oferta si explica rolul fiecaruia.", "CTA: Care detaliu ti-ar placea la nunta ta? Scrie 1, 2 sau 3."],
      ["ZIUA 2 · REEL", "HOOK: De la o coala simpla la un detaliu care ajunge pe masa mirilor.", "Filmeaza procesul unui produs de nunta pana la rezultatul final.", "CTA: Salveaza ideea si trimite-o persoanei cu care iei deciziile."],
      ["ZIUA 3 · EDUCATIV", "HOOK: Nu comanda invitatiile inainte sa verifici aceste 3 lucruri.", "Explica textul, cantitatea, termenul si potrivirea cu tema nuntii.", "CTA: Salveaza postarea pentru momentul comenzii."],
      ["ZIUA 4 · CONVERSATIE", "HOOK: Elegant sau romantic? Ce ati alege?", "Arata doua variante reale din portofoliu.", "CTA: Scrie ELEGANT sau ROMANTIC."],
      ["ZIUA 5 · VANZARE", "HOOK: Daca ai stabilit deja data nuntii, acum este momentul pentru detalii.", "Prezinta un produs sau serviciu concret, ce include si cum se comanda.", "CTA: Trimite-mi data nuntii si iti spun variantele disponibile."],
      ["ZIUA 6 · PORTOFOLIU", "HOOK: Asa arata cand toate detaliile unei nunti vorbesc aceeasi limba.", "Prezinta 4-6 produse din aceeasi tema sau culoare.", "CTA: Salveaza combinatia daca acesta este stilul pe care il cauti."],
      ["ZIUA 7 · CONTINUARE", "HOOK: Varianta preferata merita sa o vedem completa.", "Continua formatul care a obtinut cele mai bune semnale si schimba unghiul.", "CTA: Ce element vrei sa adaug in partea a doua?"]
    ],
    baby: [
      ["ZIUA 1 · CARUSEL", "HOOK: Botezul trece intr-o zi. Detaliile raman in fotografii ani de zile.", "Arata 3 produse relevante si explica rolul fiecaruia.", "CTA: Care detaliu ti se pare cel mai important? 1, 2 sau 3."],
      ["ZIUA 2 · REEL", "HOOK: Asa se transforma un produs simplu intr-un detaliu personalizat pentru bebe.", "Filmeaza personalizarea de la inceput pana la produsul final.", "CTA: Urmareste pagina pentru urmatoarea transformare."],
      ["ZIUA 3 · EDUCATIV", "HOOK: Daca pregatesti botezul, nu lasa aceste 3 lucruri pe ultima saptamana.", "Explica termenele, cantitatile si personalizarea.", "CTA: Salveaza lista si verifica ce ai deja pregatit."],
      ["ZIUA 4 · CONVERSATIE", "HOOK: Pentru botez: alb si auriu sau pastel?", "Arata doua variante reale.", "CTA: Scrie ALB/AURIU sau PASTEL."],
      ["ZIUA 5 · VANZARE", "HOOK: Daca vrei ca botezul sa aiba un fir vizual de la primul pana la ultimul detaliu.", "Prezinta un set sau produs real si ce poate fi personalizat.", "CTA: Scrie-mi BOTEZ si iti trimit variantele."],
      ["ZIUA 6 · DOVADA", "HOOK: Detaliul pe care parintii il observa abia cand primesc comanda.", "Arata ambalarea, personalizarea sau un feedback real.", "CTA: Spune-mi luna botezului si iti spun ce poti rezerva."],
      ["ZIUA 7 · REPETA", "HOOK: Varianta care v-a placut merita sa o ducem un pas mai departe.", "Creeaza o noua varianta pornind de la tema cu cele mai bune semnale.", "CTA: Scrie PARTEA 2 daca vrei continuarea."]
    ],
    gifts: [
      ["ZIUA 1 · CARUSEL", "HOOK: Cel mai greu cadou nu este cel scump. Este cel care pare ales pentru oricine.", "Prezinta 3 idei pentru 3 tipuri diferite de persoane.", "CTA: Spune-mi pentru cine cauti cadoul."],
      ["ZIUA 2 · REEL", "HOOK: Iti arat cadoul inainte sa ajunga la persoana care il va primi.", "Filmeaza produsul, personalizarea si ambalarea.", "CTA: Scrie-mi CADOU si iti propun idei."],
      ["ZIUA 3 · EDUCATIV", "HOOK: Cum alegi un cadou personalizat fara sa dai gres?", "Explica 3 intrebari: pentru cine, cu ce ocazie, ce stil are.", "CTA: Salveaza postarea pentru urmatoarea ocazie."],
      ["ZIUA 4 · CONVERSATIE", "HOOK: Ai prefera un cadou util sau unul sentimental?", "Arata cate un exemplu real.", "CTA: UTIL sau SENTIMENTAL?"],
      ["ZIUA 5 · VANZARE", "HOOK: Daca ai o persoana imposibil de cumparat, incepe de aici.", "Prezinta un produs real si ocaziile pentru care este potrivit.", "CTA: Scrie CADOU si spune-mi ocazia."],
      ["ZIUA 6 · DOVADA", "HOOK: Nu produsul este partea cea mai frumoasa. Reactia celui care il primeste este.", "Foloseste continut real sau feedback real.", "CTA: Spune-mi ocazia si iti recomand o varianta."],
      ["ZIUA 7 · REPETA", "HOOK: Unul dintre produsele care a atras reactii merita o idee noua.", "Creeaza o noua varianta a produsului care a functionat.", "CTA: Ce varianta ai vrea sa vezi?"]
    ],
    beauty: [
      ["ZIUA 1 · EDUCATIV", "HOOK: Daca rezultatul tau nu rezista cum vrei, s-ar putea sa faci aceasta greseala.", "Explica o problema frecventa din serviciul tau si arata solutia.", "CTA: Spune-mi daca ti se intampla."],
      ["ZIUA 2 · REEL", "HOOK: Uite diferenta pe care o face un profesionist in primele 30 de secunde.", "Arata procesul sau before/after real, cu acordul clientului.", "CTA: Scrie PROGRAMARE pentru disponibilitate."],
      ["ZIUA 3 · MIT", "HOOK: 3 lucruri pe care probabil le faci gresit fara sa-ti dai seama.", "Explica 3 greseli concrete din nisa.", "CTA: Care te-a surprins? 1, 2 sau 3."],
      ["ZIUA 4 · CONVERSATIE", "HOOK: Ce ai alege pentru urmatoarea ta programare?", "Arata doua rezultate sau servicii reale.", "CTA: A sau B?"],
      ["ZIUA 5 · SERVICIU", "HOOK: Daca vrei un rezultat vizibil, acesta este serviciul pe care l-as lua in calcul.", "Explica pentru cine este serviciul, ce include si cum se face programarea.", "CTA: Scrie PROGRAMARE."],
      ["ZIUA 6 · DOVADA", "HOOK: Rezultatul real spune mai mult decat 10 promisiuni.", "Arata un rezultat real si explica procesul.", "CTA: Vrei sa vedem daca este potrivit pentru tine? Scrie-mi."],
      ["ZIUA 7 · FAQ", "HOOK: Intrebarea pe care o primesc cel mai des este.", "Raspunde unei intrebari reale primite de la clienti.", "CTA: Lasa urmatoarea intrebare in comentarii."]
    ],
    food: [
      ["ZIUA 1 · CARUSEL", "HOOK: Daca iti place acest produs, trebuie sa vezi cum il pregatim.", "Arata ingredientele, procesul si produsul final.", "CTA: Ai incerca? DA sau NU."],
      ["ZIUA 2 · REEL", "HOOK: Sunetul pe care il auzi cand apare partea cea mai buna.", "Filmeaza cadre apetisante din preparare si produsul final.", "CTA: Trimite Reel-ul persoanei cu care ai imparti portia."],
      ["ZIUA 3 · EDUCATIV", "HOOK: De ce nu iese acasa la fel? Iata secretul.", "Explica un pas concret al prepararii.", "CTA: Salveaza pentru data viitoare."],
      ["ZIUA 4 · CONVERSATIE", "HOOK: Cu ce ai incepe: A sau B?", "Arata doua produse reale.", "CTA: Voteaza A sau B."],
      ["ZIUA 5 · VANZARE", "HOOK: Daca ti-am facut pofta, partea buna este ca il poti comanda.", "Prezinta produsul, optiunile, pretul si modul de comanda.", "CTA: Scrie COMANDA."],
      ["ZIUA 6 · DOVADA", "HOOK: Ce spun clientii dupa prima imbucatura.", "Foloseste feedback real, fara citate inventate.", "CTA: Vrei sa incerci? Scrie-mi."],
      ["ZIUA 7 · REPETA", "HOOK: Produsul care v-a facut sa opriti scroll-ul merita o noua versiune.", "Reia produsul sau formatul cu un unghi nou.", "CTA: Ce varianta ai testa?"]
    ],
    home: [
      ["ZIUA 1 · INSPIRATIE", "HOOK: Casa ta nu are nevoie de mai multe obiecte. Are nevoie de detalii care spun ceva despre tine.", "Arata 3 produse in contexte reale.", "CTA: Pe care l-ai pune la tine acasa: 1, 2 sau 3?"],
      ["ZIUA 2 · REEL", "HOOK: Uite cum se schimba un colt al casei in cateva secunde.", "Fa un before/after cu produsul tau.", "CTA: Salveaza ideea pentru urmatoarea schimbare de decor."],
      ["ZIUA 3 · EDUCATIV", "HOOK: 3 greseli care fac un decor sa para incarcat.", "Explica 3 principii simple si arata exemple.", "CTA: Salveaza postarea."],
      ["ZIUA 4 · CONVERSATIE", "HOOK: Minimalist sau cozy?", "Arata doua stiluri reale.", "CTA: Scrie stilul tau in comentarii."],
      ["ZIUA 5 · VANZARE", "HOOK: Daca ai un colt care pare ca ii lipseste ceva, incepe cu acest detaliu.", "Prezinta un produs si beneficiul lui.", "CTA: Scrie DETALII."],
      ["ZIUA 6 · DOVADA", "HOOK: Asa arata produsul in casa unui client.", "Foloseste continut real trimis de client, cu acordul lui.", "CTA: Trimite-mi o poza si iti spun cum s-ar potrivi."],
      ["ZIUA 7 · REPETA", "HOOK: Varianta care a atras cele mai bune reactii primeste o continuare.", "Reia stilul sau formatul cu o noua combinatie.", "CTA: Ce combinatie vrei sa vezi?"]
    ],
    services: [
      ["ZIUA 1 · PROBLEMA", "HOOK: Daca pierzi timp cu problema pe care o rezolv eu, exista o varianta mai simpla.", "Descrie problema clientului ideal si explica solutia serviciului.", "CTA: Scrie SOLUTIE si iti explic cum functioneaza."],
      ["ZIUA 2 · REEL", "HOOK: Asta se intampla in spatele unui rezultat bun.", "Arata procesul, instrumentele si pasii principali.", "CTA: Urmareste pagina pentru mai multe exemple."],
      ["ZIUA 3 · EDUCATIV", "HOOK: 3 semne ca ai nevoie de serviciul meu.", "Arata 3 probleme concrete pe care clientul le poate recunoaste.", "CTA: Care dintre ele te descrie?"],
      ["ZIUA 4 · CONVERSATIE", "HOOK: Care este cea mai mare problema pe care ai vrea sa o rezolvi acum?", "Invita publicul sa descrie problema fara sa vinzi direct.", "CTA: Scrie problema in comentarii."],
      ["ZIUA 5 · OFERTA", "HOOK: Daca vrei rezultatul dorit, uite exact ce primesti.", "Prezinta serviciul, procesul, ce include si urmatorul pas.", "CTA: Scrie INFO pentru detalii."],
      ["ZIUA 6 · DOVADA", "HOOK: Inainte si dupa: ce s-a schimbat dupa ce am lucrat impreuna.", "Foloseste un caz real si date reale.", "CTA: Vrei sa vedem daca te pot ajuta? Scrie-mi."],
      ["ZIUA 7 · FAQ", "HOOK: Daca te gandesti sa apelezi la serviciul meu, probabil ai aceasta intrebare.", "Raspunde unei intrebari reale primite de la clienti.", "CTA: Lasa-mi urmatoarea intrebare."]
    ],
    other: [
      ["ZIUA 1 · PROBLEMA", "HOOK: Daca te confrunti cu problema pe care o rezolva aceasta pagina, postarea aceasta este pentru tine.", "Explica problema, solutia si arata un exemplu real.", "CTA: Spune-mi in comentarii daca te confrunti cu asta."],
      ["ZIUA 2 · REEL", "HOOK: Uite ce se intampla in spatele rezultatului pe care il vezi aici.", "Filmeaza procesul real.", "CTA: Urmareste pagina pentru urmatoarea parte."],
      ["ZIUA 3 · EDUCATIV", "HOOK: 3 lucruri pe care as vrea sa le stii inainte sa alegi produsul sau serviciul meu.", "Ofera 3 recomandari concrete din nisa paginii.", "CTA: Salveaza postarea."],
      ["ZIUA 4 · CONVERSATIE", "HOOK: Am nevoie de parerea ta: A sau B?", "Arata doua optiuni reale din nisa.", "CTA: Voteaza A sau B."],
      ["ZIUA 5 · VANZARE", "HOOK: Daca vrei rezultatul dorit, acesta este un punct bun de pornire.", "Prezinta oferta reala si exact ce primeste clientul.", "CTA: Scrie INFO pentru detalii."],
      ["ZIUA 6 · DOVADA", "HOOK: Nu vreau sa-ti spun doar eu ca functioneaza. Uite un exemplu real.", "Arata un rezultat sau testimonial real.", "CTA: Vrei sa afli daca ti se potriveste? Scrie-mi."],
      ["ZIUA 7 · REPETA", "HOOK: Tema care a atras cele mai bune semnale merita testata din nou.", "Reia categoria cu cea mai buna medie, schimbind hook-ul si exemplul.", "CTA: Ce varianta ai vrea sa vezi?"]
    ]
  };

  const days = common[key] || common.other;
  return {
    niche: key,
    goal: goal || "",
    bestSignal: bestCategory ? "Categoria cu cea mai buna medie: " + bestCategory.category : "Nu exista inca o categorie cu suficiente date.",
    referencePost: topPost ? String(topPost.message || "").replace(/\s+/g, " ").slice(0, 140) : null,
    days: days.map(x => ({ day: x[0], hook: x[1], content: x[2], cta: x[3] }))
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
      const r=await fetch("/api/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({state,pageId:btn.dataset.id,...JSON.parse(sessionStorage.getItem("pageDoctorPrefs")||"{}")})});
      const d=await r.json(); if(!r.ok) throw new Error(d.error||"Eroare");
      sessionStorage.setItem("pageDoctorResult",JSON.stringify(d));
      location.href="/?connected=1";
    }catch(e){s.textContent=e.message;document.querySelectorAll(".page-option").forEach(x=>x.disabled=false)}
  }));
  </script></body></html>`;
}

app.get("/", (req, res) => {
  const file = path.join(__dirname, "public", "index.html");
  let html = fs.readFileSync(file, "utf8");
  html = html
    .replace("✍️ Ce să postezi în continuare?", "✍️ Ce să postezi în continuare?")
    .replace("3 variante inspirate din postarea ta cu cele mai multe interacțiuni", "3 postări noi, fiecare cu un scop diferit")
    .replace("✨ Generează 3 variante", "✨ Creează 3 postări noi")
    .replace("🔄 Transformă postarea care a mers în alte formate", "♻️ Nu lăsa postarea care a mers să fie folosită o singură dată")
    .replace("Aici NU inventăm alte idei. Păstrăm aceeași postare și o adaptăm pentru Carusel, Reel și Stories.", "Aici nu inventăm o idee nouă. Refolosim aceeași postare și o transformăm concret în Carusel, Reel și Stories.")
    .replace("🔄 Transformă în alte formate", "🔄 Refolosește postarea");

  const override = `
<script>
(function(){
  const originalGenerate = window.generateNextPosts;
  window.generateNextPosts = function(){
    const d=window.pageDoctorData||{}, diag=d.diagnostic||{}, items=diag.nextPosts||[], out=document.getElementById('generatedPosts');
    if(!out) return;
    out.innerHTML='';
    if(!items.length){
      out.innerHTML='<div class="priority">Nu avem încă suficiente date pentru a construi postări noi pe baza unui semnal real.</div>';
      return;
    }
    items.forEach(function(v){
      const div=document.createElement('div');
      div.className='variant';
      div.innerHTML='<b>'+escapeText(v.title)+'</b><div class="mini" style="margin-top:4px">🎯 '+escapeText(v.objective)+'</div><p><strong>De ce aceasta?</strong> '+escapeText(v.reason)+'</p><p><strong>🔥 '+escapeText(v.hook)+'</strong></p><div style="white-space:pre-line;margin-top:10px">'+escapeText(v.caption)+'</div><p><strong>👉 '+escapeText(v.cta)+'</strong></p><div class="mini">📊 '+escapeText(v.evidence||'')+'</div>';
      out.appendChild(div);
    });
    out.scrollIntoView({behavior:'smooth',block:'nearest'});
  };

  window.repurposeTopPost = function(){
    const d=window.pageDoctorData||{}, items=d.diagnostic?.repurposedPosts||[], out=document.getElementById('repurposedPosts');
    if(!out) return;
    out.innerHTML='';
    if(!items.length){
      out.innerHTML='<div class="priority">Nu există încă suficiente date pentru a transforma postarea principală.</div>';
      return;
    }
    items.forEach(function(v){
      const div=document.createElement('div');
      div.className='variant';
      let html='<b>'+escapeText(v.title)+'</b><div class="mini">'+escapeText(v.format||'')+'</div>';
      if(v.slides) html+='<div style="margin-top:10px">'+v.slides.map(function(x){return '<div class="priority" style="margin-top:7px">'+escapeText(x)+'</div>';}).join('')+'</div>';
      if(v.frames) html+='<div style="margin-top:10px">'+v.frames.map(function(x){return '<div class="priority" style="margin-top:7px">'+escapeText(x)+'</div>';}).join('')+'</div>';
      if(v.stories) html+='<div style="margin-top:10px">'+v.stories.map(function(x){return '<div class="priority" style="margin-top:7px">'+escapeText(x)+'</div>';}).join('')+'</div>';
      html+='<p><strong>Caption:</strong> '+escapeText(v.caption||'')+'</p><strong>👉 '+escapeText(v.cta||'')+'</strong>';
      div.innerHTML=html;
      out.appendChild(div);
    });
    out.scrollIntoView({behavior:'smooth',block:'nearest'});
  };
})();
</script>`;

  html = html.replace("</body>", override + "</body>");
  res.send(html);
});

app.listen(PORT, () => console.log(`Page Doctor listening on ${PORT}`));
