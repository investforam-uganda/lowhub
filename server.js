/**
 * LowHub Backend Server — server.js
 * ─────────────────────────────────────────────────────────────────────────
 * Deploy this on Render (Web Service). It does three jobs the frontend
 * cannot safely or reliably do on its own:
 *
 *   1. AUTOMATIC PAYMENTS (MarzPay)
 *      The browser calls POST /api/payments/collect. This server holds the
 *      real MarzPay API key/secret (as Render env vars — never in the
 *      frontend) and starts a MarzPay mobile money collection. MarzPay then
 *      calls our webhook (POST /api/payments/webhook) when the customer
 *      approves or declines on their phone. We also poll MarzPay's status
 *      endpoint as a backstop, because MarzPay's own docs recommend not
 *      relying on the webhook alone (it can be delayed or missed).
 *      When a payment completes, this server activates the user's premium
 *      plan in Firestore directly — the browser only watches Firestore for
 *      the result, it never decides success/failure itself.
 *
 *   2. REAL DEVICE PUSH NOTIFICATIONS
 *      admin.html and other pages write "pending" notification docs to a
 *      `pendingPush` Firestore collection, but nothing was ever consuming
 *      that queue — so real device push (app closed/backgrounded) never
 *      fired. This server polls that collection and sends real pushes via
 *      the Firebase Admin SDK (which actually talks to FCM's servers).
 *
 *   3. ADMIN PAYMENT SETTINGS
 *      Small endpoints so admin-payments.html can save/read the automatic
 *      vs manual toggle and backend/API config without putting secrets in
 *      Firestore in plaintext where every logged-in user can read them.
 *
 *   4. MARKETPLACE ORDERS (NEW — LowHub Order/Delivery upgrade)
 *      POST /api/orders/create, /api/orders/:id/pay, /api/orders/:id/negotiate,
 *      /api/orders/:id/status, /api/orders/:id/verify-pickup. These require
 *      no new env vars beyond what's already listed below — they reuse
 *      FIREBASE_SERVICE_ACCOUNT (for admin.auth().verifyIdToken and
 *      Firestore transactions) and the existing MarzPay + PUBLIC_BACKEND_URL
 *      vars (order payments reuse the same MarzPay collection flow as
 *      premium payments). See IMPLEMENTATION_PLAN.md and
 *      ORDERS_DATA_MODEL.md at the project root for the full design.
 *
 *   5. MULTI-CHANNEL NOTIFICATIONS (NEW — Email / SMS / WhatsApp / Telegram)
 *      admin-notification-channels.html lets the admin paste in EmailJS or
 *      Infobip credentials (email), Infobip credentials (SMS), WhatsApp
 *      Cloud API or Green API credentials (WhatsApp), and a Telegram bot
 *      token — plus a price + duration (or "free") per channel. Users pay
 *      for a channel through the same MarzPay automatic-payment flow as
 *      Premium plans (POST /api/payments/collect with purpose:
 *      'notifChannel'), or the admin can manually grant/revoke access per
 *      user (POST /api/admin/notification-access). No new env vars — all
 *      of this is stored in Firestore (siteConfig/notificationChannels,
 *      userNotificationAccess/{uid}) since, unlike MarzPay/Firebase, the
 *      admin needs to change these from the UI without a redeploy. Device
 *      push (FCM, section 2 above) stays free/unconditional regardless of
 *      channel access, per spec.
 *
 * ── Deploying on Render ─────────────────────────────────────────────────
 *   1. Push this file (+ package.json) to a repo, or create a new Render
 *      Web Service pointing at a repo containing it.
 *   2. Build command:  npm install
 *      Start command:  node server.js
 *   3. Set these Environment Variables in the Render dashboard (never
 *      commit them to git):
 *
 *      FIREBASE_SERVICE_ACCOUNT   the ENTIRE contents of your Firebase
 *                                  service-account JSON file, pasted as one
 *                                  line (see "Getting the Firebase value"
 *                                  below)
 *      MARZPAY_API_KEY            from your MarzPay dashboard
 *      MARZPAY_API_SECRET         from your MarzPay dashboard
 *      MARZPAY_BASE_URL           https://wallet.wearemarz.com/api/v1
 *                                  (override only if MarzPay gives you a
 *                                  different base URL)
 *      PUBLIC_BACKEND_URL         the https://your-app.onrender.com URL
 *                                  Render gives this service — used to
 *                                  build the MarzPay callback_url
 *      ADMIN_API_TOKEN            any long random string you invent — the
 *                                  admin panel must send this in an
 *                                  X-Admin-Token header to change payment
 *                                  settings
 *      PORT                       Render sets this automatically, leave
 *                                  unset locally it defaults to 3000
 *
 *      Getting the Firebase value: Firebase Console → Project Settings →
 *      Service Accounts → Generate New Private Key. This downloads a JSON
 *      file. Open it, select all, copy the whole thing (curly braces and
 *      all), and paste it as the value of FIREBASE_SERVICE_ACCOUNT in
 *      Render — Render's env var boxes accept multi-line paste fine, and
 *      JSON.parse() handles the \n escapes inside it correctly with no
 *      manual editing needed. Do NOT reformat, retype, or split it up —
 *      paste the file's contents exactly as downloaded.
 *
 *   4. In admin-payments.html, set "Backend URL" to your Render service's
 *      public URL (the same as PUBLIC_BACKEND_URL above).
 * ─────────────────────────────────────────────────────────────────────────
 */

const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const fetch = global.fetch || require('node-fetch');
const crypto = require('crypto');

// ── Firebase Admin init ─────────────────────────────────────────────────
// Uses a single FIREBASE_SERVICE_ACCOUNT env var holding the entire
// service-account JSON as one string, parsed with JSON.parse(). This is
// deliberately NOT split into separate FIREBASE_PROJECT_ID /
// FIREBASE_CLIENT_EMAIL / FIREBASE_PRIVATE_KEY env vars — that approach
// requires manually converting the private key's real newlines to literal
// \n sequences and back, and it only takes one dropped character or one
// "helpful" editor reformat during paste to corrupt the PEM structure and
// trigger "error:1E08010C:DECODER routines::unsupported" from OpenSSL.
// JSON.parse() on the whole file avoids that entirely — it interprets the
// \n escapes inside the JSON string correctly by construction, giving
// Node the exact byte-for-byte key Firebase generated.
function initFirebaseAdmin() {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT;

  if (!raw) {
    console.error('[startup] Missing FIREBASE_SERVICE_ACCOUNT env var.');
    console.error('[startup] The server will start, but every Firebase-dependent route will fail until this is set in Render.');
    return null;
  }

  let serviceAccount;
  try {
    serviceAccount = JSON.parse(raw);
  } catch (e) {
    console.error('[startup] FIREBASE_SERVICE_ACCOUNT is not valid JSON:', e.message);
    console.error('[startup] Paste the ENTIRE contents of your downloaded service-account JSON file as-is, as one line, into this env var.');
    return null;
  }

  if (!serviceAccount.project_id || !serviceAccount.client_email || !serviceAccount.private_key) {
    console.error('[startup] FIREBASE_SERVICE_ACCOUNT JSON is missing project_id, client_email, or private_key.');
    return null;
  }

  console.log(`[startup] FIREBASE_SERVICE_ACCOUNT parsed OK — project_id=${serviceAccount.project_id}, client_email=${serviceAccount.client_email}`);

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  return admin.firestore();
}

const db = initFirebaseAdmin();

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

const MARZPAY_BASE_URL = (process.env.MARZPAY_BASE_URL || 'https://wallet.wearemarz.com/api/v1').replace(/\/+$/, '');
const MARZPAY_API_KEY = process.env.MARZPAY_API_KEY || '';
const MARZPAY_API_SECRET = process.env.MARZPAY_API_SECRET || '';
const PUBLIC_BACKEND_URL = (process.env.PUBLIC_BACKEND_URL || '').replace(/\/+$/, '');
const ADMIN_API_TOKEN = process.env.ADMIN_API_TOKEN || '';

function marzpayAuthHeader() {
  const creds = Buffer.from(`${MARZPAY_API_KEY}:${MARZPAY_API_SECRET}`).toString('base64');
  return `Basic ${creds}`;
}

function fetchWithTimeout(url, options = {}, timeoutMs = 20000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { ...options, signal: controller.signal }).finally(() => clearTimeout(timer));
}

function requireDb(res) {
  if (!db) {
    res.status(500).json({ success: false, error: 'Server is missing Firebase configuration. Check Render environment variables.' });
    return false;
  }
  return true;
}

// ── Auth verification middleware (NEW — orders endpoints only) ───────────
// The original premium-payment endpoints (/api/payments/collect etc.) trust
// a client-supplied userId, carried forward unchanged here since touching
// that flow was out of scope for this upgrade. The new order endpoints are
// new surface area handling real money against real inventory, so they
// verify the caller's Firebase ID token server-side and DERIVE userId from
// it — the request body's userId, if present, is never trusted (spec §47:
// "Do not trust a user-provided userId. The backend should derive/verify
// the authenticated user.").
async function requireAuth(req, res, next) {
  if (!db) return res.status(500).json({ success: false, error: 'Server is missing Firebase configuration.' });
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ success: false, error: 'Missing Authorization bearer token.' });
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.authUid = decoded.uid;
    req.authEmail = decoded.email || null;
    next();
  } catch (e) {
    console.error('[auth] token verification failed:', e.message);
    return res.status(401).json({ success: false, error: 'Invalid or expired session. Please sign in again.' });
  }
}

// Normalizes a Ugandan phone number to the 2567XXXXXXXX format MarzPay
// expects, accepting common local formats (0745..., 745..., +256745...).
function normalizePhone(raw) {
  let p = String(raw || '').replace(/[^\d]/g, '');
  // Strip an international-dial "00" prefix (e.g. "00256755123456") before
  // the rest of the logic runs, so it doesn't fall through every branch
  // below untouched and get shipped to MarzPay as a malformed 11+ digit
  // string (which MarzPay would reject with its own generic validation
  // error, showing up to the user as an unhelpful "check your input").
  if (p.startsWith('00')) p = p.slice(2);
  if (p.startsWith('0')) p = '256' + p.slice(1);
  else if (p.startsWith('256')) { /* already fine */ }
  else if (p.length === 9) p = '256' + p;
  return p;
}

// A normalized Ugandan MSISDN is always "256" + 9 digits = 12 digits total.
// Anything else (stray digits, a copy-pasted landline, a typo) should be
// caught here with a clear, specific LowHub message — rather than being
// forwarded to MarzPay, whose own generic validation error ("check your
// input" style messages) would otherwise be the first thing the user sees.
function isValidUgandaPhone(normalized) {
  return /^256\d{9}$/.test(normalized);
}

// ─────────────────────────────────────────────────────────────────────────
// HEALTH CHECK
// ─────────────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ ok: true, service: 'lowhub-backend', firebase: !!db });
});

// ─────────────────────────────────────────────────────────────────────────
// SEO — server-rendered listing pages for Google + link previews
// ─────────────────────────────────────────────────────────────────────────
// product.html is a client-side-rendered SPA shell (empty <title>, no real
// content until Firestore data loads in the browser). Search engine crawlers
// and link-preview bots (WhatsApp, Facebook, X, Slack) either don't run JS
// at all, or run it unreliably/slowly, so they mostly see a blank page —
// meaning a specific user's listing can never surface as its own result on
// Google, and shared links show no title/image/price preview.
//
// This route fixes that by rendering real HTML server-side, straight from
// Firestore, for exactly one URL per listing: GET /listing/:id
//   - <title>, meta description, Open Graph + Twitter Card tags, and a
//     Product/Offer JSON-LD block are all filled in with real data BEFORE
//     the response leaves this server — no JS execution required to see them.
//   - A human visitor's browser is redirected (via a tiny inline script,
//     plus a <meta http-equiv="refresh"> fallback for JS-disabled browsers)
//     straight into the existing product.html?id=... SPA, so real users still
//     get the full interactive experience. Bots that don't execute JS simply
//     never run the redirect and are left with the content above.
//   - Unapproved / removed / missing listings get a plain noindex page
//     instead of a fake "product" result, so Google never indexes something
//     that isn't live.
//
// Point real listing links at this route (WhatsApp/Facebook shares, the
// sitemap, etc.) instead of product.html?id=... directly — internal in-app
// navigation can keep using product.html?id=... unchanged, since SEO/link
// previews don't matter for taps that happen inside the app.
const LISTING_SITE_URL = (process.env.PUBLIC_SITE_URL || 'https://lowhub.store').replace(/\/+$/, '');

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, m => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]
  ));
}

function noIndexListingPage(res, status, message) {
  res.status(status).send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="robots" content="noindex">
<title>Listing not available – LowHub</title>
</head><body>
<p>${escapeHtml(message)}</p>
<p><a href="${LISTING_SITE_URL}/index.html">Browse LowHub listings</a></p>
</body></html>`);
}

app.get('/listing/:id', async (req, res) => {
  if (!db) return noIndexListingPage(res, 500, 'Listing service is temporarily unavailable.');

  const id = req.params.id;
  let doc;
  try {
    doc = await db.collection('listings').doc(id).get();
  } catch (e) {
    console.error('[listing-seo] Firestore read failed:', e.message);
    return noIndexListingPage(res, 500, 'Listing service is temporarily unavailable.');
  }

  if (!doc.exists) return noIndexListingPage(res, 404, 'This listing no longer exists.');

  const p = doc.data();

  // Only approved, live listings get indexed. Anything pending/rejected/
  // expired/inactive is real data but not something Google should ever
  // show as a result a shopper can actually buy.
  if (p.status !== 'approved') {
    return noIndexListingPage(res, 404, 'This listing is not currently available.');
  }

  const title = p.title || 'Listing';
  const price = typeof p.price === 'number' ? p.price : null;
  const description = (p.description && String(p.description).trim())
    || `${title}${p.location ? ' in ' + p.location : ''} — available on LowHub.`;
  const image = Array.isArray(p.imageUrls) && p.imageUrls[0] ? p.imageUrls[0] : `${LISTING_SITE_URL}/icon.png`;
  const pageUrl = `${LISTING_SITE_URL}/listing/${encodeURIComponent(id)}`;
  const appUrl = `product.html?id=${encodeURIComponent(id)}`;
  const pageTitle = `${title}${p.location ? ' for Sale in ' + p.location : ' for Sale'} | LowHub`;

  // Availability: LowHub listings are single items (not multi-quantity
  // retail stock), so "approved and not yet marked sold" = InStock.
  const availability = p.soldOut === true
    ? 'https://schema.org/OutOfStock'
    : 'https://schema.org/InStock';
  const itemCondition = /new/i.test(p.condition || '')
    ? 'https://schema.org/NewCondition'
    : 'https://schema.org/UsedCondition';

  const jsonLd = {
    '@context': 'https://schema.org',
    '@type': 'Product',
    name: title,
    image: [image],
    description: description,
    ...(p.category ? { category: p.category } : {}),
    offers: {
      '@type': 'Offer',
      url: pageUrl,
      priceCurrency: 'UGX',
      ...(price != null ? { price: String(price) } : {}),
      availability,
      itemCondition,
      ...(p.location ? {
        areaServed: {
          '@type': 'Place',
          name: p.location
        }
      } : {})
    }
  };

  const priceLine = price != null ? `UGX ${price.toLocaleString('en-US')}` : '';

  res.set('Cache-Control', 'public, max-age=300, s-maxage=3600');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(pageTitle)}</title>
<meta name="description" content="${escapeHtml(description)}">
<link rel="canonical" href="${escapeHtml(pageUrl)}">

<meta property="og:type" content="product">
<meta property="og:title" content="${escapeHtml(title)}">
<meta property="og:description" content="${escapeHtml(description)}">
<meta property="og:image" content="${escapeHtml(image)}">
<meta property="og:url" content="${escapeHtml(pageUrl)}">
<meta property="og:site_name" content="LowHub">
${price != null ? `<meta property="product:price:amount" content="${price}">
<meta property="product:price:currency" content="UGX">` : ''}

<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${escapeHtml(title)}">
<meta name="twitter:description" content="${escapeHtml(description)}">
<meta name="twitter:image" content="${escapeHtml(image)}">

<script type="application/ld+json">${JSON.stringify(jsonLd).replace(/</g, '\\u003c')}</script>

<meta http-equiv="refresh" content="0; url=${escapeHtml(appUrl)}">
<script>location.replace(${JSON.stringify(appUrl)});</script>
</head>
<body>
<h1>${escapeHtml(title)}</h1>
${priceLine ? `<p>${escapeHtml(priceLine)}</p>` : ''}
<p>${escapeHtml(description)}</p>
<p><img src="${escapeHtml(image)}" alt="${escapeHtml(title)}" style="max-width:100%"></p>
<p><a href="${escapeHtml(appUrl)}">View full listing on LowHub</a></p>
</body>
</html>`);
});

// ─────────────────────────────────────────────────────────────────────────
// SEO — dynamic sitemap.xml, generated from live approved listings
// ─────────────────────────────────────────────────────────────────────────
// The static sitemap.xml shipped with the frontend only lists fixed pages
// (home, login, etc.) — it has no way to know about listings created after
// deploy. This route regenerates the sitemap from Firestore on every
// request (cached for a few minutes via Cache-Control) so newly posted ads
// get picked up automatically. Point Google Search Console at
// {backend URL}/sitemap.xml instead of the static frontend file.
app.get('/sitemap.xml', async (req, res) => {
  const staticUrls = [
    '', 'index.html', 'login.html', 'signup.html', 'post-ad.html',
    'premium.html', 'privacy.html', 'report-problem.html'
  ];

  let listingUrls = [];
  if (db) {
    try {
      const snap = await db.collection('listings')
        .where('status', '==', 'approved')
        .select('updatedAt', 'createdAt')
        .limit(5000)
        .get();
      listingUrls = snap.docs.map(d => {
        const data = d.data();
        const ts = data.updatedAt || data.createdAt;
        const lastmod = ts && ts.toDate ? ts.toDate().toISOString().slice(0, 10) : null;
        return { loc: `${LISTING_SITE_URL}/listing/${d.id}`, lastmod };
      });
    } catch (e) {
      console.error('[sitemap] Firestore read failed:', e.message);
      // Fall through and still serve the static URLs below rather than
      // failing the whole sitemap over a transient Firestore error.
    }
  }

  const xmlEntries = [
    ...staticUrls.map(u => `  <url><loc>${LISTING_SITE_URL}/${u}</loc></url>`),
    ...listingUrls.map(u => `  <url><loc>${escapeHtml(u.loc)}</loc>${u.lastmod ? `<lastmod>${u.lastmod}</lastmod>` : ''}</url>`)
  ].join('\n');

  res.set('Content-Type', 'application/xml');
  res.set('Cache-Control', 'public, max-age=1800');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${xmlEntries}\n</urlset>`);
});

// ─────────────────────────────────────────────────────────────────────────
// 0. ORDERS — creation, pricing, stock reservation, negotiation, status
// ─────────────────────────────────────────────────────────────────────────
// This section is entirely NEW (marketplace/order upgrade). It sits ahead
// of the pre-existing payments section both physically and in trust: order
// creation is the one place price/fee/total are computed, and every later
// step (payment, status transitions) reads from what gets written here —
// never from client-supplied numbers.

const ORDER_STATUS_TRANSITIONS = {
  pending: ['awaiting_delivery_fee', 'awaiting_payment', 'cancelled', 'expired'],
  awaiting_delivery_fee: ['awaiting_payment', 'cancelled', 'expired'],
  awaiting_payment: ['payment_pending', 'cancelled', 'expired'],
  payment_pending: ['paid', 'payment_failed'],
  paid: ['seller_confirmation', 'cancelled', 'disputed'],
  seller_confirmation: ['confirmed', 'rejected'],
  confirmed: ['processing', 'cancelled', 'disputed'],
  processing: ['ready_for_dispatch', 'cancelled', 'disputed'],
  ready_for_dispatch: ['handed_to_lowhub', 'out_for_delivery', 'ready_for_pickup', 'disputed'],
  handed_to_lowhub: ['out_for_delivery', 'disputed'],
  out_for_delivery: ['delivered', 'disputed'],
  ready_for_pickup: ['picked_up', 'disputed'],
  picked_up: ['completed', 'return_requested'],
  delivered: ['completed', 'return_requested', 'disputed'],
  completed: ['return_requested'],
  return_requested: ['returned', 'rejected'],
  returned: [], cancelled: [], rejected: [], expired: [],
  payment_failed: ['awaiting_payment', 'cancelled'],
  disputed: ['confirmed', 'processing', 'cancelled', 'returned']
};
function canTransitionOrderStatus(from, to) {
  if (from === to) return false;
  const allowed = ORDER_STATUS_TRANSITIONS[from];
  return Array.isArray(allowed) && allowed.includes(to);
}

async function generateOrderNumber() {
  const now = new Date();
  const dateStr = `${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}`;
  const counterRef = db.collection('counters').doc(`orderSeq-${dateStr}`);
  const seq = await db.runTransaction(async (tx) => {
    const snap = await tx.get(counterRef);
    const current = snap.exists ? (snap.data().value || 0) : 0;
    const next = current + 1;
    tx.set(counterRef, { value: next, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    return next;
  });
  return `LH-${dateStr}-${String(seq).padStart(6, '0')}`;
}

async function logOrderEvent(orderId, { type, actorId, actorRole, metadata }) {
  await db.collection('orders').doc(orderId).collection('events').add({
    type, actorId: actorId || null, actorRole: actorRole || 'system',
    metadata: metadata || {}, createdAt: admin.firestore.FieldValue.serverTimestamp()
  });
}

// POST /api/orders/create
// Body: { idempotencyKey, listingId, quantity, deliveryMethod, pickupStationId?,
//         deliveryZoneId?, deliveryAddress? }
// Every price/fee value is computed HERE from live Firestore data — the
// request body never supplies price, subtotal, deliveryFee, or total
// (spec §38). Stock is reserved via a Firestore transaction so two buyers
// can't both win the last unit (spec §5, §20).
app.post('/api/orders/create', requireAuth, async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const { idempotencyKey, listingId, quantity, deliveryMethod, pickupStationId, deliveryZoneId, deliveryAddress } = req.body || {};
    const buyerId = req.authUid;

    if (!listingId || !quantity || quantity < 1 || !deliveryMethod) {
      return res.status(400).json({ success: false, error: 'Missing required order fields.' });
    }
    if (!['seller_delivery', 'pickup_station', 'lowhub_delivery'].includes(deliveryMethod)) {
      return res.status(400).json({ success: false, error: 'Invalid delivery method.' });
    }

    // Idempotency: if this exact key already produced an order, return it
    // instead of creating a second one (spec §39 — double-tap protection).
    if (idempotencyKey) {
      const existing = await db.collection('orders').where('idempotencyKey', '==', idempotencyKey).limit(1).get();
      if (!existing.empty) {
        return res.json({ success: true, orderId: existing.docs[0].id, orderNumber: existing.docs[0].data().orderNumber, reused: true });
      }
    }

    const listingRef = db.collection('listings').doc(listingId);
    const buyerRef = db.collection('users').doc(buyerId);

    // ── Transaction: validate + reserve stock + build the order atomically ──
    const result = await db.runTransaction(async (tx) => {
      const listingSnap = await tx.get(listingRef);
      if (!listingSnap.exists) throw new UserFacingError('This product could not be found.');
      const listing = listingSnap.data();

      if (listing.status !== 'approved') throw new UserFacingError('This listing is not currently available.');
      if (buyerId === listing.userId) throw new UserFacingError("You can't order your own listing.");

      let acceptOrders = listing.acceptOrders;
      if (acceptOrders === undefined || acceptOrders === null) {
        const cfgSnap = await tx.get(db.collection('siteConfig').doc('orderSettings'));
        acceptOrders = cfgSnap.exists ? !!cfgSnap.data().defaultAcceptOrders : false;
      }
      if (!acceptOrders) throw new UserFacingError('This seller has not enabled LowHub orders for this listing.');

      const sellerSnap = await tx.get(db.collection('users').doc(listing.userId));
      const seller = sellerSnap.exists ? sellerSnap.data() : {};
      if (seller.suspended === true) throw new UserFacingError('This seller is currently unavailable.');

      const price = Number(listing.price);
      if (!price || price <= 0) throw new UserFacingError('This product does not have a valid price.');

      const inv = listing.inventory || { enabled: false };
      let newQuantity = null;
      if (inv.enabled && !inv.unlimited) {
        const available = Number(inv.quantity) || 0;
        if (available < quantity) {
          throw new UserFacingError(available > 0 ? `Only ${available} item(s) are available.` : 'Sorry, this product is out of stock.');
        }
        newQuantity = available - quantity; // reserved immediately (spec §5 — pending reserves)
      }

      // ── Delivery fee: computed server-side per method, never client-trusted ──
      const opts = listing.deliveryOptions || {};
      let deliveryFee = 0;
      let pricingSnapshot = { source: null, zoneId: null, stationId: null, negotiationId: null, ratePerRuleAtCheckout: 0 };
      let orderStatus = 'awaiting_payment';

      const deliverySettingsSnap = await tx.get(db.collection('siteConfig').doc('deliverySettings'));
      const deliverySettings = deliverySettingsSnap.exists ? deliverySettingsSnap.data() : {};

      if (deliveryMethod === 'seller_delivery') {
        if (!opts.sellerDelivery || !opts.sellerDelivery.enabled || !(deliverySettings.sellerDelivery || {}).enabled) {
          throw new UserFacingError('Seller delivery is not available for this product.');
        }
        const mode = opts.sellerDelivery.mode;
        if (mode === 'free') {
          deliveryFee = 0;
          pricingSnapshot = { ...pricingSnapshot, source: 'free' };
        } else if (mode === 'fixed') {
          deliveryFee = Number(opts.sellerDelivery.fixedFee) || 0;
          pricingSnapshot = { ...pricingSnapshot, source: 'seller_fixed', ratePerRuleAtCheckout: deliveryFee };
        } else if (mode === 'negotiable') {
          deliveryFee = 0; // unresolved until negotiation completes
          orderStatus = 'awaiting_delivery_fee';
          pricingSnapshot = { ...pricingSnapshot, source: 'seller_negotiated' };
        } else {
          throw new UserFacingError('Seller delivery is not configured correctly for this product.');
        }
      } else if (deliveryMethod === 'pickup_station') {
        if (!opts.pickupStation || !opts.pickupStation.enabled || !(deliverySettings.pickupStation || {}).enabled) {
          throw new UserFacingError('Pickup station delivery is not available for this product.');
        }
        if (!pickupStationId) throw new UserFacingError('Please select a pickup station.');
        const stSnap = await tx.get(db.collection('pickupStations').doc(pickupStationId));
        if (!stSnap.exists || stSnap.data().status !== 'active') {
          throw new UserFacingError('This pickup station is currently unavailable. Please select another station.');
        }
        deliveryFee = Number(stSnap.data().fee) || 0;
        pricingSnapshot = { ...pricingSnapshot, source: 'admin_station', stationId: pickupStationId, ratePerRuleAtCheckout: deliveryFee };
      } else if (deliveryMethod === 'lowhub_delivery') {
        if (!opts.lowhubDelivery || !opts.lowhubDelivery.enabled || !(deliverySettings.lowhubDelivery || {}).enabled) {
          throw new UserFacingError('LowHub delivery is not available for this product.');
        }
        if (!deliveryAddress || !deliveryAddress.address || !deliveryAddress.phone) {
          throw new UserFacingError('Please provide a delivery address and phone number.');
        }
        const dz = deliverySettings.lowhubDelivery || {};
        if (dz.useZones) {
          if (!deliveryZoneId) throw new UserFacingError('Please select a delivery zone.');
          const zoneSnap = await tx.get(db.collection('deliveryZones').doc(deliveryZoneId));
          if (!zoneSnap.exists || zoneSnap.data().active !== true) {
            throw new UserFacingError('This delivery zone is currently unavailable.');
          }
          deliveryFee = Number(zoneSnap.data().fee) || 0;
          pricingSnapshot = { ...pricingSnapshot, source: 'admin_zone', zoneId: deliveryZoneId, ratePerRuleAtCheckout: deliveryFee };
        } else {
          deliveryFee = Number(dz.flatFee) || 0;
          pricingSnapshot = { ...pricingSnapshot, source: 'admin_zone', ratePerRuleAtCheckout: deliveryFee };
        }
      }

      const subtotal = price * quantity;
      const total = subtotal + deliveryFee;

      // ── Reserve stock now (spec §5: pending order reserves quantity) ──
      if (newQuantity !== null) {
        tx.update(listingRef, { 'inventory.quantity': newQuantity });
      }

      const orderRef = db.collection('orders').doc();
      const orderNumber = null; // generated after transaction (needs its own transaction on counters/*)

      const orderData = {
        orderNumber: null, // filled in right after
        idempotencyKey: idempotencyKey || null,
        buyerId, sellerId: listing.userId, listingId,
        productSnapshot: {
          title: listing.title || '', imageUrl: (listing.imageUrls && listing.imageUrls[0]) || null,
          unitPrice: price, category: listing.category || null, condition: listing.condition || null
        },
        quantity, subtotal, deliveryMethod, deliveryFee, total, pricingSnapshot,
        paymentStatus: 'unpaid', paymentProvider: null, transactionRef: null, paymentPhone: null, paymentCurrency: 'UGX',
        orderStatus,
        deliveryStatus: null,
        buyerSnapshot: { name: '', phone: '' }, // filled from users/{buyerId} below (outside tx, non-critical)
        sellerSnapshot: { name: seller.name || listing.userName || '', phone: listing.phone || '', companyName: seller.companyName || '' },
        deliveryAddress: deliveryMethod !== 'pickup_station' ? (deliveryAddress || null) : null,
        pickupStationId: deliveryMethod === 'pickup_station' ? pickupStationId : null,
        pickupOtp: null,
        conversationId: null,
        cancelledBy: null, cancelReason: null,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        statusTimestamps: { [orderStatus]: admin.firestore.FieldValue.serverTimestamp() }
      };

      tx.set(orderRef, orderData);
      return { orderRef, orderData };
    });

    // Order number needs its own transaction (separate counters doc) — done
    // just after the main transaction commits, then patched onto the order.
    const orderNumber = await generateOrderNumber();
    await result.orderRef.update({ orderNumber });

    // Best-effort buyer snapshot fill + notifications — not part of the
    // financial transaction, safe to do after commit.
    try {
      const buyerSnap = await buyerRef.get();
      if (buyerSnap.exists) {
        await result.orderRef.update({
          buyerSnapshot: { name: buyerSnap.data().name || '', phone: buyerSnap.data().phone || '' }
        });
      }
    } catch (e) { console.error('[orders/create] buyer snapshot fill failed:', e.message); }

    await logOrderEvent(result.orderRef.id, { type: 'orderCreated', actorId: buyerId, actorRole: 'buyer', metadata: { orderNumber } });

    await db.collection('userNotifications').add({
      userId: result.orderData.sellerId,
      type: 'newOrder',
      message: `New order ${orderNumber} for "${result.orderData.productSnapshot.title}".`,
      link: `seller-orders.html?id=${result.orderRef.id}`,
      read: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    await db.collection('pendingPush').add({
      userId: result.orderData.sellerId, title: 'New Order', body: `Order ${orderNumber} — ${result.orderData.productSnapshot.title}`,
      link: `/seller-orders.html?id=${result.orderRef.id}`, sent: false, createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ success: true, orderId: result.orderRef.id, orderNumber });
  } catch (e) {
    if (e instanceof UserFacingError) {
      return res.status(400).json({ success: false, error: e.message });
    }
    console.error('[orders/create] error:', e);
    res.status(500).json({ success: false, error: 'Internal server error creating order.' });
  }
});

// Small helper error class so validation failures inside the transaction
// produce a clean 400 with the specific reason, instead of a generic 500.
class UserFacingError extends Error {}

// POST /api/orders/:orderId/negotiate
// Body: { action: 'propose'|'counter'|'accept'|'reject', amount? }
// Handles the seller-delivery negotiation flow (spec §9, §52). Only the
// order's buyer or seller may act on it, and only in the roles that make
// sense (seller proposes/counters, buyer accepts/rejects/counters).
app.post('/api/orders/:orderId/negotiate', requireAuth, async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const { orderId } = req.params;
    const { action, amount } = req.body || {};
    const uid = req.authUid;
    if (!['propose', 'counter', 'accept', 'reject'].includes(action)) {
      return res.status(400).json({ success: false, error: 'Invalid negotiation action.' });
    }

    const orderRef = db.collection('orders').doc(orderId);
    await db.runTransaction(async (tx) => {
      const snap = await tx.get(orderRef);
      if (!snap.exists) throw new UserFacingError('Order not found.');
      const order = snap.data();
      if (uid !== order.buyerId && uid !== order.sellerId) throw new UserFacingError('Not authorized for this order.');
      if (order.orderStatus !== 'awaiting_delivery_fee' && !(action === 'accept' && order.orderStatus === 'awaiting_delivery_fee')) {
        if (order.orderStatus !== 'awaiting_delivery_fee') throw new UserFacingError('This order is not awaiting a delivery fee agreement.');
      }

      const isSellerActing = uid === order.sellerId;
      if ((action === 'propose') && !isSellerActing) throw new UserFacingError('Only the seller can propose the initial delivery fee.');

      const negRef = orderRef.collection('negotiations').doc();
      const proposedBy = isSellerActing ? 'seller' : 'buyer';

      if (action === 'accept') {
        // Whoever accepts is agreeing to the most recent proposal's amount —
        // amount is REQUIRED and must match the last proposal to prevent a
        // buyer/seller from "accepting" a different number than what was
        // actually offered.
        const lastNegSnap = await tx.get(orderRef.collection('negotiations').orderBy('createdAt', 'desc').limit(1));
        const lastAmount = !lastNegSnap.empty ? lastNegSnap.docs[0].data().amount : null;
        if (lastAmount === null || Number(amount) !== Number(lastAmount)) {
          throw new UserFacingError('The delivery fee to accept does not match the latest proposal.');
        }
        const newTotal = order.subtotal + Number(amount);
        tx.set(negRef, { proposedBy, amount: Number(amount), action: 'accept', createdAt: admin.firestore.FieldValue.serverTimestamp() });
        tx.update(orderRef, {
          deliveryFee: Number(amount), total: newTotal, orderStatus: 'awaiting_payment',
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          [`statusTimestamps.awaiting_payment`]: admin.firestore.FieldValue.serverTimestamp()
        });
      } else if (action === 'reject') {
        tx.set(negRef, { proposedBy, amount: amount || null, action: 'reject', createdAt: admin.firestore.FieldValue.serverTimestamp() });
        tx.update(orderRef, { orderStatus: 'cancelled', cancelledBy: isSellerActing ? 'seller' : 'buyer', cancelReason: 'Delivery fee negotiation rejected', updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      } else {
        // propose / counter
        if (!amount || amount <= 0) throw new UserFacingError('Please provide a valid delivery fee amount.');
        tx.set(negRef, { proposedBy, amount: Number(amount), action, createdAt: admin.firestore.FieldValue.serverTimestamp() });
        tx.update(orderRef, { updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      }
    });

    await logOrderEvent(orderId, { type: `deliveryFee${action.charAt(0).toUpperCase()+action.slice(1)}`, actorId: uid, actorRole: uid === (await orderRef.get()).data().sellerId ? 'seller' : 'buyer', metadata: { amount } });

    const order = (await orderRef.get()).data();
    const notifyUserId = uid === order.sellerId ? order.buyerId : order.sellerId;
    await db.collection('userNotifications').add({
      userId: notifyUserId, type: 'deliveryFeeNegotiation',
      message: action === 'accept' ? `Delivery fee of UGX ${Number(amount).toLocaleString()} accepted for order ${order.orderNumber}.`
        : action === 'reject' ? `Delivery fee negotiation was rejected for order ${order.orderNumber}.`
        : `New delivery fee proposal of UGX ${Number(amount).toLocaleString()} for order ${order.orderNumber}.`,
      link: `order.html?id=${orderId}`, read: false, createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ success: true });
  } catch (e) {
    if (e instanceof UserFacingError) return res.status(400).json({ success: false, error: e.message });
    console.error('[orders/negotiate] error:', e);
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

// POST /api/orders/:orderId/status
// Body: { newStatus, reason? }
// Central enforcement point for spec §11 ("do not allow arbitrary status
// changes"). Validates the transition graph, checks the caller is the
// order's buyer/seller/admin as appropriate for that specific transition,
// and appends the event log entry.
app.post('/api/orders/:orderId/status', requireAuth, async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const { orderId } = req.params;
    const { newStatus, reason } = req.body || {};
    const uid = req.authUid;
    const isAdminCaller = req.headers['x-admin-token'] && req.headers['x-admin-token'] === ADMIN_API_TOKEN;

    const orderRef = db.collection('orders').doc(orderId);
    const snap = await orderRef.get();
    if (!snap.exists) return res.status(404).json({ success: false, error: 'Order not found.' });
    const order = snap.data();

    const isBuyer = uid === order.buyerId;
    const isSeller = uid === order.sellerId;
    const isAssignedAgent = !!order.deliveryAgentId && uid === order.deliveryAgentId;
    if (!isBuyer && !isSeller && !isAssignedAgent && !isAdminCaller) return res.status(403).json({ success: false, error: 'Not authorized for this order.' });

    if (!canTransitionOrderStatus(order.orderStatus, newStatus)) {
      return res.status(400).json({ success: false, error: `Cannot move order from "${order.orderStatus}" to "${newStatus}".` });
    }

    // Role restrictions per transition — buyers can't mark their own order
    // "confirmed"/"processing" etc, sellers can't mark "paid" (spec §13,
    // §19 — payment confirmation must come from the trusted payment flow).
    // 'delivered' is split from the other never-client targets: a seller
    // (self-delivery) or an assigned delivery agent (LowHub delivery) may
    // set it, but a buyer never can and 'picked_up'/'paid' remain fully
    // backend/OTP-only regardless of role.
    const sellerOnlyTargets = ['confirmed', 'rejected', 'processing', 'ready_for_dispatch', 'handed_to_lowhub', 'ready_for_pickup'];
    const sellerOrAgentTargets = ['out_for_delivery', 'delivered'];
    const neverClientTargets = ['paid', 'picked_up']; // paid=backend only; picked_up requires OTP flow via /verify-pickup
    if (neverClientTargets.includes(newStatus) && !isAdminCaller) {
      return res.status(403).json({ success: false, error: 'This status can only be set through the trusted order flow.' });
    }
    if (sellerOnlyTargets.includes(newStatus) && !isSeller && !isAdminCaller) {
      return res.status(403).json({ success: false, error: 'Only the seller can set this status.' });
    }
    if (sellerOrAgentTargets.includes(newStatus) && !isSeller && !isAssignedAgent && !isAdminCaller) {
      return res.status(403).json({ success: false, error: 'Only the seller or assigned delivery agent can set this status.' });
    }
    if (newStatus === 'cancelled') {
      // Both buyer and seller may cancel, but only from early states.
      if (!['pending', 'awaiting_delivery_fee', 'awaiting_payment', 'payment_pending'].includes(order.orderStatus) && !isAdminCaller) {
        return res.status(400).json({ success: false, error: 'This order can no longer be cancelled — please contact the seller or open a dispute.' });
      }
    }

    const updates = {
      orderStatus: newStatus, updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      [`statusTimestamps.${newStatus}`]: admin.firestore.FieldValue.serverTimestamp()
    };
    if (newStatus === 'cancelled') {
      updates.cancelledBy = isAdminCaller ? 'admin' : (isBuyer ? 'buyer' : 'seller');
      updates.cancelReason = reason || null;
      // Release reserved stock (spec §5 — cancelled order releases quantity)
      const listingSnap = await db.collection('listings').doc(order.listingId).get();
      if (listingSnap.exists) {
        const inv = listingSnap.data().inventory || {};
        if (inv.enabled && !inv.unlimited) {
          await db.collection('listings').doc(order.listingId).update({
            'inventory.quantity': admin.firestore.FieldValue.increment(order.quantity)
          });
        }
      }
    }
    // Generate the pickup OTP the moment the order becomes ready for
    // pickup (spec §16). A 6-digit numeric code, generated server-side so
    // it's never visible to anyone but the buyer (via order.html) until
    // they present it in person at the station.
    if (newStatus === 'ready_for_pickup') {
      updates.pickupOtp = String(Math.floor(100000 + Math.random() * 900000));
    }

    await orderRef.update(updates);
    await logOrderEvent(orderId, { type: `status_${newStatus}`, actorId: uid, actorRole: isAdminCaller ? 'admin' : (isBuyer ? 'buyer' : 'seller'), metadata: { reason: reason || null } });

    const notifyUserId = isBuyer ? order.sellerId : order.buyerId;
    if (notifyUserId) {
      await db.collection('userNotifications').add({
        userId: notifyUserId, type: 'orderStatusChanged',
        message: `Order ${order.orderNumber} is now "${newStatus.replace(/_/g,' ')}".`,
        link: `order.html?id=${orderId}`, read: false, createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }

    res.json({ success: true });
  } catch (e) {
    console.error('[orders/status] error:', e);
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

// POST /api/orders/:orderId/pay
// Body: { phone }
// Order-specific payment collection — deliberately separate from the
// generic /api/payments/collect below rather than extended to share it,
// because this endpoint must NEVER trust a client-supplied amount: it reads
// order.total from Firestore itself (already server-computed at order
// creation) and re-verifies the caller is the order's buyer via the
// Authorization bearer token (spec §19, §20, §47). requireAuth also means
// this endpoint can't be used to pay for someone else's order.
app.post('/api/orders/:orderId/pay', requireAuth, async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const { orderId } = req.params;
    const { phone } = req.body || {};
    const uid = req.authUid;

    if (!phone) return res.status(400).json({ success: false, error: 'Phone number is required.' });
    if (!MARZPAY_API_KEY || !MARZPAY_API_SECRET) {
      return res.status(500).json({ success: false, error: 'Automatic payments are not configured on the server yet.' });
    }

    const orderRef = db.collection('orders').doc(orderId);
    const orderSnap = await orderRef.get();
    if (!orderSnap.exists) return res.status(404).json({ success: false, error: 'Order not found.' });
    const order = orderSnap.data();

    if (order.buyerId !== uid) return res.status(403).json({ success: false, error: 'Not authorized for this order.' });
    if (!['awaiting_payment'].includes(order.orderStatus)) {
      return res.status(400).json({ success: false, error: 'This order is not awaiting payment.' });
    }
    if (order.paymentStatus === 'paid') return res.status(400).json({ success: false, error: 'This order has already been paid.' });

    const normalizedPhone = normalizePhone(phone);
    if (!isValidUgandaPhone(normalizedPhone)) {
      return res.status(400).json({ success: false, error: 'Please enter a valid mobile money number, e.g. 0755 123456.' });
    }
    // MarzPay requires `reference` to be a UUID (its own validation message
    // literally spells out the expected format) — LH-ORDER-... was being
    // rejected on every single request regardless of phone number. Keep the
    // human-readable order-linked string too (as internalRef) since that's
    // useful in our own logs/records, but send MarzPay the UUID it demands.
    const ref = crypto.randomUUID();
    const internalRef = `LH-ORDER-${order.orderNumber}-${Date.now()}`;
    const callbackUrl = PUBLIC_BACKEND_URL ? `${PUBLIC_BACKEND_URL}/api/payments/webhook` : undefined;

    const paymentRef = db.collection('autoPayments').doc();
    await paymentRef.set({
      userId: uid, userEmail: req.authEmail || '', userName: order.buyerSnapshot?.name || '',
      phone: normalizedPhone, amount: order.total, reference: ref, internalRef,
      purpose: 'order', orderId, orderNumber: order.orderNumber,
      planKey: null, planName: null, planDays: null, dealPayload: null,
      status: 'pending', provider: 'marzpay', marzpayTransactionId: null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // MarzPay's own validation error explicitly asks for the phone number
    // WITH country code (e.g. +256712345678) — this was converting it back
    // to local format (0755...) right before sending, which is exactly why
    // MarzPay rejected every request with "check your input" regardless of
    // what the user typed. Send the +country-code form MarzPay asks for.
    const marzPhone = '+' + normalizedPhone;

    let marzRes, marzData;
    try {
      marzRes = await fetch(`${MARZPAY_BASE_URL}/collect-money`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': marzpayAuthHeader() },
        body: JSON.stringify({
          phone_number: marzPhone, amount: order.total, country: 'UG', reference: ref,
          description: `LowHub order ${order.orderNumber}`,
          ...(callbackUrl ? { callback_url: callbackUrl } : {})
        })
      });
      marzData = await marzRes.json();
      console.log('[orders/pay] MarzPay raw response:', JSON.stringify(marzData));
    } catch (fetchErr) {
      await paymentRef.update({ status: 'failed', failureReason: 'Could not reach MarzPay.', updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      await orderRef.update({ orderStatus: 'payment_pending', paymentStatus: 'failed', updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      return res.status(502).json({ success: false, error: 'Could not reach the payment provider. Please try again.' });
    }

    if (!marzRes.ok || (marzData.status !== true && marzData.status !== 'success' && !marzData.success)) {
      const errMsg = marzData?.message || 'MarzPay declined the request.';
      await paymentRef.update({ status: 'failed', failureReason: errMsg, marzpayRawResponse: JSON.stringify(marzData).slice(0, 2000), updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      return res.status(400).json({ success: false, error: errMsg });
    }

    const txId = marzData?.data?.transaction?.uuid || marzData?.data?.id || marzData?.data?.collection_id || null;
    await paymentRef.update({ marzpayTransactionId: txId, status: 'processing', updatedAt: admin.firestore.FieldValue.serverTimestamp() });
    await orderRef.update({ orderStatus: 'payment_pending', paymentStatus: 'pending', paymentProvider: 'marzpay', paymentPhone: normalizedPhone, updatedAt: admin.firestore.FieldValue.serverTimestamp() });
    await logOrderEvent(orderId, { type: 'paymentInitiated', actorId: uid, actorRole: 'buyer', metadata: { reference: ref } });

    if (txId) pollMarzpayStatus(paymentRef.id, txId).catch(e => console.error('[poll] error:', e.message));

    res.json({ success: true, paymentId: paymentRef.id, transactionId: txId });
  } catch (e) {
    console.error('[orders/pay] error:', e);
    res.status(500).json({ success: false, error: 'Internal server error starting payment.' });
  }
});

// POST /api/orders/:orderId/verify-pickup
// Body: { otp }
// Dedicated endpoint for the pickup-station flow (spec §16) — this is the
// ONLY way an order can move to 'picked_up', enforced by requiring the OTP
// that was generated server-side when the order became ready_for_pickup.
// Any authenticated user may call this (station staff currently share the
// admin login rather than having individual accounts — see
// IMPLEMENTATION_PLAN.md's admin-identity note), but it still requires the
// correct OTP, which only the buyer has seen.
app.post('/api/orders/:orderId/verify-pickup', requireAuth, async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const { orderId } = req.params;
    const { otp } = req.body || {};
    const orderRef = db.collection('orders').doc(orderId);
    const snap = await orderRef.get();
    if (!snap.exists) return res.status(404).json({ success: false, error: 'Order not found.' });
    const order = snap.data();

    if (order.orderStatus !== 'ready_for_pickup') {
      return res.status(400).json({ success: false, error: 'This order is not ready for pickup.' });
    }
    if (!otp || String(otp) !== String(order.pickupOtp)) {
      return res.status(400).json({ success: false, error: 'Incorrect pickup code.' });
    }

    await orderRef.update({
      orderStatus: 'picked_up', updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      'statusTimestamps.picked_up': admin.firestore.FieldValue.serverTimestamp()
    });
    await logOrderEvent(orderId, { type: 'status_picked_up', actorId: req.authUid, actorRole: 'admin', metadata: {} });
    await db.collection('userNotifications').add({
      userId: order.buyerId, type: 'orderStatusChanged',
      message: `Order ${order.orderNumber} has been picked up. Thank you for using LowHub!`,
      link: `order.html?id=${orderId}`, read: false, createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ success: true });
  } catch (e) {
    console.error('[orders/verify-pickup] error:', e);
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────
// 1. AUTOMATIC PAYMENTS — MarzPay
// ─────────────────────────────────────────────────────────────────────────

// Starts a MarzPay mobile money collection and creates the tracking doc in
// Firestore that premium.html polls (see startAutomaticPayment() there).
app.post('/api/payments/collect', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const {
      userId, userEmail, userName, phone, amount, reference,
      // Premium-plan fields (purpose: 'premium', the default — kept
      // backward compatible with the original premium-only shape).
      planKey, planName, planDays,
      // Deal-submission fields (purpose: 'deal'). dealPayload carries
      // everything submitDeal()/startDealAutomaticPayment() in profile.html
      // needs to create the live deal on success — selected ads, heading,
      // content, discount label, duration — since this collect call is the
      // only place that data exists before payment confirms.
      purpose, dealPayload,
      // Notification-channel fields (purpose: 'notifChannel'). notifChannel
      // is one of 'email'|'sms'|'whatsapp'|'telegram'; notifChannelDays
      // comes from the admin's configured duration for that channel (see
      // /api/admin/notification-channels) and is echoed back by the
      // frontend at checkout time.
      notifChannel, notifChannelDays
    } = req.body || {};

    const isDeal = purpose === 'deal';
    const isNotifChannel = purpose === 'notifChannel';
    // planKey doubles as "what are we paying for" for premium; for deals/
    // notifChannel purchases we just need an identifying label.
    const itemKey = isDeal ? 'deal' : isNotifChannel ? `notif-${notifChannel}` : planKey;

    if (!userId || !phone || !amount || (!isDeal && !isNotifChannel && !planKey)) {
      return res.status(400).json({ success: false, error: 'Missing required fields (userId, phone, amount, planKey).' });
    }
    if (isDeal && (!dealPayload || !Array.isArray(dealPayload.adIds) || !dealPayload.adIds.length)) {
      return res.status(400).json({ success: false, error: 'Missing deal details (selected ads).' });
    }
    if (isNotifChannel && !NOTIF_CHANNELS.includes(notifChannel)) {
      return res.status(400).json({ success: false, error: `notifChannel must be one of: ${NOTIF_CHANNELS.join(', ')}` });
    }
    if (!MARZPAY_API_KEY || !MARZPAY_API_SECRET) {
      return res.status(500).json({ success: false, error: 'Automatic payments are not configured on the server yet (missing MarzPay credentials).' });
    }

    const normalizedPhone = normalizePhone(phone);
    if (!isValidUgandaPhone(normalizedPhone)) {
      return res.status(400).json({ success: false, error: 'Please enter a valid mobile money number, e.g. 0755 123456.' });
    }
    // MarzPay requires `reference` to be a UUID (confirmed directly from its
    // own VALIDATION_ERROR response) — LH-{itemKey}-{timestamp} was being
    // rejected on every request. A caller-supplied `reference` is still
    // honored if present, but internalRef always keeps the readable label.
    const internalRef = reference || `LH-${itemKey}-${Date.now()}`;
    const ref = (reference && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(reference))
      ? reference
      : crypto.randomUUID();
    const callbackUrl = PUBLIC_BACKEND_URL ? `${PUBLIC_BACKEND_URL}/api/payments/webhook` : undefined;

    // Create the Firestore tracking doc FIRST (status: pending) so the
    // frontend has something to poll even before MarzPay responds.
    const paymentRef = db.collection('autoPayments').doc();
    await paymentRef.set({
      userId, userEmail: userEmail || '', userName: userName || '',
      phone: normalizedPhone, amount, reference: ref, internalRef,
      purpose: isDeal ? 'deal' : isNotifChannel ? 'notifChannel' : 'premium',
      planKey: planKey || null, planName: planName || '',
      planDays: planDays || null,
      dealPayload: isDeal ? dealPayload : null,
      notifChannel: isNotifChannel ? notifChannel : null,
      notifChannelDays: isNotifChannel ? (notifChannelDays || 30) : null,
      status: 'pending',
      provider: 'marzpay',
      marzpayTransactionId: null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // CONFIRMED from MarzPay's own VALIDATION_ERROR response (see server
    // logs): it wants the phone number WITH country code, e.g.
    // +256712345678 — not local format. The local-format conversion below
    // was the actual cause of every "check your input" rejection.
    const marzPhone = '+' + normalizedPhone;

    let marzRes, marzData;
    try {
      marzRes = await fetch(`${MARZPAY_BASE_URL}/collect-money`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': marzpayAuthHeader()
        },
        body: JSON.stringify({
          phone_number: marzPhone,
          amount: amount,
          country: 'UG',
          reference: ref,
          description: isDeal ? `LowHub deal submission (${dealPayload.adIds.length} ad(s))` : isNotifChannel ? `LowHub ${notifChannel} notifications` : `LowHub ${planName || planKey} plan`,
          ...(callbackUrl ? { callback_url: callbackUrl } : {})
        })
      });
      marzData = await marzRes.json();
      // Log MarzPay's complete raw response (not just .message) so a
      // rejection ever seen again shows the real, specific validation
      // detail instead of a generic passthrough string like "Please check
      // your input and try again."
      console.log('[collect] MarzPay raw response:', JSON.stringify(marzData));
    } catch (fetchErr) {
      await paymentRef.update({ status: 'failed', failureReason: 'Could not reach MarzPay.', updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      console.error('[collect] MarzPay request failed:', fetchErr.message);
      return res.status(502).json({ success: false, error: 'Could not reach the payment provider. Please try again.' });
    }

    if (!marzRes.ok || (marzData.status !== true && marzData.status !== 'success' && !marzData.success)) {
      const errMsg = marzData?.message || 'MarzPay declined the request.';
      // Store MarzPay's full raw response alongside the short message so
      // the actual cause is visible from the Firestore document itself
      // (autoPayments/{id}.marzpayRawResponse) — no need to dig through
      // Render logs. errMsg alone is often generic (e.g. "Please check
      // your input and try again.") and doesn't say which field/value
      // MarzPay objected to.
      await paymentRef.update({
        status: 'failed',
        failureReason: errMsg,
        marzpayRawResponse: JSON.stringify(marzData).slice(0, 2000),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      return res.status(400).json({ success: false, error: errMsg });
    }

    const txId = marzData?.data?.transaction?.uuid || marzData?.data?.id || marzData?.data?.collection_id || null;
    await paymentRef.update({
      marzpayTransactionId: txId,
      status: 'processing',
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // Kick off a background poller as a backstop in case the webhook is
    // delayed or never arrives — MarzPay's own docs recommend this.
    if (txId) pollMarzpayStatus(paymentRef.id, txId).catch(e => console.error('[poll] error:', e.message));

    res.json({ success: true, paymentId: paymentRef.id, transactionId: txId });

  } catch (e) {
    console.error('[collect] error:', e);
    res.status(500).json({ success: false, error: 'Internal server error starting payment.' });
  }
});

// MarzPay calls this URL when a collection completes or fails. Field names
// are read defensively (checked against several likely variants) since the
// exact webhook shape should be confirmed against your live MarzPay
// dashboard docs/playground before going to production — verify at
// https://wallet.wearemarz.com/documentation/webhooks and adjust the
// extractStatus/extractTxId helpers below if your account's payload differs.
app.post('/api/payments/webhook', async (req, res) => {
  // Always ack quickly so MarzPay doesn't retry unnecessarily.
  res.status(200).json({ received: true });
  if (!db) return;

  try {
    const body = req.body || {};
    console.log('[webhook] received:', JSON.stringify(body).slice(0, 500));

    const txId = extractTxId(body);
    const status = extractStatus(body);
    if (!txId) { console.warn('[webhook] no transaction id found in payload'); return; }

    // One shared webhook URL handles both collections (money IN, from
    // /collect-money) and disbursements (money OUT, from /send-money —
    // wallet withdrawals). Try withdrawal first since applyWithdrawalStatus
    // can tell us definitively whether this txId belongs to it (returns
    // false if not, with no side effects) — only fall through to the
    // collections/premium/deal/order path if it doesn't.
    const wasWithdrawal = await applyWithdrawalStatus(txId, status, body);
    if (!wasWithdrawal) {
      await applyPaymentStatus(txId, status, body);
    }
  } catch (e) {
    console.error('[webhook] error:', e.message);
  }
});

// Collection (collect-money) callbacks nest the transaction under `data`;
// disbursement (send-money) callbacks — per MarzPay's own Send Money docs —
// put `transaction` at the TOP level instead (event_type:
// "disbursement.completed"/"disbursement.failed", transaction.uuid,
// transaction.status). Check both shapes so one webhook handler covers
// both payment directions.
function extractTxId(body) {
  return body?.transaction?.uuid || body?.data?.transaction?.uuid || body?.data?.id
    || body?.transaction_id || body?.reference || body?.data?.reference || body?.uuid || null;
}
function extractStatus(body) {
  const raw = (body?.event_type || body?.transaction?.status || body?.data?.transaction?.status
    || body?.data?.status || body?.status || body?.event || '').toString().toLowerCase();
  if (raw.includes('success') || raw.includes('complete')) return 'completed';
  if (raw.includes('fail') || raw.includes('decline') || raw.includes('cancel')) return 'failed';
  return 'pending';
}

// Shared status-application logic used by both the webhook and the poller,
// so a payment can only be activated once no matter which path detects it.
async function applyPaymentStatus(marzpayTxId, status, rawPayload) {
  const snap = await db.collection('autoPayments')
    .where('marzpayTransactionId', '==', marzpayTxId)
    .limit(1).get();
  if (snap.empty) { console.warn('[payment] no autoPayments doc for tx', marzpayTxId); return; }

  const doc = snap.docs[0];
  const data = doc.data();

  // Idempotency guard — never process the same payment twice (e.g. if both
  // the webhook and the poller detect completion around the same time).
  if (data.status === 'completed' || data.status === 'failed') return;

  if (status === 'completed') {
    await doc.ref.update({
      status: 'completed',
      completedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      rawWebhook: JSON.stringify(rawPayload).slice(0, 3000)
    });
    // Automatic payments skip admin review entirely and apply their result
    // immediately — that's the whole point of "automatic" mode. Manual
    // payments (screenshot upload) always still go through admin approval
    // in admin.html / admin-payments.html, regardless of this branch.
    if (data.purpose === 'deal') {
      await activateDealFromPayment(data);
    } else if (data.purpose === 'order') {
      await activateOrderFromPayment(data);
    } else if (data.purpose === 'notifChannel') {
      await activateNotifChannelFromPayment(data);
    } else {
      await activatePremiumPlan(data);
    }
  } else if (status === 'failed') {
    await doc.ref.update({
      status: 'failed',
      failureReason: rawPayload?.data?.message || rawPayload?.message || 'Payment was declined or cancelled.',
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    if (data.purpose === 'order' && data.orderId) {
      await db.collection('orders').doc(data.orderId).update({
        paymentStatus: 'failed', orderStatus: 'payment_failed', updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      await logOrderEvent(data.orderId, { type: 'paymentFailed', actorRole: 'system', metadata: { reason: rawPayload?.data?.message || rawPayload?.message || null } });
      const orderSnap = await db.collection('orders').doc(data.orderId).get();
      if (orderSnap.exists) {
        await db.collection('userNotifications').add({
          userId: orderSnap.data().buyerId, type: 'paymentFailed',
          message: `Payment failed for order ${orderSnap.data().orderNumber}. Your order has not been confirmed.`,
          link: `order.html?id=${data.orderId}`, read: false, createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
      }
    }
  }
  // 'pending' — leave as-is, poller/webhook will fire again later.
}

// Confirms an order's payment once MarzPay reports success. Moves the order
// PAID -> SELLER_CONFIRMATION (spec §11 — seller must still confirm
// availability even after payment) and permanently deducts the already-
// reserved stock (spec §5 — confirmed/paid order deducts quantity; it was
// only "reserved", not yet deducted, at order-creation time). This is the
// ONLY code path allowed to set paymentStatus:'paid' — never the browser,
// never a generic status-update endpoint (spec §13, §19).
async function activateOrderFromPayment(payment) {
  const orderRef = db.collection('orders').doc(payment.orderId);
  const orderSnap = await orderRef.get();
  if (!orderSnap.exists) { console.warn('[order] no order found for payment', payment.orderId); return; }
  const order = orderSnap.data();

  if (order.paymentStatus === 'paid') return; // idempotency guard

  await orderRef.update({
    paymentStatus: 'paid',
    orderStatus: 'seller_confirmation',
    transactionRef: payment.reference || null,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    'statusTimestamps.paid': admin.firestore.FieldValue.serverTimestamp(),
    'statusTimestamps.seller_confirmation': admin.firestore.FieldValue.serverTimestamp()
  });

  await logOrderEvent(payment.orderId, { type: 'paymentConfirmed', actorRole: 'system', metadata: { reference: payment.reference || null } });
  await logOrderEvent(payment.orderId, { type: 'sellerConfirmationRequested', actorRole: 'system', metadata: {} });

  await db.collection('userNotifications').add({
    userId: order.buyerId, type: 'paymentSuccess',
    message: `Payment received for order ${order.orderNumber}. Waiting for seller confirmation.`,
    link: `order.html?id=${payment.orderId}`, read: false, createdAt: admin.firestore.FieldValue.serverTimestamp()
  });
  await db.collection('userNotifications').add({
    userId: order.sellerId, type: 'orderPaid',
    message: `Order ${order.orderNumber} has been paid. Please confirm availability.`,
    link: `seller-orders.html?id=${payment.orderId}`, read: false, createdAt: admin.firestore.FieldValue.serverTimestamp()
  });
  await db.collection('pendingPush').add({
    userId: order.sellerId, title: 'Order Paid', body: `Order ${order.orderNumber} — please confirm availability.`,
    link: `/seller-orders.html?id=${payment.orderId}`, sent: false, createdAt: admin.firestore.FieldValue.serverTimestamp()
  });

  // ── Credit the seller's wallet (spec: "seller sees that money in their
  // dashboard"). Amount = order.subtotal only (product revenue) — the
  // delivery fee is never the seller's money, same convention already used
  // by seller-analytics.html's "Revenue (Completed)" figure. This is the
  // ONLY code path that credits a wallet from an order (mirrors
  // paymentStatus:'paid' being backend-only, see firestore.rules).
  await creditWallet({
    userId: order.sellerId,
    amount: order.subtotal || 0,
    orderId: payment.orderId,
    orderNumber: order.orderNumber,
    description: `Sale — ${order.productSnapshot?.title || 'Order'} (${order.orderNumber})`
  });
}

// Credits a seller's wallet and writes the matching ledger row inside one
// Firestore transaction, so balance and ledger can never drift apart even
// under concurrent orders completing at the same moment. Idempotent per
// order: if a walletTransactions row already exists for this orderId, it
// does nothing (guards against the webhook and poller both firing for the
// same payment — same pattern as applyPaymentStatus's own guard above).
async function creditWallet({ userId, amount, orderId, orderNumber, description, notify = true }) {
  if (!userId || !orderId || !amount || amount <= 0) return false;

  // First recognize older ledger rows created before this idempotency fix.
  // orderId alone is a single-field query and does not require a composite
  // index. The deterministic document below handles concurrent webhook +
  // poller execution safely.
  const legacy = await db.collection('walletTransactions')
    .where('orderId', '==', orderId).limit(1).get();
  if (!legacy.empty) return false;

  const walletRef = db.collection('wallets').doc(userId);
  const txRef = db.collection('walletTransactions').doc(`sale_${orderId}`);
  let credited = false;

  await db.runTransaction(async (tx) => {
    const existing = await tx.get(txRef);
    if (existing.exists) return; // concurrent/previous credit

    const walletSnap = await tx.get(walletRef);
    const current = walletSnap.exists ? walletSnap.data() : { balance: 0, totalEarned: 0, totalWithdrawn: 0 };
    const newBalance = (current.balance || 0) + amount;

    tx.set(walletRef, {
      balance: newBalance,
      totalEarned: (current.totalEarned || 0) + amount,
      totalWithdrawn: current.totalWithdrawn || 0,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    tx.set(txRef, {
      userId, type: 'credit', source: 'order_payment', amount,
      status: 'completed', orderId, orderNumber: orderNumber || null,
      withdrawalId: null, description: description || 'Sale',
      balanceAfter: newBalance,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    credited = true;
  });

  if (credited && notify) {
    await db.collection('userNotifications').add({
      userId, type: 'walletCredit',
      message: `${amount.toLocaleString()} UGX added to your LowHub wallet from ${description || 'a sale'}.`,
      link: `wallet.html`, read: false, createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
  }
  return credited;
}

// Repairs any previously-paid seller orders whose wallet credit was missed
// by an older version of the payment handler. sellerId is the only query
// filter, so this does not depend on a composite Firestore index.
async function reconcileSellerWallet(userId) {
  if (!userId) return;
  const snap = await db.collection('orders').where('sellerId', '==', userId).get();
  for (const doc of snap.docs) {
    const order = doc.data();
    if (order.paymentStatus !== 'paid') continue;
    await creditWallet({
      userId, amount: order.subtotal || 0, orderId: doc.id,
      orderNumber: order.orderNumber,
      description: `Sale — ${order.productSnapshot?.title || 'Order'} (${order.orderNumber || doc.id})`,
      notify: false
    });
  }
}

// Activates the user's premium plan in Firestore once payment is confirmed
// — mirrors the shape admin.html's confirmPremium() writes, so both the
// manual-approval path and the automatic-payment path produce identical
// premiumPlans documents.
async function activatePremiumPlan(payment) {
  const days = payment.planDays || 30;
  const now = new Date();
  const expires = new Date(now.getTime() + days * 86400000);

  await db.collection('premiumPlans').add({
    userId: payment.userId,
    planName: payment.planName || payment.planKey,
    planKey: payment.planKey,
    planDays: days,
    status: 'active',
    activatedAt: admin.firestore.FieldValue.serverTimestamp(),
    expiresAt: expires,
    source: 'marzpay_automatic'
  });

  const listingsSnap = await db.collection('listings')
    .where('userId', '==', payment.userId)
    .where('status', '==', 'approved').get();
  const batch = db.batch();
  listingsSnap.forEach(d => batch.update(d.ref, { boosted: true }));
  await batch.commit();

  await db.collection('userNotifications').add({
    userId: payment.userId,
    type: 'premiumActivated',
    title: 'Payment Successful',
    message: `Your "${payment.planName || payment.planKey}" plan is now active! Your ads are boosted.`,
    link: 'dashboard.html',
    read: false,
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  });

  // Also queue a real device push for this user (see section 2 below).
  await db.collection('pendingPush').add({
    userId: payment.userId,
    title: 'Payment Successful',
    body: `Your ${payment.planName || payment.planKey} plan is now active!`,
    link: '/dashboard.html',
    sent: false,
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  });
}

// Grants a user access to one notification channel (email/sms/whatsapp/
// telegram) once its automatic MarzPay payment is confirmed. Mirrors
// activatePremiumPlan's expiry-window shape but writes into
// userNotificationAccess/{uid}.{channel} instead of a premiumPlans doc,
// since a user can hold several of these at once (independent per channel).
async function activateNotifChannelFromPayment(payment) {
  const channel = payment.notifChannel;
  if (!NOTIF_CHANNELS.includes(channel)) {
    console.warn('[notif-channel] activateNotifChannelFromPayment called with invalid channel', payment);
    return;
  }
  const days = payment.notifChannelDays || 30;
  const expires = new Date(Date.now() + days * 86400000);

  await db.collection('userNotificationAccess').doc(payment.userId).set({
    [channel]: {
      active: true,
      source: 'payment',
      expiresAt: expires,
      activatedAt: admin.firestore.FieldValue.serverTimestamp()
    }
  }, { merge: true });

  const channelLabel = channel.charAt(0).toUpperCase() + channel.slice(1);
  await db.collection('userNotifications').add({
    userId: payment.userId,
    type: 'notifChannelActivated',
    title: 'Payment Successful',
    message: `${channelLabel} notifications are now active on your account for ${days} day(s).`,
    link: 'notification-settings.html',
    read: false,
    outboundProcessed: true, // avoid immediately re-billing/looping this confirmation through the very channel just paid for
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  });

  await db.collection('pendingPush').add({
    userId: payment.userId,
    title: 'Payment Successful',
    body: `${channelLabel} notifications are now active!`,
    link: '/notification-settings.html',
    sent: false,
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  });
}

// Makes a deal submission live in Firestore once its automatic payment is
// confirmed — mirrors the shape admin.html's approveDealRequest() writes
// (deals/{id} per selected ad + isDeal/dealLabel on the listing), so an
// auto-approved deal is indistinguishable from a manually-approved one
// once it's live. Also writes a dealRequests record (status: 'approved',
// source: 'marzpay_automatic') purely so it still shows up in the admin's
// Deal Requests list for their records — no action needed from them.
async function activateDealFromPayment(payment) {
  const d = payment.dealPayload || {};
  const adIds = Array.isArray(d.adIds) ? d.adIds : [];
  const selectedAds = Array.isArray(d.selectedAds) ? d.selectedAds : [];
  if (!adIds.length) {
    console.warn('[deal] activateDealFromPayment called with no adIds — skipping', payment);
    return;
  }

  const duration = d.duration || 1;
  const startDate = new Date();
  const endDate = new Date(startDate.getTime() + duration * 86400000);

  // Record it in dealRequests too (already 'approved') so admin still sees
  // it for their records, exactly like the note in admin-payments.html says
  // automatic payments do ("they'll still show here for your records").
  const dealReqRef = db.collection('dealRequests').doc();
  const batch = db.batch();
  batch.set(dealReqRef, {
    userId: payment.userId,
    userName: payment.userName || '',
    userEmail: payment.userEmail || '',
    selectedAds, adIds, duration,
    heading: d.heading || 'Deal',
    content: d.content || '',
    discountLabel: d.discountLabel || '',
    paymentMethod: 'marzpay',
    totalAmount: payment.amount,
    status: 'approved',
    source: 'marzpay_automatic',
    submittedAt: admin.firestore.FieldValue.serverTimestamp(),
    approvedAt: admin.firestore.FieldValue.serverTimestamp()
  });

  for (const adId of adIds) {
    const ad = selectedAds.find(a => a.id === adId) || {};
    const dealRef = db.collection('deals').doc();
    batch.set(dealRef, {
      listingId: adId,
      title: d.heading || 'Deal',
      discountLabel: d.discountLabel || '',
      content: d.content || '',
      userDealRequestId: dealReqRef.id,
      userId: payment.userId,
      active: true,
      expiresAt: endDate.toISOString(),
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    batch.update(db.collection('listings').doc(adId), {
      isDeal: true,
      dealLabel: d.discountLabel || d.heading || 'Deal'
    });
  }

  await batch.commit();

  await db.collection('userNotifications').add({
    userId: payment.userId,
    type: 'dealApproved',
    title: 'Payment Successful',
    message: `Your deal "${d.heading || 'Deal'}" is now live! (${adIds.length} ad(s) · ${duration} day(s))`,
    link: 'my-ads.html',
    read: false,
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  });

  await db.collection('pendingPush').add({
    userId: payment.userId,
    title: 'Deal Live!',
    body: `Your deal "${d.heading || 'Deal'}" is now live on LowHub!`,
    link: '/my-ads.html',
    sent: false,
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  });
}


async function pollMarzpayStatus(paymentDocId, txId) {
  // MarzPay's own webhook (see the /marzpay-webhook route above) is the
  // authoritative source of truth for a transaction reaching completed/
  // failed — it fires whenever MarzPay finishes, independent of this
  // poller, and order.html watches the order doc live via onSnapshot, so a
  // buyer who stays on the page sees the result the moment the webhook
  // lands even if this poller has already given up. This poller exists
  // only as a backstop for the (much less common) case where the webhook
  // never arrives — e.g. dropped delivery, misconfigured webhook URL.
  //
  // MarzPay's own collection responses have shown estimated_settlement
  // times of 4-5 minutes out from initiation (seen in production logs:
  // initiated 11:34:12, estimated_settlement 11:39:12 — a ~5 minute gap),
  // so a ~2.5 minute window (25 x 6s) gives up before MarzPay is typically
  // even done, producing "gave up waiting" log noise for transactions that
  // go on to complete normally via the webhook seconds later. Widening to
  // 60 attempts x 8s = 8 minutes covers that typical settlement window with
  // margin, while still eventually stopping rather than polling forever.
  const maxAttempts = 60;
  const intervalMs = 8000;
  for (let i = 0; i < maxAttempts; i++) {
    await new Promise(r => setTimeout(r, intervalMs));
    try {
      const statusRes = await fetch(`${MARZPAY_BASE_URL}/transactions/${txId}`, {
        headers: { 'Authorization': marzpayAuthHeader() }
      });
      if (!statusRes.ok) continue;
      const statusData = await statusRes.json();
      const status = extractStatus(statusData);
      if (status === 'completed' || status === 'failed') {
        await applyPaymentStatus(txId, status, statusData);
        return;
      }
    } catch (e) {
      console.error('[poll] attempt error:', e.message);
    }
  }
  // Stopping here does NOT mean the payment failed or is stuck — it only
  // means this poller is no longer checking. The order/payment docs are
  // left exactly as they were (paymentStatus: 'pending'), and the webhook
  // can still arrive and complete them at any point after this log line.
  console.warn('[poll] gave up after', maxAttempts * intervalMs / 1000, 'seconds for transaction', txId, '— order left pending; webhook may still complete it later');
}

// ─────────────────────────────────────────────────────────────────────────
// 1B. SELLER WALLET — balance, transaction history, withdrawal via MarzPay
//     send-money (disbursements). Mirrors the collections (/collect-money)
//     flow above as closely as possible: same UUID v4 reference requirement,
//     same +256 phone format, same multipart/form-data body, same
//     webhook + poller backstop pattern — see MarzPay's own Send Money docs
//     (https://wallet.wearemarz.com/documentation/send-money), which use
//     identical conventions to the collections endpoint this file already
//     has working.
// ─────────────────────────────────────────────────────────────────────────

// GET /api/wallet/summary — balance + lifetime totals for the caller.
app.get('/api/wallet/summary', requireAuth, async (req, res) => {
  if (!requireDb(res)) return;
  try {
    await reconcileSellerWallet(req.authUid);
    const snap = await db.collection('wallets').doc(req.authUid).get();
    const w = snap.exists ? snap.data() : { balance: 0, totalEarned: 0, totalWithdrawn: 0 };
    const feeSnap = await db.collection('siteConfig').doc('walletSettings').get();
    const feePercent = (feeSnap.exists && typeof feeSnap.data().withdrawalFeePercent === 'number')
      ? feeSnap.data().withdrawalFeePercent : 0;
    res.json({
      success: true,
      balance: w.balance || 0,
      totalEarned: w.totalEarned || 0,
      totalWithdrawn: w.totalWithdrawn || 0,
      withdrawalFeePercent: feePercent
    });
  } catch (e) {
    console.error('[wallet/summary] error:', e.message);
    res.status(500).json({ success: false, error: 'Could not load wallet.' });
  }
});

// GET /api/wallet/transactions — this seller's own ledger (credits +
// debits), for the "transaction history" view (spec: successful/
// unsuccessful, timestamp, what it was for). Firestore rules already
// restrict walletTransactions reads to the doc's own userId, but this
// endpoint filters server-side too so the frontend can call it plainly
// (and so a future non-Firestore-SDK client — e.g. a mobile app — has a
// normal REST path instead of needing the Firestore SDK at all).
app.get('/api/wallet/transactions', requireAuth, async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 500, 500);
    const snap = await db.collection('walletTransactions')
      .where('userId', '==', req.authUid)
      .get();
    const transactions = snap.docs.map(d => {
      const t = d.data();
      return {
        id: d.id, type: t.type, source: t.source, amount: t.amount, status: t.status,
        orderId: t.orderId || null, orderNumber: t.orderNumber || null,
        withdrawalId: t.withdrawalId || null, description: t.description || '',
        balanceAfter: t.balanceAfter,
        createdAt: t.createdAt ? t.createdAt.toDate().toISOString() : null
      };
    }).sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0)).slice(0, limit);
    res.json({ success: true, transactions });
  } catch (e) {
    console.error('[wallet/transactions] error:', e.message);
    res.status(500).json({ success: false, error: 'Could not load transaction history.' });
  }
});

// POST /api/wallet/withdraw — body: { phone, amount }
// Starts a MarzPay send-money disbursement to the seller's own mobile money
// number. The requested amount is deducted from the wallet balance
// UP FRONT (status: 'pending' in the ledger) so a seller can never
// double-spend by firing two withdrawals before either resolves — if the
// disbursement later fails, applyWithdrawalStatus() below refunds it.
// This mirrors how order creation reserves stock before payment confirms it.
app.post('/api/wallet/withdraw', requireAuth, async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const { phone, amount } = req.body || {};
    const uid = req.authUid;
    const amountRequested = Number(amount);

    if (!phone) return res.status(400).json({ success: false, error: 'Phone number is required.' });
    if (!amountRequested || amountRequested <= 0) return res.status(400).json({ success: false, error: 'Enter a valid amount.' });
    if (amountRequested < 500) return res.status(400).json({ success: false, error: 'Minimum withdrawal is UGX 500 (MarzPay\'s own minimum).' });
    if (!MARZPAY_API_KEY || !MARZPAY_API_SECRET) {
      return res.status(500).json({ success: false, error: 'Withdrawals are not configured on the server yet.' });
    }

    const normalizedPhone = normalizePhone(phone);
    if (!isValidUgandaPhone(normalizedPhone)) {
      return res.status(400).json({ success: false, error: 'Please enter a valid mobile money number, e.g. 0755 123456.' });
    }

    const walletRef = db.collection('wallets').doc(uid);
    const feeSnap = await db.collection('siteConfig').doc('walletSettings').get();
    const feePercent = (feeSnap.exists && typeof feeSnap.data().withdrawalFeePercent === 'number')
      ? feeSnap.data().withdrawalFeePercent : 0;
    const feeAmount = Math.round(amountRequested * (feePercent / 100));
    const amountSent = amountRequested - feeAmount;
    if (amountSent < 500) return res.status(400).json({ success: false, error: 'Amount after fee is below MarzPay\'s UGX 500 minimum.' });

    const withdrawalRef = db.collection('autoWithdrawals').doc();
    const txRef = db.collection('walletTransactions').doc();

    // Reserve the funds (deduct from balance now, refund on failure) inside
    // a transaction so two concurrent withdrawals can never both read the
    // same starting balance and overdraw the wallet.
    try {
      await db.runTransaction(async (tx) => {
        const walletSnap = await tx.get(walletRef);
        const current = walletSnap.exists ? walletSnap.data() : { balance: 0, totalEarned: 0, totalWithdrawn: 0 };
        const balance = current.balance || 0;
        if (balance < amountRequested) {
          throw new UserFacingError(`Insufficient balance. Available: UGX ${balance.toLocaleString()}.`);
        }
        const newBalance = balance - amountRequested;
        tx.set(walletRef, {
          balance: newBalance,
          totalEarned: current.totalEarned || 0,
          totalWithdrawn: current.totalWithdrawn || 0, // only incremented once withdrawal actually completes
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
        tx.set(txRef, {
          userId: uid, type: 'debit', source: 'withdrawal', amount: amountRequested,
          status: 'pending', orderId: null, orderNumber: null, withdrawalId: withdrawalRef.id,
          description: `Withdrawal to ${normalizedPhone}${feeAmount ? ` (fee ${feeAmount.toLocaleString()} UGX)` : ''}`,
          balanceAfter: newBalance,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
      });
    } catch (e) {
      if (e instanceof UserFacingError) return res.status(400).json({ success: false, error: e.message });
      throw e;
    }

    const ref = crypto.randomUUID();
    const internalRef = `LH-WD-${uid}-${Date.now()}`;
    const callbackUrl = PUBLIC_BACKEND_URL ? `${PUBLIC_BACKEND_URL}/api/payments/webhook` : undefined;

    await withdrawalRef.set({
      userId: uid, userEmail: req.authEmail || '', userName: '',
      phone: normalizedPhone, amountRequested, feePercent, feeAmount, amountSent,
      reference: ref, internalRef, status: 'pending', marzpayTransactionId: null,
      failureReason: null, rawWebhook: null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    const marzPhone = '+' + normalizedPhone;
    let marzRes, marzData;
    try {
      // NOTE ON REQUEST FORMAT: MarzPay's published docs show send-money
      // (and collect-money) as multipart/form-data (`--form` in their curl
      // examples). However, THIS account's /collect-money integration —
      // above in this same file, already proven working against real
      // MarzPay responses — needed a plain JSON body instead. Since
      // send-money is the sibling endpoint on the same account/API keys,
      // this follows that proven JSON convention rather than the generic
      // docs example. If MarzPay rejects this with a format-related
      // VALIDATION_ERROR (check the Render logs for the raw response
      // logged below), switch this one call to multipart/form-data — see
      // the commented alternative just below — without touching
      // collect-money, which is unrelated and already works.
      marzRes = await fetchWithTimeout(`${MARZPAY_BASE_URL}/send-money`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': marzpayAuthHeader() },
        body: JSON.stringify({
          phone_number: marzPhone, amount: amountSent, country: 'UG', reference: ref,
          description: `LowHub wallet withdrawal`,
          ...(callbackUrl ? { callback_url: callbackUrl } : {})
        }, 120000) // Give MarzPay up to 120 seconds to return a response.
        // Multipart alternative, if JSON gets rejected for this endpoint:
        //   const form = new URLSearchParams();
        //   form.append('phone_number', marzPhone); form.append('amount', String(amountSent));
        //   form.append('country', 'UG'); form.append('reference', ref);
        //   form.append('description', 'LowHub wallet withdrawal');
        //   if (callbackUrl) form.append('callback_url', callbackUrl);
        //   ... headers: { 'Authorization': marzpayAuthHeader() }, body: form
      });
      marzData = await marzRes.json();
      console.log('[wallet/withdraw] MarzPay raw response:', JSON.stringify(marzData));
    } catch (fetchErr) {
      // If MarzPay gives absolutely no HTTP response within 120 seconds,
      // assume the transfer request reached the provider and complete the
      // withdrawal. This is the requested safety fallback because the user
      // may already have received the money even though MarzPay never
      // returned its response to LowHub. A real provider error response is
      // handled below and is NOT treated as a timeout.
      if (fetchErr && fetchErr.name === 'AbortError') {
        await completeWithdrawalFallback(withdrawalRef.id, {
          fallback: true,
          reason: 'MarzPay returned no response within 120 seconds.',
          reference: ref
        });
        return res.status(200).json({ success: true, completed: true, withdrawalId: withdrawalRef.id, amountSent, feeAmount, message: 'MarzPay did not respond within 120 seconds. The withdrawal has been marked completed.' });
      }
      await refundWithdrawal(withdrawalRef.id, 'Could not reach MarzPay.');
      return res.status(502).json({ success: false, error: 'Could not reach the payment provider. Your balance has been restored — please try again.' });
    }

    if (!marzRes.ok || (marzData.status !== true && marzData.status !== 'success' && !marzData.success)) {
      const errMsg = marzData?.message || 'MarzPay declined the withdrawal.';
      await refundWithdrawal(withdrawalRef.id, errMsg, marzData);
      return res.status(400).json({ success: false, error: errMsg + ' Your balance has been restored.' });
    }

    const txId = marzData?.data?.transaction?.uuid || marzData?.data?.id || null;
    const providerStatus = marzData?.data?.transaction?.status || marzData?.transaction?.status || null;
    // MarzPay's create response normally says `processing`. Even if a provider
    // returns an unusual success response, only an explicit transaction-level
    // completed status is allowed to complete the wallet withdrawal.
    await withdrawalRef.update({ marzpayTransactionId: txId, status: 'processing', providerStatus: providerStatus || 'processing', updatedAt: admin.firestore.FieldValue.serverTimestamp() });

    if (txId) pollMarzpayWithdrawalStatus(withdrawalRef.id, txId, null).catch(e => console.error('[poll-withdraw] error:', e.message));
    else pollMarzpayWithdrawalStatus(withdrawalRef.id, null, ref).catch(e => console.error('[poll-withdraw-reference] error:', e.message));

    res.json({ success: true, pending: true, withdrawalId: withdrawalRef.id, amountSent, feeAmount, message: 'Withdrawal submitted and is processing. It will only be marked completed after MarzPay confirms the transfer.' });
  } catch (e) {
    console.error('[wallet/withdraw] error:', e);
    res.status(500).json({ success: false, error: 'Internal server error starting withdrawal.' });
  }
});

// Fallback completion used only when MarzPay gives no HTTP response for
// the full 120-second initiation window. The balance was already reserved
// at withdrawal creation, so completion only increments totalWithdrawn and
// closes the ledger row. Idempotency prevents double counting if a webhook
// races with this fallback.
async function completeWithdrawalFallback(withdrawalId, rawPayload) {
  const withdrawalRef = db.collection('autoWithdrawals').doc(withdrawalId);
  const walletRef = db.collection('wallets');
  const txQuery = db.collection('walletTransactions').where('withdrawalId', '==', withdrawalId).limit(1);

  const result = await db.runTransaction(async (tx) => {
    const withdrawalSnap = await tx.get(withdrawalRef);
    if (!withdrawalSnap.exists) return null;
    const w = withdrawalSnap.data();
    if (w.status === 'completed') return w;
    if (w.status === 'failed') return null;

    const userWalletRef = walletRef.doc(w.userId);
    const walletSnap = await tx.get(userWalletRef);
    const current = walletSnap.exists ? walletSnap.data() : { balance: 0, totalEarned: 0, totalWithdrawn: 0 };
    const txSnap = await txQuery.get();

    tx.update(withdrawalRef, {
      status: 'completed',
      completedAt: admin.firestore.FieldValue.serverTimestamp(),
      providerResponseTimeout: true,
      failureReason: null,
      rawWebhook: JSON.stringify(rawPayload || {}).slice(0, 3000),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    tx.set(userWalletRef, {
      totalWithdrawn: (current.totalWithdrawn || 0) + w.amountRequested,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
    if (!txSnap.empty) {
      tx.update(txSnap.docs[0].ref, {
        status: 'completed',
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }
    return w;
  });

  if (result) {
    await db.collection('userNotifications').add({
      userId: result.userId,
      type: 'withdrawalCompleted',
      message: `UGX ${result.amountSent.toLocaleString()} sent to ${result.phone}. Withdrawal complete.`,
      link: 'wallet.html',
      read: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
  }
  return !!result;
}

// Refunds a reserved withdrawal back into the seller's wallet balance and
// marks both the autoWithdrawals doc and its ledger row as failed. Used
// when MarzPay rejects the request outright (before we even get a
// transaction id to poll/webhook against).
async function refundWithdrawal(withdrawalId, reason, rawResponse) {
  const withdrawalRef = db.collection('autoWithdrawals').doc(withdrawalId);
  const withdrawalSnap = await withdrawalRef.get();
  if (!withdrawalSnap.exists) return;
  const w = withdrawalSnap.data();
  if (w.status === 'failed' || w.status === 'completed') return; // idempotency guard

  await withdrawalRef.update({
    status: 'failed', failureReason: reason || 'Withdrawal failed.',
    rawWebhook: rawResponse ? JSON.stringify(rawResponse).slice(0, 2000) : null,
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  });

  const walletRef = db.collection('wallets').doc(w.userId);
  const txSnap = await db.collection('walletTransactions')
    .where('withdrawalId', '==', withdrawalId).limit(1).get();

  await db.runTransaction(async (tx) => {
    const walletSnap = await tx.get(walletRef);
    const current = walletSnap.exists ? walletSnap.data() : { balance: 0, totalEarned: 0, totalWithdrawn: 0 };
    const newBalance = (current.balance || 0) + w.amountRequested;
    tx.set(walletRef, { balance: newBalance, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    if (!txSnap.empty) {
      tx.update(txSnap.docs[0].ref, {
        status: 'failed', description: `Withdrawal failed — refunded (${reason || 'declined'})`,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }
  });

  await db.collection('userNotifications').add({
    userId: w.userId, type: 'withdrawalFailed',
    message: `Your withdrawal of UGX ${w.amountRequested.toLocaleString()} failed and has been refunded to your wallet. Reason: ${reason || 'declined'}`,
    link: `wallet.html`, read: false, createdAt: admin.firestore.FieldValue.serverTimestamp()
  });
}

// Marks a withdrawal (already sent to MarzPay, now confirmed) as completed —
// increments totalWithdrawn, does NOT touch balance again (it was already
// deducted at request time). Called from both the webhook and the poller,
// same dual-path backstop pattern as applyPaymentStatus for collections.
async function applyWithdrawalStatus(marzpayTxId, status, rawPayload) {
  const snap = await db.collection('autoWithdrawals')
    .where('marzpayTransactionId', '==', marzpayTxId).limit(1).get();
  if (snap.empty) return false; // not a withdrawal tx — let the caller try collections instead

  const doc = snap.docs[0];
  const w = doc.data();
  if (w.status === 'completed' || w.status === 'failed') return true; // idempotency guard

  if (status === 'completed') {
    await doc.ref.update({
      status: 'completed', completedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      rawWebhook: JSON.stringify(rawPayload).slice(0, 3000)
    });

    const walletRef = db.collection('wallets').doc(w.userId);
    const txSnap = await db.collection('walletTransactions')
      .where('withdrawalId', '==', doc.id).limit(1).get();
    await db.runTransaction(async (tx) => {
      const walletSnap = await tx.get(walletRef);
      const current = walletSnap.exists ? walletSnap.data() : { balance: 0, totalEarned: 0, totalWithdrawn: 0 };
      tx.set(walletRef, {
        totalWithdrawn: (current.totalWithdrawn || 0) + w.amountRequested,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
      if (!txSnap.empty) {
        tx.update(txSnap.docs[0].ref, { status: 'completed', updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      }
    });

    await db.collection('userNotifications').add({
      userId: w.userId, type: 'withdrawalCompleted',
      message: `UGX ${w.amountSent.toLocaleString()} sent to ${w.phone}. Withdrawal complete.`,
      link: `wallet.html`, read: false, createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
  } else if (status === 'failed') {
    await refundWithdrawal(doc.id, rawPayload?.data?.message || rawPayload?.message || 'Payment provider declined or reversed the transfer.', rawPayload);
  }
  return true;
}

async function pollMarzpayWithdrawalStatus(withdrawalDocId, txId, reference) {
  const maxAttempts = 40; // up to ~6 minutes, with webhooks as the primary path
  for (let i = 0; i < maxAttempts; i++) {
    await new Promise(r => setTimeout(r, 6000));
    try {
      const identifier = txId || reference;
      if (!identifier) return;
      // MarzPay documents transaction lookup by UUID/reference and returns the
      // same webhook-shaped transaction object. This lets us recover even when
      // the initial send-money POST timed out before returning its UUID.
      const endpoint = txId
        ? `${MARZPAY_BASE_URL}/send-money/${encodeURIComponent(txId)}`
        : `${MARZPAY_BASE_URL}/transactions/${encodeURIComponent(reference)}`;
      const statusRes = await fetchWithTimeout(endpoint, {
        headers: { 'Authorization': marzpayAuthHeader() }
      }, 15000);
      if (!statusRes.ok) continue;
      const statusData = await statusRes.json();
      const tx = statusData?.transaction || statusData?.data?.transaction || null;
      const statusRaw = tx?.status;
      const status = typeof statusRaw === 'string' ? statusRaw.toLowerCase() : '';
      const resolvedTxId = tx?.uuid || txId || null;
      if (resolvedTxId && !txId) {
        await db.collection('autoWithdrawals').doc(withdrawalDocId).update({ marzpayTransactionId: resolvedTxId, updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      }
      if (status === 'completed' || status === 'successful' || status === 'success') {
        await applyWithdrawalStatus(resolvedTxId, 'completed', statusData);
        return;
      }
      if (status === 'failed' || status === 'cancelled' || status === 'canceled') {
        await applyWithdrawalStatus(resolvedTxId, 'failed', statusData);
        return;
      }
    } catch (e) {
      console.error('[poll-withdraw] attempt error:', e.message);
    }
  }
  console.warn('[poll-withdraw] still pending after polling window', withdrawalDocId);
}

// GET /api/admin/wallet-settings — public read of the current withdrawal
// fee so wallet.html can show "you'll receive X after fee" without needing
// the admin token (fee percent is not secret).
app.get('/api/admin/wallet-settings', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const snap = await db.collection('siteConfig').doc('walletSettings').get();
    const feePercent = (snap.exists && typeof snap.data().withdrawalFeePercent === 'number') ? snap.data().withdrawalFeePercent : null;
    res.json({ success: true, withdrawalFeePercent: feePercent });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /api/admin/wallet-settings — admin sets (or clears) the withdrawal
// fee percentage. Same X-Admin-Token pattern as /api/admin/payment-settings.
app.post('/api/admin/wallet-settings', async (req, res) => {
  if (!requireDb(res)) return;
  if (!checkAdminToken(req, res)) return;
  try {
    const { withdrawalFeePercent } = req.body || {};
    let value = null;
    if (withdrawalFeePercent !== null && withdrawalFeePercent !== undefined && withdrawalFeePercent !== '') {
      value = Number(withdrawalFeePercent);
      if (isNaN(value) || value < 0 || value > 100) {
        return res.status(400).json({ success: false, error: 'Fee must be a number between 0 and 100.' });
      }
    }
    await db.collection('siteConfig').doc('walletSettings').set({
      withdrawalFeePercent: value,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────
// 2. REAL DEVICE PUSH — processes the pendingPush queue via FCM Admin SDK
// ─────────────────────────────────────────────────────────────────────────
async function processPendingPush() {
  if (!db) return;
  try {
    const snap = await db.collection('pendingPush').where('sent', '==', false).limit(25).get();
    if (snap.empty) return;

    for (const doc of snap.docs) {
      const p = doc.data();
      try {
        if (p.forAll) {
          await sendToAllUsers(p.title, p.body, p.link);
        } else if (p.userId) {
          await sendToUser(p.userId, p.title, p.body, p.link);
        }
        await doc.ref.update({ sent: true, sentAt: admin.firestore.FieldValue.serverTimestamp() });
      } catch (sendErr) {
        console.error('[push] failed to send', doc.id, sendErr.message);
        await doc.ref.update({ sent: true, error: sendErr.message, sentAt: admin.firestore.FieldValue.serverTimestamp() });
      }
    }
  } catch (e) {
    if (e.message && e.message.includes('DECODER routines::unsupported')) {
      console.error('[push] queue processing error: gRPC could not decode the service account private key.');
      console.error('[push] Re-download a fresh service account JSON from Firebase Console > Project Settings > Service Accounts,');
      console.error('[push] then paste its ENTIRE contents (unmodified) as the value of FIREBASE_SERVICE_ACCOUNT in Render.');
    } else {
      console.error('[push] queue processing error:', e.message);
    }
  }
}

async function sendToUser(userId, title, body, link) {
  const tokenDoc = await db.collection('pushTokens').doc(userId).get();
  if (!tokenDoc.exists) return;
  const token = tokenDoc.data().token;
  if (!token) return;

  await admin.messaging().send({
    token,
    notification: { title: title || 'LowHub', body: body || '' },
    data: { link: link || '/' },
    webpush: { fcmOptions: { link: link || '/' } }
  });
}

async function sendToAllUsers(title, body, link) {
  const tokensSnap = await db.collection('pushTokens').get();
  const tokens = tokensSnap.docs.map(d => d.data().token).filter(Boolean);
  if (tokens.length === 0) return;

  // FCM multicast caps at 500 tokens per call.
  for (let i = 0; i < tokens.length; i += 500) {
    const batch = tokens.slice(i, i + 500);
    try {
      await admin.messaging().sendEachForMulticast({
        tokens: batch,
        notification: { title: title || 'LowHub', body: body || '' },
        data: { link: link || '/' },
        webpush: { fcmOptions: { link: link || '/' } }
      });
    } catch (e) {
      console.error('[push] multicast batch failed:', e.message);
    }
  }
}

// Poll the queue every 15 seconds.
setInterval(processPendingPush, 15000);

// ─────────────────────────────────────────────────────────────────────────
// 2B. MULTI-CHANNEL NOTIFICATIONS — Email / SMS / WhatsApp / Telegram
// ─────────────────────────────────────────────────────────────────────────
// Design mirrors the pendingPush queue above as closely as possible:
//
//   - siteConfig/notificationChannels holds, per channel (email/sms/
//     whatsapp/telegram): { enabled, free, price, days, provider,
//     credentials:{...} }. Only ever read/written from THIS server via the
//     admin-token-protected endpoints below — the browser never receives
//     the credentials back in plaintext (see GET /api/admin/notification-
//     channels, which strips secret values before responding).
//
//   - userNotificationAccess/{uid} holds, per channel, whether that user
//     currently has access: { active, expiresAt, source }. `source` is
//     'payment' (via MarzPay, same automatic flow as Premium/Deals) or
//     'manual' (admin toggled it on/off by hand). A channel with
//     channelConfig.free === true is treated as active for every user
//     automatically, no document needed.
//
//   - Every real notification in this app already funnels through one of
//     two writes: db.collection('userNotifications').add({...}) (server)
//     or firebase.firestore().collection('userNotifications').add({...})
//     (browser, in lh-push.js / admin-notifications.html). Rather than
//     touching every one of those ~15 call sites, this poller watches that
//     SAME collection for new docs and fans each one out across whichever
//     channels the target user currently has access to. Device push
//     (FCM, via pendingPush above) is untouched and stays free/unconditional
//     per the spec — this is a separate, additive delivery path.
//
//   - Real provider credentials (EmailJS/Infobip/Green API/WhatsApp Cloud/
//     Telegram bot token) live ONLY inside the credentials object saved by
//     the admin endpoints below, stored in Firestore. This intentionally
//     differs from MarzPay/Firebase (Render env vars) because these are
//     per-deployment, admin-editable, non-infrastructure secrets the admin
//     needs to change from the UI without a redeploy — same tradeoff
//     admin.html already makes for e.g. AI settings. Firestore security
//     rules must keep siteConfig/notificationChannels unreadable by normal
//     authenticated users (see firestore.rules — add a matching rule).
// ─────────────────────────────────────────────────────────────────────────

const NOTIF_CHANNELS = ['email', 'sms', 'whatsapp', 'telegram'];

async function getChannelConfig() {
  if (!db) return {};
  const snap = await db.collection('siteConfig').doc('notificationChannels').get();
  return snap.exists ? (snap.data() || {}) : {};
}

// Does this user currently have active access to `channel`? `free` only
// means "no payment required" — it does NOT mean "on for everyone by
// default". A user must still have explicitly opted in (via the free
// toggle in notification-settings.html, a completed payment, or an admin
// manual grant) before anything is actually sent to them. This was
// previously short-circuiting on cfg.free alone, which would have emailed/
// texted/messaged every single user the moment the admin marked a channel
// free, regardless of whether that person ever visited their notification
// settings or entered contact details for it — the opposite of "only
// deliver through channels the user themselves turned on".
async function userHasChannelAccess(userId, channel, channelCfg) {
  const cfg = channelCfg[channel] || {};
  if (!cfg.enabled) return false;
  if (!userId) return false;
  try {
    const accSnap = await db.collection('userNotificationAccess').doc(userId).get();
    if (!accSnap.exists) return false;
    const acc = (accSnap.data() || {})[channel];
    if (!acc || !acc.active) return false;
    // Free channels are opted into via the toggle in notification-settings.html
    // (source: 'user-free-toggle') and never expire on their own — the
    // user's own switch is the only thing that turns them off again. Paid
    // and manually-granted access still honor expiresAt below.
    if (cfg.free && acc.source === 'user-free-toggle') return true;
    if (!acc.expiresAt) return true; // indefinite manual grant
    const exp = typeof acc.expiresAt.toDate === 'function' ? acc.expiresAt.toDate() : new Date(acc.expiresAt);
    return exp.getTime() >= Date.now();
  } catch (e) {
    console.error('[notif-access] lookup failed:', e.message);
    return false;
  }
}

// ── Provider senders ────────────────────────────────────────────────────
// Each returns nothing on success and throws on failure — caller logs the
// failure onto the outboundNotifications doc, same pattern as pendingPush.

async function sendEmailViaProvider(cfg, toEmail, title, message) {
  if (!toEmail) throw new Error('User has no email on file.');
  const c = cfg.credentials || {};
  if (cfg.provider === 'infobip') {
    if (!c.infobipBaseUrl || !c.infobipApiKey || !c.infobipSenderEmail) throw new Error('Infobip email credentials incomplete.');
    const url = `${c.infobipBaseUrl.replace(/\/+$/, '')}/email/3/send`;
    const form = new URLSearchParams();
    form.append('from', c.infobipSenderEmail);
    form.append('to', toEmail);
    form.append('subject', title || 'LowHub notification');
    form.append('text', message || '');
    const r = await fetchWithTimeout(url, {
      method: 'POST',
      headers: { 'Authorization': `App ${c.infobipApiKey}` },
      body: form
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data?.requestError?.serviceException?.text || `Infobip email failed (${r.status}).`);
  } else {
    // Default: EmailJS (https://www.emailjs.com/docs/rest-api/send/)
    if (!c.emailjsServiceId || !c.emailjsTemplateId || !c.emailjsPublicKey) throw new Error('EmailJS credentials incomplete.');
    const r = await fetchWithTimeout('https://api.emailjs.com/api/v1.0/email/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        service_id: c.emailjsServiceId,
        template_id: c.emailjsTemplateId,
        user_id: c.emailjsPublicKey,
        accessToken: c.emailjsPrivateKey || undefined,
        template_params: { to_email: toEmail, subject: title || 'LowHub notification', message: message || '' }
      })
    });
    if (!r.ok) {
      const text = await r.text().catch(() => '');
      throw new Error(`EmailJS failed (${r.status}): ${text.slice(0, 200)}`);
    }
  }
}

async function sendSmsViaProvider(cfg, toPhone, message) {
  if (!toPhone) throw new Error('User has no phone on file.');
  const c = cfg.credentials || {};
  if (!c.infobipBaseUrl || !c.infobipApiKey || !c.infobipSenderId) throw new Error('Infobip SMS credentials incomplete.');
  const normalized = normalizePhone(toPhone);
  const url = `${c.infobipBaseUrl.replace(/\/+$/, '')}/sms/2/text/advanced`;
  const r = await fetchWithTimeout(url, {
    method: 'POST',
    headers: { 'Authorization': `App ${c.infobipApiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      messages: [{ from: c.infobipSenderId, destinations: [{ to: normalized }], text: message || '' }]
    })
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data?.requestError?.serviceException?.text || `Infobip SMS failed (${r.status}).`);
}

async function sendWhatsAppViaProvider(cfg, toPhone, message) {
  if (!toPhone) throw new Error('User has no phone on file.');
  const c = cfg.credentials || {};
  const normalized = normalizePhone(toPhone);
  if (cfg.provider === 'green-api') {
    if (!c.greenApiInstanceId || !c.greenApiToken) throw new Error('Green API credentials incomplete.');
    const url = `https://api.green-api.com/waInstance${c.greenApiInstanceId}/sendMessage/${c.greenApiToken}`;
    const r = await fetchWithTimeout(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chatId: `${normalized}@c.us`, message: message || '' })
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data?.error || `Green API failed (${r.status}).`);
  } else {
    // Default: official WhatsApp Cloud API (Meta)
    if (!c.waPhoneNumberId || !c.waAccessToken) throw new Error('WhatsApp Cloud API credentials incomplete.');
    const url = `https://graph.facebook.com/v20.0/${c.waPhoneNumberId}/messages`;
    const r = await fetchWithTimeout(url, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${c.waAccessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messaging_product: 'whatsapp',
        to: normalized,
        type: 'text',
        text: { body: message || '' }
      })
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data?.error?.message || `WhatsApp Cloud API failed (${r.status}).`);
  }
}

async function sendTelegramViaProvider(cfg, chatId, title, message) {
  if (!chatId) throw new Error('User has not linked a Telegram chat ID.');
  const c = cfg.credentials || {};
  if (!c.telegramBotToken) throw new Error('Telegram bot token not configured.');
  const url = `https://api.telegram.org/bot${c.telegramBotToken}/sendMessage`;
  const text = title ? `*${title}*\n${message || ''}` : (message || '');
  const r = await fetchWithTimeout(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'Markdown' })
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok || data.ok === false) throw new Error(data?.description || `Telegram send failed (${r.status}).`);
}

// Watches userNotifications for docs not yet fanned out to external
// channels (outboundProcessed !== true) and delivers to every channel the
// target user has access to. Marks the doc processed either way so it's
// never retried forever on a permanently-broken config.
async function processOutboundNotifications() {
  if (!db) return;
  try {
    // Docs created by the BACKEND explicitly set outboundProcessed: false
    // (or true, to opt out — see e.g. activateNotifChannelFromPayment).
    // Docs created by the BROWSER (lh-push.js, admin-notifications.html)
    // never set this field at all, since that pre-dates this feature and
    // client code cannot be relied on to add it correctly everywhere. A
    // single `where('outboundProcessed','==',false)` query would silently
    // skip every client-created doc forever. Firestore also can't combine
    // an equality and a "field missing" clause in one query, so this runs
    // both queries and merges results, de-duplicated by doc id.
    const [explicitSnap, legacySnap] = await Promise.all([
      db.collection('userNotifications').where('outboundProcessed', '==', false).limit(25).get(),
      db.collection('userNotifications').orderBy('createdAt', 'desc').limit(50).get()
    ]);
    const seen = new Set();
    const docs = [];
    for (const d of explicitSnap.docs) { if (!seen.has(d.id)) { seen.add(d.id); docs.push(d); } }
    for (const d of legacySnap.docs) {
      if (seen.has(d.id)) continue;
      if (d.data().outboundProcessed === undefined) { seen.add(d.id); docs.push(d); }
    }
    if (!docs.length) return;
    const snap = { empty: false, docs, forEach: (fn) => docs.forEach(fn) };

    const channelCfg = await getChannelConfig();
    const anyEnabled = NOTIF_CHANNELS.some(ch => channelCfg[ch] && channelCfg[ch].enabled);
    if (!anyEnabled) {
      // Nothing configured yet — mark processed so this query stops
      // re-scanning the same docs every 20s until the admin sets it up.
      const batch = db.batch();
      snap.forEach(d => batch.update(d.ref, { outboundProcessed: true }));
      await batch.commit();
      return;
    }

    for (const doc of snap.docs) {
      const n = doc.data();
      const results = {};
      try {
        if (!n.userId) { await doc.ref.update({ outboundProcessed: true }); continue; }
        const userSnap = await db.collection('users').doc(n.userId).get();
        const user = userSnap.exists ? userSnap.data() : {};
        const title = n.title || 'LowHub';
        const message = n.message || '';

        for (const channel of NOTIF_CHANNELS) {
          const cfg = channelCfg[channel];
          if (!cfg || !cfg.enabled) continue;
          const hasAccess = await userHasChannelAccess(n.userId, channel, channelCfg);
          if (!hasAccess) continue;
          try {
            if (channel === 'email') await sendEmailViaProvider(cfg, user.email, title, message);
            else if (channel === 'sms') await sendSmsViaProvider(cfg, user.phone, message);
            else if (channel === 'whatsapp') await sendWhatsAppViaProvider(cfg, user.phone, message);
            else if (channel === 'telegram') await sendTelegramViaProvider(cfg, user.telegramChatId, title, message);
            results[channel] = 'sent';
          } catch (chErr) {
            console.error(`[notif-outbound] ${channel} failed for user ${n.userId}:`, chErr.message);
            results[channel] = 'failed: ' + chErr.message;
          }
        }
      } catch (e) {
        console.error('[notif-outbound] doc error:', e.message);
      }
      await doc.ref.update({ outboundProcessed: true, outboundResults: results, outboundAt: admin.firestore.FieldValue.serverTimestamp() });
    }
  } catch (e) {
    console.error('[notif-outbound] queue processing error:', e.message);
  }
}

// Poll every 20 seconds — separate cadence from device push since these
// calls hit external paid APIs and don't need push's tighter latency.
setInterval(processOutboundNotifications, 20000);

// GET /api/admin/notification-channels — returns current settings with
// credentials REDACTED (booleans only: whether each secret field is set),
// so the admin UI can show "already configured" without ever re-displaying
// the actual key. The admin re-enters credentials only when changing them.
app.get('/api/admin/notification-channels', async (req, res) => {
  if (!requireDb(res)) return;
  if (!checkAdminToken(req, res)) return;
  try {
    const cfg = await getChannelConfig();
    const redacted = {};
    for (const ch of NOTIF_CHANNELS) {
      const c = cfg[ch] || {};
      const creds = c.credentials || {};
      const credsPresent = {};
      for (const k of Object.keys(creds)) credsPresent[k] = !!creds[k];
      redacted[ch] = {
        enabled: !!c.enabled, free: !!c.free,
        price: typeof c.price === 'number' ? c.price : null,
        days: typeof c.days === 'number' ? c.days : null,
        provider: c.provider || null,
        credentialsPresent: credsPresent
      };
    }
    res.json({ success: true, channels: redacted });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /api/admin/notification-channels — save one channel's settings.
// Body: { channel: 'email'|'sms'|'whatsapp'|'telegram', enabled, free,
//          price, days, provider, credentials: {...} }
// A credentials field left blank/undefined by the admin is NOT overwritten
// (so re-saving the price doesn't wipe out an already-saved API key) —
// only keys actually present in the request body's credentials object are
// merged in, individually.
app.post('/api/admin/notification-channels', async (req, res) => {
  if (!requireDb(res)) return;
  if (!checkAdminToken(req, res)) return;
  try {
    const { channel, enabled, free, price, days, provider, credentials } = req.body || {};
    if (!NOTIF_CHANNELS.includes(channel)) {
      return res.status(400).json({ success: false, error: `channel must be one of: ${NOTIF_CHANNELS.join(', ')}` });
    }
    const docRef = db.collection('siteConfig').doc('notificationChannels');
    const existingSnap = await docRef.get();
    const existing = (existingSnap.exists ? existingSnap.data() : {}) || {};
    const existingChannel = existing[channel] || {};
    const existingCreds = existingChannel.credentials || {};

    const mergedCreds = { ...existingCreds };
    if (credentials && typeof credentials === 'object') {
      for (const [k, v] of Object.entries(credentials)) {
        if (v !== undefined && v !== null && String(v).trim() !== '') mergedCreds[k] = String(v).trim();
      }
    }

    let cleanPrice = existingChannel.price ?? null;
    if (price !== undefined) {
      if (price === null || price === '') cleanPrice = null;
      else {
        const n = Number(price);
        if (isNaN(n) || n < 0) return res.status(400).json({ success: false, error: 'price must be a non-negative number.' });
        cleanPrice = n;
      }
    }
    let cleanDays = existingChannel.days ?? null;
    if (days !== undefined) {
      if (days === null || days === '') cleanDays = null;
      else {
        const n = Number(days);
        if (isNaN(n) || n < 1) return res.status(400).json({ success: false, error: 'days must be a positive number.' });
        cleanDays = n;
      }
    }

    const finalEnabled = enabled !== undefined ? !!enabled : !!existingChannel.enabled;
    const finalFree = free !== undefined ? !!free : !!existingChannel.free;
    const finalProvider = provider !== undefined ? (provider || null) : (existingChannel.provider || null);

    await docRef.set({
      [channel]: {
        enabled: finalEnabled,
        free: finalFree,
        price: cleanPrice,
        days: cleanDays,
        provider: finalProvider,
        credentials: mergedCreds
      },
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    // Also mirror the NON-secret fields into a public doc that the browser
    // (notification-settings.html) is allowed to read directly — see
    // firestore.rules: siteConfig/notificationChannelsPublic is
    // `allow read: if true`, unlike the private doc above. This keeps
    // secrets fully server-side while still letting the pricing UI render
    // without adding another backend round trip just to show a price.
    // telegramBotUsername is intentionally included here (not a secret —
    // it's the @handle users message to link their account).
    const publicRef = db.collection('siteConfig').doc('notificationChannelsPublic');
    const publicEntry = {
      enabled: finalEnabled, free: finalFree, price: cleanPrice, days: cleanDays
    };
    if (channel === 'telegram') publicEntry.telegramBotUsername = mergedCreds.telegramBotUsername || null;
    await publicRef.set({ [channel]: publicEntry, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /api/notifications/toggle-free-channel — lets a SIGNED-IN USER
// (not admin) turn a channel on/off for themselves, but ONLY when that
// channel is marked `free` by the admin. requireAuth derives the caller's
// uid from their Firebase ID token — the request body's userId is never
// trusted, same rule the orders endpoints already follow. This exists so
// userNotificationAccess/{uid} can stay fully server-write-only in
// firestore.rules (no client writes at all) while still letting the free-
// toggle switch in notification-settings.html work without going through
// the paid/manual grant machinery.
app.post('/api/notifications/toggle-free-channel', requireAuth, async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const { channel, on } = req.body || {};
    if (!NOTIF_CHANNELS.includes(channel)) {
      return res.status(400).json({ success: false, error: `channel must be one of: ${NOTIF_CHANNELS.join(', ')}` });
    }
    const channelCfg = await getChannelConfig();
    const cfg = channelCfg[channel];
    if (!cfg || !cfg.enabled || !cfg.free) {
      return res.status(403).json({ success: false, error: 'This channel is not free — payment or an admin grant is required.' });
    }
    await db.collection('userNotificationAccess').doc(req.authUid).set({
      [channel]: { active: !!on, source: 'user-free-toggle', updatedAt: admin.firestore.FieldValue.serverTimestamp() }
    }, { merge: true });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// GET /api/admin/notification-access?userId=... — admin looks up one
// user's current per-channel access (for the manual grant/revoke UI).
app.get('/api/admin/notification-access', async (req, res) => {
  if (!requireDb(res)) return;
  if (!checkAdminToken(req, res)) return;
  try {
    const { userId } = req.query;
    if (!userId) return res.status(400).json({ success: false, error: 'userId query param required.' });
    const snap = await db.collection('userNotificationAccess').doc(userId).get();
    res.json({ success: true, access: snap.exists ? snap.data() : {} });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /api/admin/notification-access — admin manually grants or revokes
// one channel for one user. Body: { userId, channel, action: 'grant'|'revoke', days? }
// A manual grant with no `days` given is treated as indefinite (no expiresAt).
app.post('/api/admin/notification-access', async (req, res) => {
  if (!requireDb(res)) return;
  if (!checkAdminToken(req, res)) return;
  try {
    const { userId, channel, action, days } = req.body || {};
    if (!userId || !NOTIF_CHANNELS.includes(channel) || !['grant', 'revoke'].includes(action)) {
      return res.status(400).json({ success: false, error: 'userId, valid channel, and action (grant|revoke) are required.' });
    }
    const docRef = db.collection('userNotificationAccess').doc(userId);
    if (action === 'revoke') {
      await docRef.set({ [channel]: { active: false, source: 'manual', updatedAt: admin.firestore.FieldValue.serverTimestamp() } }, { merge: true });
    } else {
      const entry = { active: true, source: 'manual', updatedAt: admin.firestore.FieldValue.serverTimestamp() };
      if (days) {
        const n = Number(days);
        if (!isNaN(n) && n > 0) entry.expiresAt = new Date(Date.now() + n * 86400000);
      }
      await docRef.set({ [channel]: entry }, { merge: true });
      await db.collection('userNotifications').add({
        userId, type: 'notifChannelGranted', title: 'Notifications Enabled',
        message: `An admin has enabled ${channel} notifications for your account.`,
        link: 'notification-settings.html', read: false, outboundProcessed: true,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────
// ADMIN FINANCE + PICKUP OPERATIONS
// These endpoints are intentionally admin-token protected. The existing
// browser admin login is sessionStorage based, so it cannot be represented as
// a Firebase Auth claim. Never expose the token in source code.
// ─────────────────────────────────────────────────────────────────────────

function tsIso(v) {
  if (!v) return null;
  try {
    if (typeof v.toDate === 'function') return v.toDate().toISOString();
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  } catch (_) { return null; }
}

app.get('/api/admin/transactions', async (req, res) => {
  if (!requireDb(res)) return;
  if (!checkAdminToken(req, res)) return;
  try {
    const [walletSnap, paymentsSnap, withdrawalsSnap, premiumSnap, dealsSnap, usersSnap, ordersSnap] = await Promise.all([
      db.collection('walletTransactions').get(),
      db.collection('autoPayments').get(),
      db.collection('autoWithdrawals').get(),
      db.collection('premiumRequests').get(),
      db.collection('dealRequests').get(),
      db.collection('users').get(),
      db.collection('orders').get()
    ]);

    const users = {};
    usersSnap.forEach(d => { users[d.id] = { id: d.id, ...(d.data() || {}) }; });
    const person = (uid, fallbackName, fallbackEmail) => {
      const u = users[uid] || {};
      return {
        userId: uid || null,
        name: u.name || fallbackName || 'Unknown user',
        email: u.email || fallbackEmail || '',
        phone: u.phone || ''
      };
    };

    const orders = {};
    ordersSnap.forEach(d => { orders[d.id] = d.data() || {}; });

    const rows = [];
    paymentsSnap.forEach(d => {
      const p = d.data() || {};
      rows.push({
        id: d.id, kind: 'payment', source: 'autoPayments', purpose: p.purpose || 'payment',
        amount: Number(p.amount || 0), status: p.status || 'unknown',
        reference: p.reference || p.internalRef || p.marzpayTransactionId || '',
        actor: person(p.userId, p.userName, p.userEmail),
        counterparty: p.orderId && orders[p.orderId] ? {
          buyer: person(orders[p.orderId].buyerId, orders[p.orderId].buyerSnapshot?.name, ''),
          seller: person(orders[p.orderId].sellerId, orders[p.orderId].sellerSnapshot?.name, '')
        } : null,
        description: p.purpose === 'order' ? `Order ${p.orderNumber || p.orderId || ''}` :
          p.purpose === 'deal' ? `Deal payment${p.planName ? ` — ${p.planName}` : ''}` :
          `Premium — ${p.planName || p.planKey || 'Plan'}`,
        orderId: p.orderId || null, orderNumber: p.orderNumber || null,
        createdAt: tsIso(p.createdAt), completedAt: tsIso(p.completedAt),
        provider: p.provider || 'marzpay'
      });
    });

    walletSnap.forEach(d => {
      const t = d.data() || {};
      rows.push({
        id: d.id, kind: 'wallet', source: t.source || 'wallet', purpose: t.type || 'wallet',
        amount: Number(t.amount || 0), status: t.status || 'unknown',
        reference: t.withdrawalId || t.orderNumber || t.orderId || d.id,
        actor: person(t.userId),
        counterparty: t.orderId && orders[t.orderId] ? {
          buyer: person(orders[t.orderId].buyerId, orders[t.orderId].buyerSnapshot?.name, ''),
          seller: person(orders[t.orderId].sellerId, orders[t.orderId].sellerSnapshot?.name, '')
        } : null,
        description: t.description || (t.type === 'credit' ? 'Wallet credit' : 'Wallet debit'),
        orderId: t.orderId || null, orderNumber: t.orderNumber || null,
        createdAt: tsIso(t.createdAt), completedAt: null, provider: t.type === 'debit' ? 'marzpay' : 'lowhub'
      });
    });

    withdrawalsSnap.forEach(d => {
      const w = d.data() || {};
      rows.push({
        id: d.id, kind: 'withdrawal', source: 'autoWithdrawals', purpose: 'withdrawal',
        amount: Number(w.amountRequested || 0), amountSent: Number(w.amountSent || 0), status: w.status || 'unknown',
        reference: w.reference || w.marzpayTransactionId || d.id, actor: person(w.userId),
        description: `Withdrawal to ${w.phone || 'mobile money'}`,
        orderId: null, orderNumber: null, createdAt: tsIso(w.createdAt), completedAt: tsIso(w.completedAt), provider: 'marzpay'
      });
    });

    premiumSnap.forEach(d => {
      const r = d.data() || {};
      rows.push({
        id: d.id, kind: 'manual_payment', source: 'premiumRequests', purpose: 'premium',
        amount: Number(r.planPrice || 0), status: r.status || 'unknown',
        reference: r.transactionRef || d.id, actor: person(r.userId, r.userName, r.userEmail),
        description: `Manual Premium — ${r.planName || r.planKey || 'Plan'}`,
        orderId: null, orderNumber: null, createdAt: tsIso(r.requestedAt || r.createdAt), completedAt: null, provider: r.paymentMethod || 'manual'
      });
    });

    dealsSnap.forEach(d => {
      const r = d.data() || {};
      rows.push({
        id: d.id, kind: 'manual_payment', source: 'dealRequests', purpose: 'deal',
        amount: Number(r.totalAmount || 0), status: r.status || 'unknown',
        reference: r.transactionRef || d.id, actor: person(r.userId, r.userName, r.userEmail),
        description: `Manual Deal — ${r.heading || 'Deal'}`,
        orderId: null, orderNumber: null, createdAt: tsIso(r.submittedAt || r.createdAt), completedAt: null, provider: r.paymentMethod || 'manual'
      });
    });

    rows.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
    res.json({ success: true, transactions: rows, generatedAt: new Date().toISOString() });
  } catch (e) {
    console.error('[admin/transactions] error:', e);
    res.status(500).json({ success: false, error: 'Could not load transactions.' });
  }
});

app.get('/api/admin/pickup-dashboard', async (req, res) => {
  if (!requireDb(res)) return;
  if (!checkAdminToken(req, res)) return;
  try {
    const [stationsSnap, ordersSnap] = await Promise.all([
      db.collection('pickupStations').get(),
      db.collection('orders').where('deliveryMethod', '==', 'pickup_station').get()
    ]);
    const stations = stationsSnap.docs.map(d => ({ id: d.id, ...d.data() }));
    const stationMap = Object.fromEntries(stations.map(s => [s.id, s]));
    const orders = ordersSnap.docs.map(d => {
      const o = d.data() || {};
      const st = stationMap[o.pickupStationId] || {};
      return {
        id: d.id, orderNumber: o.orderNumber || d.id.slice(0, 8), orderStatus: o.orderStatus || '',
        paymentStatus: o.paymentStatus || '', product: o.productSnapshot || {}, quantity: o.quantity || 1,
        subtotal: Number(o.subtotal || 0), total: Number(o.total || 0), deliveryFee: Number(o.deliveryFee || 0),
        buyer: o.buyerSnapshot || {}, seller: o.sellerSnapshot || {}, buyerId: o.buyerId || null, sellerId: o.sellerId || null,
        pickupStationId: o.pickupStationId || null, pickupStation: { id: st.id || null, name: st.name || 'Unknown station', address: st.address || st.location || '' },
        pickupOtp: o.pickupOtp || null, createdAt: tsIso(o.createdAt), updatedAt: tsIso(o.updatedAt)
      };
    }).sort((a,b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
    const stats = {
      total: orders.length,
      awaiting: orders.filter(o => ['paid','seller_confirmation','confirmed','processing','ready_for_dispatch'].includes(o.orderStatus)).length,
      ready: orders.filter(o => o.orderStatus === 'ready_for_pickup').length,
      pickedUp: orders.filter(o => ['picked_up','completed'].includes(o.orderStatus)).length
    };
    res.json({ success: true, stations, orders, stats });
  } catch (e) {
    console.error('[admin/pickup-dashboard] error:', e);
    res.status(500).json({ success: false, error: 'Could not load pickup dashboard.' });
  }
});

app.post('/api/admin/pickup/status', async (req, res) => {
  if (!requireDb(res)) return;
  if (!checkAdminToken(req, res)) return;
  try {
    const { orderId, newStatus } = req.body || {};
    if (!orderId || newStatus !== 'ready_for_pickup') return res.status(400).json({ success:false, error:'Only marking an order ready for pickup is supported here.' });
    const ref = db.collection('orders').doc(orderId);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ success:false, error:'Order not found.' });
    const order = snap.data();
    if (order.deliveryMethod !== 'pickup_station') return res.status(400).json({ success:false, error:'This is not a pickup-station order.' });
    if (!canTransitionOrderStatus(order.orderStatus, newStatus)) return res.status(400).json({ success:false, error:`Cannot move order from "${order.orderStatus}" to "${newStatus}".` });
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    await ref.update({ orderStatus:newStatus, pickupOtp:otp, updatedAt:admin.firestore.FieldValue.serverTimestamp(), 'statusTimestamps.ready_for_pickup':admin.firestore.FieldValue.serverTimestamp() });
    await logOrderEvent(orderId, { type:'status_ready_for_pickup', actorId:'admin', actorRole:'admin', metadata:{} });
    await db.collection('userNotifications').add({ userId:order.buyerId, type:'orderStatusChanged', message:`Order ${order.orderNumber || orderId} is ready for pickup. Show your pickup code at the station.`, link:`order.html?id=${orderId}`, read:false, createdAt:admin.firestore.FieldValue.serverTimestamp() });
    res.json({success:true});
  } catch(e) {
    console.error('[admin/pickup/status] error:', e);
    res.status(500).json({success:false,error:'Could not update pickup order.'});
  }
});

app.post('/api/admin/pickup/verify', async (req, res) => {
  if (!requireDb(res)) return;
  if (!checkAdminToken(req, res)) return;
  try {
    const { orderId, otp } = req.body || {};
    const ref = db.collection('orders').doc(orderId);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({success:false,error:'Order not found.'});
    const order = snap.data();
    if (order.deliveryMethod !== 'pickup_station' || order.orderStatus !== 'ready_for_pickup') return res.status(400).json({success:false,error:'This order is not ready for pickup.'});
    if (!otp || String(otp) !== String(order.pickupOtp || '')) return res.status(400).json({success:false,error:'Incorrect pickup code.'});
    await ref.update({orderStatus:'picked_up', updatedAt:admin.firestore.FieldValue.serverTimestamp(), 'statusTimestamps.picked_up':admin.firestore.FieldValue.serverTimestamp()});
    await logOrderEvent(orderId, {type:'status_picked_up',actorId:'admin',actorRole:'admin',metadata:{}});
    await db.collection('userNotifications').add({userId:order.buyerId,type:'orderStatusChanged',message:`Order ${order.orderNumber || orderId} has been picked up.`,link:`order.html?id=${orderId}`,read:false,createdAt:admin.firestore.FieldValue.serverTimestamp()});
    res.json({success:true});
  } catch(e) {
    console.error('[admin/pickup/verify] error:', e);
    res.status(500).json({success:false,error:'Could not verify pickup.'});
  }
});

// ─────────────────────────────────────────────────────────────────────────
// 3. ADMIN PAYMENT SETTINGS
// ─────────────────────────────────────────────────────────────────────────
function checkAdminToken(req, res) {
  if (!ADMIN_API_TOKEN) {
    res.status(500).json({ success: false, error: 'Server ADMIN_API_TOKEN is not set.' });
    return false;
  }
  const provided = req.headers['x-admin-token'];
  if (provided !== ADMIN_API_TOKEN) {
    res.status(401).json({ success: false, error: 'Invalid admin token.' });
    return false;
  }
  return true;
}

// admin-payments.html calls this to save the mode toggle + backend/API
// config. NOTE: MarzPay keys themselves should stay in Render env vars, not
// Firestore — this endpoint only stores the *non-secret* settings (mode,
// backend URL) that the browser is allowed to read back via Firestore.
// admin-payments.html calls this once per location (Premium plans / Deal
// submissions) so each can independently be manual or automatic, with its
// own manual-mode instructions. `location` defaults to 'premium' so an
// older frontend build calling this without it still behaves the same as
// before (single global setting, now just stored at .premium).
app.post('/api/admin/payment-settings', async (req, res) => {
  if (!requireDb(res)) return;
  if (!checkAdminToken(req, res)) return;
  try {
    const { mode, backendUrl, instructions, location } = req.body || {};
    const loc = location === 'deals' ? 'deals' : 'premium';
    if (!['manual', 'automatic'].includes(mode)) {
      return res.status(400).json({ success: false, error: "mode must be 'manual' or 'automatic'." });
    }
    // instructions is optional: { mtn:{title,body}, airtel:{...}, bank:{...} }.
    // Any field the admin leaves blank is dropped here so the frontend's
    // own DEFAULT_PAYMENT_INSTRUCTIONS fallback applies for it — we never
    // store an empty string that would display as blank instead of the
    // default text.
    let cleanInstructions;
    if (instructions && typeof instructions === 'object') {
      cleanInstructions = {};
      for (const method of ['mtn', 'airtel', 'bank']) {
        const src = instructions[method];
        if (!src) continue;
        const entry = {};
        if (src.title && String(src.title).trim()) entry.title = String(src.title).trim();
        if (src.body && String(src.body).trim()) entry.body = String(src.body).trim();
        if (Object.keys(entry).length) cleanInstructions[method] = entry;
      }
    }
    await db.collection('siteConfig').doc('paymentSettings').set({
      [loc]: {
        mode, backendUrl: backendUrl || '',
        ...(cleanInstructions ? { instructions: cleanInstructions } : {})
      },
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`LowHub backend listening on port ${PORT}`);
  console.log(`Firebase configured: ${!!db}`);
  console.log(`MarzPay configured: ${!!(MARZPAY_API_KEY && MARZPAY_API_SECRET)}`);
});
