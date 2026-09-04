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

function requireDb(res) {
  if (!db) {
    res.status(500).json({ success: false, error: 'Server is missing Firebase configuration. Check Render environment variables.' });
    return false;
  }
  return true;
}

// Normalizes a Ugandan phone number to the 2567XXXXXXXX format MarzPay
// expects, accepting common local formats (0745..., 745..., +256745...).
function normalizePhone(raw) {
  let p = String(raw || '').replace(/[^\d]/g, '');
  if (p.startsWith('0')) p = '256' + p.slice(1);
  else if (p.startsWith('256')) { /* already fine */ }
  else if (p.length === 9) p = '256' + p;
  return p;
}

// ─────────────────────────────────────────────────────────────────────────
// HEALTH CHECK
// ─────────────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ ok: true, service: 'lowhub-backend', firebase: !!db });
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
      purpose, dealPayload
    } = req.body || {};

    const isDeal = purpose === 'deal';
    // planKey doubles as "what are we paying for" for premium; for deals we
    // just need an identifying label, so fall back to a fixed one.
    const itemKey = isDeal ? 'deal' : planKey;

    if (!userId || !phone || !amount || (!isDeal && !planKey)) {
      return res.status(400).json({ success: false, error: 'Missing required fields (userId, phone, amount, planKey).' });
    }
    if (isDeal && (!dealPayload || !Array.isArray(dealPayload.adIds) || !dealPayload.adIds.length)) {
      return res.status(400).json({ success: false, error: 'Missing deal details (selected ads).' });
    }
    if (!MARZPAY_API_KEY || !MARZPAY_API_SECRET) {
      return res.status(500).json({ success: false, error: 'Automatic payments are not configured on the server yet (missing MarzPay credentials).' });
    }

    const normalizedPhone = normalizePhone(phone);
    const ref = reference || `LH-${itemKey}-${Date.now()}`;
    const callbackUrl = PUBLIC_BACKEND_URL ? `${PUBLIC_BACKEND_URL}/api/payments/webhook` : undefined;

    // Create the Firestore tracking doc FIRST (status: pending) so the
    // frontend has something to poll even before MarzPay responds.
    const paymentRef = db.collection('autoPayments').doc();
    await paymentRef.set({
      userId, userEmail: userEmail || '', userName: userName || '',
      phone: normalizedPhone, amount, reference: ref,
      purpose: isDeal ? 'deal' : 'premium',
      planKey: planKey || null, planName: planName || '',
      planDays: planDays || null,
      dealPayload: isDeal ? dealPayload : null,
      status: 'pending',
      provider: 'marzpay',
      marzpayTransactionId: null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    let marzRes, marzData;
    try {
      marzRes = await fetch(`${MARZPAY_BASE_URL}/collect-money`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': marzpayAuthHeader()
        },
        body: JSON.stringify({
          phone_number: normalizedPhone,
          amount: amount,
          reference: ref,
          description: isDeal ? `LowHub deal submission (${dealPayload.adIds.length} ad(s))` : `LowHub ${planName || planKey} plan`,
          ...(callbackUrl ? { callback_url: callbackUrl } : {})
        })
      });
      marzData = await marzRes.json();
    } catch (fetchErr) {
      await paymentRef.update({ status: 'failed', failureReason: 'Could not reach MarzPay.', updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      console.error('[collect] MarzPay request failed:', fetchErr.message);
      return res.status(502).json({ success: false, error: 'Could not reach the payment provider. Please try again.' });
    }

    if (!marzRes.ok || (marzData.status !== true && marzData.status !== 'success' && !marzData.success)) {
      const errMsg = marzData?.message || 'MarzPay declined the request.';
      await paymentRef.update({ status: 'failed', failureReason: errMsg, updatedAt: admin.firestore.FieldValue.serverTimestamp() });
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

    await applyPaymentStatus(txId, status, body);
  } catch (e) {
    console.error('[webhook] error:', e.message);
  }
});

function extractTxId(body) {
  return body?.data?.transaction?.uuid || body?.data?.id || body?.transaction_id
    || body?.reference || body?.data?.reference || body?.uuid || null;
}
function extractStatus(body) {
  const raw = (body?.data?.transaction?.status || body?.data?.status || body?.status || body?.event || '').toString().toLowerCase();
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
    } else {
      await activatePremiumPlan(data);
    }
  } else if (status === 'failed') {
    await doc.ref.update({
      status: 'failed',
      failureReason: rawPayload?.data?.message || rawPayload?.message || 'Payment was declined or cancelled.',
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
  }
  // 'pending' — leave as-is, poller/webhook will fire again later.
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
  const maxAttempts = 25;
  for (let i = 0; i < maxAttempts; i++) {
    await new Promise(r => setTimeout(r, 6000));
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
  console.warn('[poll] gave up waiting for transaction', txId);
}

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
