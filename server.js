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
 *      FIREBASE_PROJECT_ID        e.g. lowhub-marketplace-ug
 *      FIREBASE_CLIENT_EMAIL      from your Firebase service account JSON
 *      FIREBASE_PRIVATE_KEY       from your Firebase service account JSON
 *                                  (paste with \n literal newlines — see
 *                                  note below)
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
 *      Getting the Firebase values: Firebase Console → Project Settings →
 *      Service Accounts → Generate New Private Key. That JSON file has
 *      "project_id", "client_email", and "private_key" — copy those three
 *      values into the env vars above. FIREBASE_PRIVATE_KEY contains real
 *      newlines in the JSON; when pasting into Render's single-line env var
 *      box, replace each newline with the two characters \n — this file
 *      converts them back automatically (see initFirebaseAdmin below).
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
function initFirebaseAdmin() {
  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  let privateKey = process.env.FIREBASE_PRIVATE_KEY;

  if (!projectId || !clientEmail || !privateKey) {
    console.error('[startup] Missing FIREBASE_PROJECT_ID / FIREBASE_CLIENT_EMAIL / FIREBASE_PRIVATE_KEY env vars.');
    console.error('[startup] The server will start, but every Firebase-dependent route will fail until these are set in Render.');
    return null;
  }

  // Render env vars are single-line, so the private key's real newlines are
  // typically pasted as the literal two-character sequence \n — convert back.
  privateKey = privateKey.replace(/\\n/g, '\n');

  admin.initializeApp({
    credential: admin.credential.cert({ projectId, clientEmail, privateKey })
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
    const { userId, userEmail, userName, phone, amount, planKey, planName, planDays, reference } = req.body || {};

    if (!userId || !phone || !amount || !planKey) {
      return res.status(400).json({ success: false, error: 'Missing required fields (userId, phone, amount, planKey).' });
    }
    if (!MARZPAY_API_KEY || !MARZPAY_API_SECRET) {
      return res.status(500).json({ success: false, error: 'Automatic payments are not configured on the server yet (missing MarzPay credentials).' });
    }

    const normalizedPhone = normalizePhone(phone);
    const ref = reference || `LH-${planKey}-${Date.now()}`;
    const callbackUrl = PUBLIC_BACKEND_URL ? `${PUBLIC_BACKEND_URL}/api/payments/webhook` : undefined;

    // Create the Firestore tracking doc FIRST (status: pending) so the
    // frontend has something to poll even before MarzPay responds.
    const paymentRef = db.collection('autoPayments').doc();
    await paymentRef.set({
      userId, userEmail: userEmail || '', userName: userName || '',
      phone: normalizedPhone, amount, planKey, planName: planName || '',
      planDays: planDays || null, reference: ref,
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
          description: `LowHub ${planName || planKey} plan`,
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
    await activatePremiumPlan(data);
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

// Backstop poller: checks MarzPay's own status endpoint a few times in case
// the webhook never arrives. Stops once resolved or after ~2.5 minutes.
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
    console.error('[push] queue processing error:', e.message);
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
app.post('/api/admin/payment-settings', async (req, res) => {
  if (!requireDb(res)) return;
  if (!checkAdminToken(req, res)) return;
  try {
    const { mode, backendUrl } = req.body || {};
    if (!['manual', 'automatic'].includes(mode)) {
      return res.status(400).json({ success: false, error: "mode must be 'manual' or 'automatic'." });
    }
    await db.collection('siteConfig').doc('paymentSettings').set({
      mode, backendUrl: backendUrl || '',
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
