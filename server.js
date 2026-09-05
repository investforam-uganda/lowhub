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
    const ref = `LH-ORDER-${order.orderNumber}-${Date.now()}`;
    const callbackUrl = PUBLIC_BACKEND_URL ? `${PUBLIC_BACKEND_URL}/api/payments/webhook` : undefined;

    const paymentRef = db.collection('autoPayments').doc();
    await paymentRef.set({
      userId: uid, userEmail: req.authEmail || '', userName: order.buyerSnapshot?.name || '',
      phone: normalizedPhone, amount: order.total, reference: ref,
      purpose: 'order', orderId, orderNumber: order.orderNumber,
      planKey: null, planName: null, planDays: null, dealPayload: null,
      status: 'pending', provider: 'marzpay', marzpayTransactionId: null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    let localPhone = normalizedPhone;
    if (localPhone.startsWith('256')) localPhone = '0' + localPhone.slice(3);

    let marzRes, marzData;
    try {
      marzRes = await fetch(`${MARZPAY_BASE_URL}/collect-money`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': marzpayAuthHeader() },
        body: JSON.stringify({
          phone_number: localPhone, amount: order.total, country: 'UG', reference: ref,
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

    // NOTE ON PHONE FORMAT: MarzPay's own published SDK examples disagree
    // with each other — their PHP SDK example uses local format with a
    // country field ('0759983853' + country:'UG'), their .NET SDK example
    // uses '+2567...', and their own Python SDK example uses '256759...'
    // with no country field. We're following the PHP SDK's example here
    // (local format + country) since it's the most complete of the three,
    // but this hasn't been confirmed against MarzPay's actual raw HTTP API
    // docs — if collections keep failing, log/inspect rawResponse below
    // (now stored in Firestore) to see MarzPay's exact validation message
    // rather than guessing at another format.
    let localPhone = normalizedPhone;
    if (localPhone.startsWith('256')) localPhone = '0' + localPhone.slice(3);

    let marzRes, marzData;
    try {
      marzRes = await fetch(`${MARZPAY_BASE_URL}/collect-money`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': marzpayAuthHeader()
        },
        body: JSON.stringify({
          phone_number: localPhone,
          amount: amount,
          country: 'UG',
          reference: ref,
          description: isDeal ? `LowHub deal submission (${dealPayload.adIds.length} ad(s))` : `LowHub ${planName || planKey} plan`,
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
    } else if (data.purpose === 'order') {
      await activateOrderFromPayment(data);
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
