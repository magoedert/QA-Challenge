import express from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Load data files
const products = JSON.parse(
  fs.readFileSync(path.join(__dirname, "data", "products.json"), "utf-8")
);
const coupons = JSON.parse(
  fs.readFileSync(path.join(__dirname, "data", "coupons.json"), "utf-8")
);
const users = JSON.parse(
  fs.readFileSync(path.join(__dirname, "data", "users.json"), "utf-8")
);

// Simple session storage (in production, use Redis or database)
const sessions = new Map();

app.use(express.static(path.join(__dirname, "public")));

// Helper function to get user from session
const getUserFromSession = (req) => {
  const sessionId = req.headers.authorization?.replace("Bearer ", "");
  return sessionId ? sessions.get(sessionId) : null;
};

// Health check
app.get("/api/health", (_req, res) => res.json({ status: "ok" }));

// Products endpoint
app.get("/api/products", (_req, res) => res.json({ items: products }));

// Login endpoint
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const user = users.find((u) => u.email === email && u.password === password);

  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const sessionId = Math.random().toString(36).slice(2, 15);
  sessions.set(sessionId, { id: user.id, email: user.email, name: user.name });

  res.json({
    token: sessionId,
    user: { id: user.id, email: user.email, name: user.name },
  });
});

// Logout endpoint
app.post("/api/logout", (req, res) => {
  const sessionId = req.headers.authorization?.replace("Bearer ", "");
  if (sessionId) {
    sessions.delete(sessionId);
  }
  res.json({ message: "Logged out successfully" });
});

// Get current user
app.get("/api/me", (req, res) => {
  const user = getUserFromSession(req);
  if (!user) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  res.json({ user });
});

// Validate coupon
app.post("/api/validate-coupon", (req, res) => {
  const { code } = req.body;

  if (!code) {
    return res.status(400).json({ error: "Coupon code is required" });
  }

  const coupon = coupons.find((c) => c.code === code.toUpperCase());

  if (!coupon) {
    return res.json({ valid: false, message: "Invalid coupon code" });
  }

  if (!coupon.active) {
    return res.json({ valid: false, message: "Coupon is expired" });
  }

  res.json({
    valid: true,
    coupon: {
      code: coupon.code,
      discount: coupon.discount,
      type: coupon.type,
    },
  });
});

// Checkout with coupon and stock validation
app.post("/api/checkout", (req, res) => {
  const { items, couponCode } = req.body || {};

  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: "Items are required" });
  }

  // Validate stock
  for (const item of items) {
    const product = products.find((p) => p.id === item.id);
    if (!product) {
      return res.status(400).json({ error: `Product ${item.id} not found` });
    }
    if (!Number.isFinite(item.qty) || item.qty <= 0) {
      return res.status(400).json({ error: "Invalid quantity" });
    }
    if (item.qty > product.stock) {
      return res.status(400).json({
        error: `Insufficient stock for ${product.name}. Available: ${product.stock}`,
      });
    }
  }

  // Calculate subtotal
  let subtotal = 0;
  for (const item of items) {
    const product = products.find((p) => p.id === item.id);
    subtotal += product.price * item.qty;
  }

  // Apply coupon if provided
  let discount = 0;
  let appliedCoupon = null;

  if (couponCode) {
    const coupon = coupons.find(
      (c) => c.code === couponCode.toUpperCase() && c.active
    );
    if (coupon) {
      appliedCoupon = coupon;
      if (coupon.type === "percentage") {
        discount = subtotal * (coupon.discount / 100);
      } else if (coupon.type === "fixed") {
        discount = Math.min(coupon.discount, subtotal);
      }
    }
  }

  const total = subtotal - discount;
  const orderId = Math.random().toString(36).slice(2, 10);

  // Update stock (in production, this should be atomic)
  for (const item of items) {
    const product = products.find((p) => p.id === item.id);
    product.stock -= item.qty;
  }

  // Save updated products (in production, use database)
  fs.writeFileSync(
    path.join(__dirname, "data", "products.json"),
    JSON.stringify(products, null, 2)
  );

  res.json({
    orderId,
    subtotal,
    discount,
    total,
    appliedCoupon: appliedCoupon
      ? {
          code: appliedCoupon.code,
          discount: appliedCoupon.discount,
          type: appliedCoupon.type,
        }
      : null,
  });
});

app.get("*", (_req, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html"))
);

const port = process.env.PORT || 3001;
app.listen(port, () => console.log(`[backend] http://localhost:${port}`));
