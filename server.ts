import express from "express";
import path from "path";
import dotenv from "dotenv";
import { createServer as createViteServer } from "vite";
import { db, initDB } from "./server/database.ts";
import { GoogleGenAI } from "@google/genai";
import { testSupabaseConnection } from "./server/supabase.ts";


// Load ENV
dotenv.config();

// Initialize DB
initDB();

const app = express();
const PORT = 3000;

// Body parsers with generous limits for receipt uploads
app.use(express.json({ limit: "15mb" }));
app.use(express.urlencoded({ extended: true, limit: "15mb" }));

// -------------------------------------------------------------------------
// AUTHENTICATION MIDDLEWARE
// -------------------------------------------------------------------------
// Since iFrames block partitioned cookies, we use robust custom Header auth:
// Authorization: Bearer <userId>
function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "অননুমোদিত প্রবেশ! অনুগ্রহ করে লগইন করুন।" });
  }
  const userId = authHeader.split(" ")[1];
  const user = db.getUserById(userId);
  if (!user) {
    return res.status(401).json({ error: "ব্যবহারকারী খুঁজে পাওয়া যায়নি।" });
  }
  (req as any).user = user;
  next();
}

// -------------------------------------------------------------------------
// DIAGNOSTICS & SYSTEM STATUS ROUTES
// -------------------------------------------------------------------------
app.get("/api/supabase/status", async (req, res) => {
  try {
    const status = await testSupabaseConnection();
    res.json(status);
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// -------------------------------------------------------------------------
// AUTHENTICATION ROUTES
// -------------------------------------------------------------------------
app.post("/api/auth/register", (req, res) => {
  try {
    const { email, password, name, phone, couponCode } = req.body;
    if (!email || !password || !name || !phone) {
      return res.status(400).json({ error: "অনুগ্রহ করে সব তথ্য দিন।" });
    }
    
    const existing = db.getUserByEmail(email);
    if (existing) {
      return res.status(400).json({ error: "এই ইমেইল দিয়ে অলরেডি অ্যাকাউন্ট রয়েছে।" });
    }

    let subscribed = false;
    let subscriptionRenewal = null;

    if (couponCode && couponCode.trim() !== "") {
      const v = db.validateCoupon(couponCode, "pro");
      if (!v.valid) {
        return res.status(400).json({ error: v.error });
      }
      
      const coupon = v.coupon;
      if (coupon.discountPercent === 100) {
        subscribed = true;
        const renewalDate = new Date();
        const proPlan = db.getPlans().find(p => p.id === "pro");
        const days = proPlan ? proPlan.durationDays : 365;
        renewalDate.setDate(renewalDate.getDate() + days);
        subscriptionRenewal = renewalDate.toISOString().split('T')[0];
        
        // Increment usesCount of the coupon
        db.updateCoupon(coupon.id, { usesCount: coupon.usesCount + 1 });
      }
    }

    const user = db.createUser(email, password, name, phone);
    
    if (subscribed) {
      db.updateUser(user.id, { subscribed, subscriptionRenewal });
      
      db.addNotification({
        userId: user.id,
        messId: null,
        title: "প্রিমিয়াম মেসবুক প্রো একটিভেট হয়েছে! 🎉",
        message: `রেজিস্ট্রেশনের সময় কুপন কোড ${couponCode.toUpperCase().trim()} ব্যবহারের জন্য আপনাকে প্রিমিয়াম মেসবুক প্রো অ্যাক্সেস দেওয়া হয়েছে।`
      });
    }

    const updatedUser = db.getUserById(user.id);
    res.status(201).json({ user: updatedUser, token: user.id });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/auth/login", (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "ইমেইল ও পাসওয়ার্ড লিখুন।" });
    }

    const user = db.getUserByEmail(email);
    // Simple verification with password checking
    if (!user || (user as any).passwordHash !== password) {
      return res.status(401).json({ error: "ভুল ইমেইল বা পাসওয়ার্ড!" });
    }

    const { passwordHash, ...safeUser } = user as any;
    res.json({ user: safeUser, token: user.id });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// -------------------------------------------------------------------------
// GOOGLE SSO / GMAIL SIGN-UP & LOGIN ENDPOINTS
// -------------------------------------------------------------------------
app.get("/api/auth/google/url", (req, res) => {
  try {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    if (!clientId) {
      return res.json({ url: "", error: "GOOGLE_CLIENT_ID_MISSING" });
    }
    
    const appUrl = process.env.APP_URL || "http://localhost:3000";
    const redirectUri = `${appUrl}/api/auth/callback/google`;
    
    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'openid email profile',
      access_type: 'offline',
      prompt: 'consent'
    });
    
    res.json({ url: `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}` });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Express route matches both trailing slash options for Google OAuth callbacks
app.get(["/api/auth/callback/google", "/api/auth/callback/google/"], async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) {
      return res.status(400).send("No Auth Code Provided");
    }

    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
    const appUrl = process.env.APP_URL || "http://localhost:3000";
    const redirectUri = `${appUrl}/api/auth/callback/google`;

    if (!clientId || !clientSecret) {
      return res.status(500).send("Google credentials are not configured on the server. Please check your system settings.");
    }

    // Exchange auth code for token
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        code: code as string,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: "authorization_code"
      })
    });

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      return res.status(500).send(`Failed to exchange token: ${errorText}`);
    }

    const tokenData = await tokenResponse.json();
    const accessToken = tokenData.access_token;

    // Fetch user details
    const userinfoResponse = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });

    if (!userinfoResponse.ok) {
      return res.status(500).send("Failed to retrieve user information from Google.");
    }

    const googleUser = await userinfoResponse.json();
    const email = googleUser.email;
    const name = googleUser.name || email.split("@")[0];

    if (!email) {
      return res.status(400).send("Email address was not provided by Google SSO.");
    }

    // Login or sign up user
    let user: any = db.getUserByEmail(email);
    if (!user) {
      // User doesn't exist, create automatically (Gmail SSO registration)
      user = db.createUser(email, "google-sso-oauth-password-hashed-placeholder", name, "+8801700000000");
    }

    // Exclude password hash
    const { passwordHash: _, ...safeUser } = user as any;

    // Send successful postMessage to opener window and auto-close
    res.send(`
      <html>
        <head>
          <title>Authenticating with Google...</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background-color: #f8fafc; color: #334155; }
            .card { background: white; padding: 2.5rem; border-radius: 1.5rem; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.05); text-align: center; max-width: 400px; }
            .spinner { margin: 0 auto 1.5rem; border: 4px solid #f3f3f3; border-top: 4px solid #0f172a; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; }
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            h2 { font-size: 1.25rem; font-weight: 700; color: #1e293b; margin: 0 0 0.5rem; }
            p { font-size: 0.875rem; color: #64748b; margin: 0; }
          </style>
        </head>
        <body>
          <div class="card">
            <div class="spinner"></div>
            <h2>অ্যাকাউন্ট যাচাই করা হচ্ছে...</h2>
            <p>আপনার জিমেইল ভেরিফিকেশন সম্পন্ন হয়েছে। দয়া করে অপেক্ষা করুন...</p>
          </div>
          <script>
            try {
              if (window.opener) {
                window.opener.postMessage({
                  type: 'OAUTH_AUTH_SUCCESS',
                  token: ${JSON.stringify(user.id)},
                  user: ${JSON.stringify(safeUser)}
                }, '*');
                window.close();
              } else {
                // Return to home if helper is not opened as a popup
                window.location.href = '/';
              }
            } catch (err) {
              console.error("Popup message error:", err);
              window.location.href = '/';
            }
          </script>
        </body>
      </html>
    `);
  } catch (err: any) {
    res.status(500).send(`Authentication error: ${err.message}`);
  }
});

// SSO Developer Friendly Simulation Route
app.post("/api/auth/google/sso-simulation", (req, res) => {
  try {
    const { email, name } = req.body;
    if (!email) {
      return res.status(400).json({ error: "অনুগ্রহ করে গুগল ইমেইল দিন।" });
    }

    let user: any = db.getUserByEmail(email);
    if (!user) {
      // Auto-register via Gmail Simulation
      const cleanName = name || email.split("@")[0];
      user = db.createUser(email, "google-sso-oauth-password-hashed-placeholder", cleanName, "+8801700000000");
    }

    const { passwordHash: _, ...safeUser } = user as any;
    res.json({ user: safeUser, token: user.id });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  const user = (req as any).user;
  res.json({ user });
});

app.post("/api/auth/profile/edit", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const { 
      name, 
      email, 
      phone, 
      password, 
      emailNotificationsEnabled, 
      notificationEmail, 
      notificationFrequency 
    } = req.body;
    
    if (!name || !email || !phone) {
      return res.status(400).json({ error: "তথ্য অসম্পূর্ণ।" });
    }

    // Check duplicate email
    const existing = db.getUserByEmail(email);
    if (existing && existing.id !== user.id) {
      return res.status(400).json({ error: "এই ইমেইলটি ইতিপূর্বে ব্যবহৃত হয়েছে।" });
    }

    const updates: any = { 
      name, 
      email, 
      phone,
      emailNotificationsEnabled: emailNotificationsEnabled !== undefined ? !!emailNotificationsEnabled : false,
      notificationEmail: notificationEmail !== undefined ? notificationEmail.trim() : email,
      notificationFrequency: notificationFrequency || "instant"
    };
    
    if (password && password.trim() !== "") {
      updates.passwordHash = password;
    }

    const updated = db.updateUser(user.id, updates);
    res.json({ success: true, user: updated });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/auth/purge", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    db.deleteUserAccount(user.id);
    res.json({ success: true, message: "অ্যাকাউন্ট এবং আপনার সমস্ত ডেটা স্থায়ীভাবে মুছে ফেলা হয়েছে।" });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// -------------------------------------------------------------------------
// MESS ROUTES (MULTI-TENANCY)
// -------------------------------------------------------------------------
app.post("/api/messes", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const { name, address, monthlyStartDate } = req.body;
    if (!name || !address) {
      return res.status(400).json({ error: "মেসের নাম এবং ঠিকানা দিন।" });
    }

    // SaaS Layer Limit Rule: Plan based multi-mess check
    const planId = user.subscribed ? "pro" : "free";
    const plan = db.getPlans().find(p => p.id === planId) || db.getPlans()[0];
    const myMesses = db.getAllMesses().filter(m => m.members.includes(user.id));
    if (myMesses.length >= plan.maxMesses) {
      return res.status(402).json({ 
        error: `সীমা অতিক্রম করেছেন! আপনার বর্তমান প্ল্যান (${user.subscribed ? 'প্রো' : 'ফ্রি'}) অনুযায়ী আপনি সর্বোচ্চ ${plan.maxMesses}টি মেসে যুক্ত থাকতে পারবেন।` 
      });
    }

    const startDate = parseInt(monthlyStartDate) || 1;
    const mess = db.createMess(name, address, startDate, user.id);
    res.status(201).json({ mess, user: db.getUserById(user.id) });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/messes/list", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    // Returns messes user is a member of plus any public list to join
    const all = db.getAllMesses();
    const myMesses = all.filter(m => m.members.includes(user.id));
    const joinable = all.filter(m => !m.members.includes(user.id));
    res.json({ myMesses, joinable });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/messes/join", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const { messId } = req.body;
    if (!messId) {
      return res.status(400).json({ error: "মেস সিলেক্ট করুন।" });
    }

    const mess = db.getMessById(messId);
    if (!mess) {
      return res.status(404).json({ error: "মেসটি খুঁজে পাওয়া যায়নি।" });
    }

    // SaaS limit safeguard: check mess member and user multi-mess plan restrictions
    const planId = user.subscribed ? "pro" : "free";
    const plan = db.getPlans().find(p => p.id === planId) || db.getPlans()[0];
    const myMesses = db.getAllMesses().filter(m => m.members.includes(user.id));
    if (myMesses.length >= plan.maxMesses) {
      return res.status(402).json({ 
        error: `সীমা অতিক্রম করেছেন! আপনার বর্তমান প্ল্যান (${user.subscribed ? 'প্রো' : 'ফ্রি'}) অনুযায়ী আপনি সর্বোচ্চ ${plan.maxMesses}টি মেসে যুক্ত থাকতে পারবেন।` 
      });
    }

    if (!user.subscribed && mess.members.length >= 10) {
      return res.status(402).json({ 
        error: "এই মেসটি ফুল! ফ্রি প্ল্যানে সর্বোচ্চ ১০ জন মেম্বার থাকতে পারে।" 
      });
    }

    const joined = db.joinMess(messId, user.id);
    res.json({ mess: joined, user: db.getUserById(user.id) });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/messes/select", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const { messId } = req.body;
    if (!messId) {
      return res.status(400).json({ error: "মেস আইডি আবশ্যক।" });
    }

    const mess = db.getMessById(messId);
    if (!mess || !mess.members.includes(user.id)) {
      return res.status(403).json({ error: "আপনি এই মেসের সদস্য নন।" });
    }

    db.updateUser(user.id, { activeMessId: messId });
    res.json({ user: db.getUserById(user.id), mess });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.put("/api/messes/active", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    if (!messId) return res.status(400).json({ error: "কোনো মেস অ্যাক্টিভ নেই।" });

    const role = user.messRoles[messId];
    if (role !== 'admin') {
      return res.status(403).json({ error: "শুধুমাত্র এডমিন মেস সেটিংস পরিবর্তন করতে পারেন।" });
    }

    const { name, address, allowedSelfReport, autoCloseMidnight, currency } = req.body;
    const updated = db.updateMess(messId, {
      name,
      address,
      allowedSelfReport: !!allowedSelfReport,
      autoCloseMidnight: !!autoCloseMidnight,
      currency: currency || "৳"
    }, user.id);

    res.json({ mess: updated });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/messes/members", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    if (!messId) return res.json({ members: [] });

    const mess = db.getMessById(messId);
    if (!mess) return res.status(404).json({ error: "মেস পাওয়া যায়নি।" });

    const role = user.messRoles[messId] || 'member';
    const activeMonth = new Date().toISOString().substring(0, 7);
    const summary = db.calculateSettlement(messId, activeMonth);

    const users = db.getAllUsers().filter(u => mess.members.includes(u.id));
    const membersList = users.map(u => {
      const calc = summary.memberSummaries.find(s => s.userId === u.id) || {
        userId: u.id,
        name: u.name,
        mealCount: 0,
        totalDeposits: 0,
        totalExpensesPaid: 0,
        totalCredit: 0,
        dueCost: 0,
        balance: 0
      };

      return {
        id: u.id,
        name: u.name,
        email: u.email,
        phone: u.phone,
        joinDate: u.joinDate,
        status: u.status,
        role: u.messRoles[messId] || 'member',
        password: (role === 'admin' || u.id === user.id) ? (u as any).passwordHash : undefined,
        defaultLunch: (u as any).defaultLunch !== undefined ? (u as any).defaultLunch : 1,
        defaultDinner: (u as any).defaultDinner !== undefined ? (u as any).defaultDinner : 1,
        calculation: {
          mealCount: calc.mealCount,
          totalDeposits: calc.totalDeposits,
          totalExpensesPaid: calc.totalExpensesPaid,
          totalCredit: calc.totalCredit,
          dueCost: calc.dueCost,
          balance: calc.balance,
          mealRate: summary.mealRate
        }
      };
    });

    res.json({ members: membersList });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/messes/members/edit", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    const role = user.messRoles[messId];
    if (!messId) return res.status(400).json({ error: "কোনো মেস অ্যাক্টিভ নেই।" });

    const { memberId, name, email, phone, password, defaultLunch, defaultDinner } = req.body;
    if (!memberId || !name || !email || !phone) {
      return res.status(400).json({ error: "তথ্য অসম্পূর্ণ।" });
    }

    const mess = db.getMessById(messId);
    if (!mess || !mess.members.includes(memberId)) {
      return res.status(404).json({ error: "মেম্বার এই মেসের সদস্য নন।" });
    }

    // Only admin can edit other members, or user can edit themselves
    if (role !== 'admin' && memberId !== user.id) {
      return res.status(403).json({ error: "অনুমতি নেই। শুধুমাত্র ম্যানেজার মেম্বারদের তথ্য এডিট করতে পারেন।" });
    }

    // Check email duplicates
    const existing = db.getUserByEmail(email);
    if (existing && existing.id !== memberId) {
      return res.status(400).json({ error: "এই ইমেইলটি ইতিপূর্বে ব্যবহৃত হয়েছে।" });
    }

    const updates: any = { name, email, phone };
    if (password && password.trim() !== "") {
      updates.passwordHash = password;
    }
    if (defaultLunch !== undefined) {
      updates.defaultLunch = parseFloat(defaultLunch) >= 0 ? parseFloat(defaultLunch) : 0;
    }
    if (defaultDinner !== undefined) {
      updates.defaultDinner = parseFloat(defaultDinner) >= 0 ? parseFloat(defaultDinner) : 0;
    }

    const updated = db.updateUser(memberId, updates);
    if (!updated) {
      return res.status(404).json({ error: "সদস্য পাওয়া যায়নি।" });
    }

    db.addAudit({
      messId,
      userId: user.id,
      userName: user.name,
      action: `সদস্য ${name}-এর তথ্য আপডেট করা হয়েছে (দুপুরের মিলঃ ${updates.defaultLunch ?? 'অপরিবর্তিত'}, রাতের মিলঃ ${updates.defaultDinner ?? 'অপরিবর্তিত'})।`
    });

    res.json({ success: true, user: updated });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/messes/members/role", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    const role = user.messRoles[messId];
    if (role !== 'admin') return res.status(403).json({ error: "অনুমতি নেই।" });

    const { memberId, newRole } = req.body;
    if (!memberId || !newRole) return res.status(400).json({ error: "তথ্য অসম্পূর্ণ।" });

    const success = db.changeMemberRole(messId, memberId, newRole, user.id);
    res.json({ success });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/messes/members/:id", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    const role = user.messRoles[messId];
    if (role !== 'admin') return res.status(403).json({ error: "অনুমতি নেই।" });

    const memberId = req.params.id;
    if (memberId === user.id) {
      return res.status(400).json({ error: "এডমিন নিজেকে মেস থেকে সরাতে পারবেন না।" });
    }

    const success = db.removeMessMember(messId, memberId, user.id);
    res.json({ success });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// -------------------------------------------------------------
// EXPENSES ROUTES
// -------------------------------------------------------------
app.get("/api/expenses", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    if (!messId) return res.json({ expenses: [] });

    const { category, paidBy, startDate, endDate } = req.query;
    const list = db.getExpensesFiltered(messId, {
      category: category as string,
      paidBy: paidBy as string,
      startDate: startDate as string,
      endDate: endDate as string
    });
    res.json({ expenses: list });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/expenses", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    if (!messId) return res.status(400).json({ error: "আপনার কোনো মেস অ্যাক্টিভ নেই।" });

    const { date, category, amount, paidByUserId, note, receiptImage } = req.body;
    if (!date || !category || !amount || !paidByUserId) {
      return res.status(400).json({ error: "অনুগ্রহ করে সব তথ্য সঠিকভাবে পূরণ করুন।" });
    }

    const expense = db.saveExpense(messId, {
      date,
      category,
      amount: parseFloat(amount),
      paidByUserId,
      note: note || "",
      receiptImage: receiptImage || null
    }, user.id);

    res.status(201).json({ expense });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

app.put("/api/expenses/:id", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    const expId = req.params.id;
    const role = user.messRoles[messId];
    if (role !== 'admin') {
      return res.status(403).json({ error: "শুধুমাত্র এডমিন হিসাব সংশোধন করতে পারেন।" });
    }

    const { date, category, amount, paidByUserId, note, receiptImage } = req.body;
    const updated = db.updateExpense(expId, {
      date,
      category,
      amount: parseFloat(amount),
      paidByUserId,
      note,
      receiptImage
    }, user.id);

    res.json({ expense: updated });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

app.delete("/api/expenses/:id", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    const expId = req.params.id;
    const role = user.messRoles[messId];
    
    if (role !== 'admin') {
      return res.status(403).json({ error: "হিসাব ডিলিট করার ক্ষমতা কেবল এডমিনের রয়েছে।" });
    }

    const success = db.deleteExpense(expId, user.id);
    res.json({ success });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

// -------------------------------------------------------------
// MEAL MANAGEMENT ROUTES
// -------------------------------------------------------------
app.get("/api/meals", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    if (!messId) return res.json({ meals: [] });

    const month = (req.query.month as string) || new Date().toISOString().substring(0, 7);
    const meals = db.getMealsForMonth(messId, month);
    res.json({ meals });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/meals", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    if (!messId) return res.status(400).json({ error: "কোনো মেস অ্যাক্টিভ নেই।" });

    const { date, type, counts } = req.body;
    if (!date || !type || !counts) {
      return res.status(400).json({ error: "সব তথ্য আবশ্যক।" });
    }

    const mess = db.getMessById(messId);
    const role = user.messRoles[messId];

    // Check optional admin closed midnight limit
    if (mess?.autoCloseMidnight) {
      const today = new Date().toISOString().split('T')[0];
      if (date < today && role !== 'admin') {
        return res.status(400).json({ error: "মেম্বর সেলফ রিপোর্ট লিমিট পেরিয়ে গেছে। ম্যানেজারকে বলুন।" });
      }
    }

    // Check self-reporting allowance
    if (role !== 'admin' && !mess?.allowedSelfReport) {
      return res.status(403).json({ error: "ম্যানেজার আপনার নিজের মিল রেকর্ড করা বন্ধ করে রেখেছেন।" });
    }

    const meal = db.saveMealCounts(messId, date, type, counts, user.id);
    res.status(201).json({ meal });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

// -------------------------------------------------------------
// PAYMENTS & DEPOSITS ROUTES
// -------------------------------------------------------------
app.get("/api/deposits", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    if (!messId) return res.json({ deposits: [] });

    const month = req.query.month as string;
    const list = db.getDeposits(messId, month);
    res.json({ deposits: list });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/deposits", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    if (!messId) return res.status(400).json({ error: "কোনো মেস অ্যাক্টিভ নেই।" });

    const { userId, date, amount, paymentType, reference } = req.body;
    if (!userId || !date || !amount || !paymentType) {
      return res.status(400).json({ error: "তথ্যাদি অসম্পূর্ণ।" });
    }

    const dep = db.saveDeposit(messId, {
      userId,
      date,
      amount: parseFloat(amount),
      paymentType,
      reference: reference || ""
    }, user.id);

    res.status(201).json({ deposit: dep });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

app.post("/api/deposits/:id/confirm", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    const role = user.messRoles[messId];
    if (role !== 'admin') {
      return res.status(403).json({ error: "কেমন এডমিন আপনি? আপনার নো-পারমিশন!" });
    }

    const depId = req.params.id;
    const success = db.confirmDeposit(depId, user.id);
    res.json({ success, deposit: db.getDBState().deposits[depId] });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/deposits/:id", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    const role = user.messRoles[messId];
    if (role !== 'admin') {
      return res.status(403).json({ error: "অনুমতি নেই।" });
    }

    const success = db.deleteDeposit(req.params.id, user.id);
    res.json({ success });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

// -------------------------------------------------------------
// MONTHLY SETTLEMENT ROUTE
// -------------------------------------------------------------
app.get("/api/settlement/:month", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    if (!messId) return res.status(400).json({ error: "কোনো মেস অ্যাক্টিভ নেই।" });

    const month = req.params.month;
    const summary = db.calculateSettlement(messId, month);
    const mess = db.getMessById(messId);
    res.json({ 
      settlement: summary, 
      isLocked: mess?.lockedMonths.includes(month) || false 
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/settlement/:month/lock", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    const role = user.messRoles[messId];
    if (role !== 'admin') {
      return res.status(403).json({ error: "শুধুমাত্র মেস এডমিন এটি লক করতে পারেন।" });
    }

    const month = req.params.month;
    const success = db.lockMonth(messId, month, user.id);
    res.json({ success });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// -------------------------------------------------------------
// AUDITS & NOTIFICATIONS
// -------------------------------------------------------------
app.get("/api/audits", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    if (!messId) return res.json({ logs: [] });
    res.json({ logs: db.getAudits(messId) });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/notifications", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    res.json({ notifications: db.getNotifications(user.id) });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/notifications/read", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    db.markNotificationsRead(user.id);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// -------------------------------------------------------------
// DASHBOARD ANALYTICS
// -------------------------------------------------------------
app.get("/api/dashboard", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    if (!messId) {
      return res.json({ empty: true });
    }

    const dbState = db.getDBState();
    const mess = db.getMessById(messId);
    if (!mess) return res.status(404).json({ error: "মেস পাওয়া যায়নি।" });

    const month = (req.query.month as string) || new Date().toISOString().substring(0, 7);

    // Compute basic month aggregates
    const settlement = db.calculateSettlement(messId, month);
    
    // Category sums
    const catSums: Record<string, number> = {
      grocery: 0, gas_fuel: 0, rent: 0, electricity: 0, water: 0, kitchen_supplies: 0, others: 0
    };
    const expenses = Object.values(dbState.expenses).filter(e => e.messId === messId && e.month === month);
    expenses.forEach(e => {
      if (catSums[e.category] !== undefined) {
        catSums[e.category] += e.amount;
      } else {
        catSums.others += e.amount;
      }
    });

    // MoM Trend (last 3 calendar months)
    const trends: { monthName: string; expense: number; meals: number }[] = [];
    const dateCursor = new Date();
    for (let i = 2; i >= 0; i--) {
      const loopDate = new Date(dateCursor.getFullYear(), dateCursor.getMonth() - i, 1);
      const cursorMonthStr = `${loopDate.getFullYear()}-${String(loopDate.getMonth() + 1).padStart(2, '0')}`;
      
      const cursExps = Object.values(dbState.expenses).filter(e => e.messId === messId && e.month === cursorMonthStr);
      const cursMeals = Object.values(dbState.meals).filter(e => e.messId === messId && e.month === cursorMonthStr);
      const loopTotalExps = cursExps.reduce((s, e) => s + e.amount, 0);
      let loopMealsCount = 0;
      cursMeals.forEach(meal => {
        Object.values(meal.counts).forEach(c => { loopMealsCount += c; });
      });

      trends.push({
        monthName: loopDate.toLocaleString('default', { month: 'short' }) + " " + loopDate.getFullYear(),
        expense: loopTotalExps,
        meals: loopMealsCount
      });
    }

    // Leaderboards
    // Top spender (who logged highest paidBy expense amount)
    const personalExpenses: Record<string, number> = {};
    mess.members.forEach(mId => { personalExpenses[mId] = 0; });
    expenses.forEach(e => {
      if (personalExpenses[e.paidByUserId] !== undefined) {
        personalExpenses[e.paidByUserId] += e.amount;
      }
    });

    const leaderboardSpender = Object.entries(personalExpenses).map(([uId, total]) => ({
      userId: uId,
      name: db.getUserById(uId)?.name || uId,
      totalSpent: total
    })).sort((a, b) => b.totalSpent - a.totalSpent);

    // Highest meal count
    const leaderboardMeals = settlement.memberSummaries.map(s => ({
      userId: s.userId,
      name: s.name,
      mealCount: s.mealCount
    })).sort((a, b) => b.mealCount - a.mealCount);

    res.json({
      messName: mess.name,
      address: mess.address,
      currency: mess.currency || "৳",
      month,
      isLocked: mess.lockedMonths.includes(month),
      allowedSelfReport: mess.allowedSelfReport,
      autoCloseMidnight: mess.autoCloseMidnight,
      geminiActive: !!mess.geminiActive,
      geminiGoogleAuthEmail: mess.geminiGoogleAuthEmail || null,
      totals: {
        totalExpense: settlement.totalExpenses,
        totalMeals: settlement.totalMeals,
        mealRate: settlement.mealRate
      },
      categoryWise: Object.entries(catSums).map(([category, amount]) => ({ category, amount })),
      trends,
      leaderboards: {
        spenders: leaderboardSpender,
        meals: leaderboardMeals
      },
      memberSettlements: settlement.memberSummaries,
      transactions: settlement.transactions,
      role: user.messRoles[messId] || 'member'
    });

  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// -------------------------------------------------------------
// BILLING & SAAS LAYER SUBSCRIPTION
// -------------------------------------------------------------
app.post("/api/saas/subscribe", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    
    // Simulate active Stripe / SSLCommerz premium checkout validation
    const targetRenewalDate = new Date();
    targetRenewalDate.setFullYear(targetRenewalDate.getFullYear() + 1); // 1 Year validity

    const updated = db.updateUser(user.id, {
      subscribed: true,
      subscriptionRenewal: targetRenewalDate.toISOString().split('T')[0]
    });

    db.addNotification({
      userId: user.id,
      messId: null,
      title: "MessBook Pro সক্রিয় হয়েছে! 🎉",
      message: "আপনার MessBook Pro সাবস্ক্রিপশন সফলভাবে সক্রিয় হয়েছে। এখন আপনি আনলিমিটেড মেস, আনলিমিটেড মেম্ব সদস্য যুক্ত করতে পারবেন।"
    });

    res.json({ user: updated, message: "পেমেন্ট সফল! আপনি এখন প্রিমিয়াম মেস ম্যানেজার।" });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/saas/subscribe-coupon", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const { couponCode } = req.body;
    if (!couponCode) {
      return res.status(400).json({ error: "কুপন কোড দিন।" });
    }

    const result = db.validateCoupon(couponCode, "pro");
    if (!result.valid || !result.coupon) {
      return res.status(400).json({ error: result.error || "ভুল বা অনুৎসারিত কুপন কোড!" });
    }
    const coupon = result.coupon;

    const targetRenewalDate = new Date();
    targetRenewalDate.setFullYear(targetRenewalDate.getFullYear() + 1); // 1 Year validity

    const updated = db.updateUser(user.id, {
      subscribed: true,
      subscriptionRenewal: targetRenewalDate.toISOString().split('T')[0]
    });

    db.updateCoupon(coupon.id, { usesCount: coupon.usesCount + 1 });

    db.addNotification({
      userId: user.id,
      messId: null,
      title: "কুপন কোড দিয়ে MessBook Pro সক্রিয় হয়েছে! 🎉",
      message: `কুপন কোড "${couponCode.toUpperCase().trim()}" ব্যবহারের জন্য আপনাকে প্রিমিয়াম মেসবুক প্রো অ্যাক্সেস দেওয়া হয়েছে।`
    });

    res.json({ user: updated, message: `কুপন"${couponCode.toUpperCase().trim()}" সফলভাবে প্রয়োগ করা হয়েছে! আপনার অ্যাকাউন্ট প্রো সংস্করণে আপগ্রেড করা হয়েছে।` });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// -------------------------------------------------------------
// SAAS ADMIN CONTROL PANEL ENDPOINTS
// -------------------------------------------------------------
app.get("/api/saas/admin/stats", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    if (user.email.toLowerCase() !== "saas@admin.com" && user.email.toLowerCase() !== "demo@admin.com") {
      return res.status(403).json({ error: "অনুমতি নেই! শুধুমাত্র সাশ অ্যাডমিন এটি দেখতে পারেন।" });
    }

    const state = db.getDBState();
    const usersList = Object.values(state.users);
    const messesList = Object.values(state.messes);
    const expensesList = Object.values(state.expenses);
    const depositsList = Object.values(state.deposits);

    const totalUsers = usersList.length;
    const totalMesses = messesList.length;
    const totalExpenses = expensesList.reduce((sum, item) => sum + item.amount, 0);
    const totalDeposits = depositsList.reduce((sum, item) => sum + item.amount, 0);
    const totalPremium = usersList.filter(u => u.subscribed).length;

    res.json({
      totalUsers,
      totalMesses,
      totalExpenses,
      totalDeposits,
      totalPremium,
      ratioPremiumPercent: totalUsers > 0 ? Math.round((totalPremium / totalUsers) * 100) : 0
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/saas/admin/users", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    if (user.email.toLowerCase() !== "saas@admin.com" && user.email.toLowerCase() !== "demo@admin.com") {
      return res.status(403).json({ error: "অনুমতি নেই!" });
    }
    const users = db.getAllUsers().map(u => {
      const { passwordHash, ...safe } = u as any;
      return { ...safe, password: passwordHash };
    });
    res.json({ users });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.put("/api/saas/admin/users/:id", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    if (user.email.toLowerCase() !== "saas@admin.com" && user.email.toLowerCase() !== "demo@admin.com") {
      return res.status(403).json({ error: "অনুমতি নেই!" });
    }
    const targetUserId = req.params.id;
    const { name, email, phone, status, subscribed, subscriptionRenewal, password } = req.body;

    const updates: any = {};
    if (name !== undefined) updates.name = name;
    if (email !== undefined) updates.email = email;
    if (phone !== undefined) updates.phone = phone;
    if (status !== undefined) updates.status = status;
    if (subscribed !== undefined) updates.subscribed = !!subscribed;
    if (subscriptionRenewal !== undefined) updates.subscriptionRenewal = subscriptionRenewal || null;
    if (password && password.trim() !== "") updates.passwordHash = password;

    const updated = db.updateUser(targetUserId, updates);
    res.json({ success: true, user: updated });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/saas/admin/users/:id", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    if (user.email.toLowerCase() !== "saas@admin.com" && user.email.toLowerCase() !== "demo@admin.com") {
      return res.status(403).json({ error: "অনুমতি নেই!" });
    }
    const targetUserId = req.params.id;
    if (targetUserId === user.id) {
      return res.status(400).json({ error: "আপনি নিজেকে ডিলিট করতে পারবেন না।" });
    }
    db.deleteUserAccount(targetUserId);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/saas/admin/impersonate/:id", requireAuth, (req, res) => {
  try {
    const admin = (req as any).user;
    if (admin.email.toLowerCase() !== "saas@admin.com" && admin.email.toLowerCase() !== "demo@admin.com") {
      return res.status(403).json({ error: "অনুমতি নেই!" });
    }
    const targetUserId = req.params.id;
    const targetUser = db.getUserById(targetUserId);
    if (!targetUser) {
      return res.status(404).json({ error: "ইউজার খুঁজে পাওয়া যায়নি।" });
    }
    
    db.addAudit({
      messId: "",
      userId: admin.id,
      userName: admin.name,
      action: `ইম্পারসনেশন শুরু: ${targetUser.name} (${targetUser.email})`
    });

    const { passwordHash: _, ...safe } = targetUser as any;
    res.json({ success: true, user: safe, token: targetUser.id });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/saas/admin/messes", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    if (user.email.toLowerCase() !== "saas@admin.com" && user.email.toLowerCase() !== "demo@admin.com") {
      return res.status(403).json({ error: "অনুমতি নেই!" });
    }
    const mSorted = db.getAllMesses().map(m => {
      const creator = db.getUserById(m.creatorId);
      return {
        ...m,
        creatorName: creator ? creator.name : "Unknown",
        creatorEmail: creator ? creator.email : "Unknown",
        memberCount: m.members.length
      };
    });
    res.json({ messes: mSorted });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/saas/admin/messes/:id", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    if (user.email.toLowerCase() !== "saas@admin.com" && user.email.toLowerCase() !== "demo@admin.com") {
      return res.status(403).json({ error: "অনুমতি নেই!" });
    }
    const messId = req.params.id;
    const success = (db as any).deleteMess(messId);
    res.json({ success });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/saas/admin/audit-logs", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    if (user.email.toLowerCase() !== "saas@admin.com" && user.email.toLowerCase() !== "demo@admin.com") {
      return res.status(403).json({ error: "অনুমতি নেই!" });
    }
    // Return all audit logs from the system state
    const state = db.getDBState();
    const logs = [...state.auditLogs].sort((a, b) => b.timestamp.localeCompare(a.timestamp)).slice(0, 200);
    res.json({ logs });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// -------------------------------------------------------------
// SAAS PLANS & COUPONS SYSTEM ENDPOINTS
// -------------------------------------------------------------

// Validate Coupon (Public/Signup time check too!)
app.get("/api/saas/coupons/validate", (req, res) => {
  try {
    const { code, planId } = req.query as any;
    if (!code) {
      return res.status(400).json({ error: "কুপন কোড প্রদান করা আবশ্যক।" });
    }
    const result = db.validateCoupon(code, planId);
    if (!result.valid) {
      return res.status(400).json({ error: result.error });
    }
    res.json({ coupon: result.coupon });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// List Plans public
app.get("/api/saas/plans", (req, res) => {
  try {
    res.json({ plans: db.getPlans() });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Helper for checking if they are SaaS admin
function checkSaasAdmin(req: any, res: any, next: any) {
  const user = req.user;
  if (!user || (user.email.toLowerCase() !== "saas@admin.com" && user.email.toLowerCase() !== "demo@admin.com")) {
    return res.status(403).json({ error: "অনুমতি নেই! শুধুমাত্র সাশ অ্যাডমিন এখানে অ্যাক্সেস করতে পারেন।" });
  }
  next();
}

// Admin Plans endpoints
app.get("/api/saas/admin/plans", requireAuth, checkSaasAdmin, (req, res) => {
  try {
    res.json({ plans: db.getPlans() });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/saas/admin/plans", requireAuth, checkSaasAdmin, (req, res) => {
  try {
    const { id, nameEn, nameBn, price, durationDays, maxMesses, maxMembers, featuresEn, featuresBn } = req.body;
    if (!id || !nameEn || !nameBn || price === undefined || !durationDays || !maxMesses || !maxMembers) {
      return res.status(400).json({ error: "অনুগ্রহ করে সকল আবশ্যক ফিল্ড পূরণ করুন।" });
    }
    const plan = {
      id,
      nameEn,
      nameBn,
      price: Number(price),
      durationDays: Number(durationDays),
      maxMesses: Number(maxMesses),
      maxMembers: Number(maxMembers),
      featuresEn: Array.isArray(featuresEn) ? featuresEn : [],
      featuresBn: Array.isArray(featuresBn) ? featuresBn : []
    };
    db.createPlan(plan);
    res.status(201).json({ plan });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.put("/api/saas/admin/plans/:id", requireAuth, checkSaasAdmin, (req, res) => {
  try {
    const planId = req.params.id;
    const { nameEn, nameBn, price, durationDays, maxMesses, maxMembers, featuresEn, featuresBn } = req.body;
    const updates: any = {};
    if (nameEn !== undefined) updates.nameEn = nameEn;
    if (nameBn !== undefined) updates.nameBn = nameBn;
    if (price !== undefined) updates.price = Number(price);
    if (durationDays !== undefined) updates.durationDays = Number(durationDays);
    if (maxMesses !== undefined) updates.maxMesses = Number(maxMesses);
    if (maxMembers !== undefined) updates.maxMembers = Number(maxMembers);
    if (featuresEn !== undefined) updates.featuresEn = featuresEn;
    if (featuresBn !== undefined) updates.featuresBn = featuresBn;

    const updated = db.updatePlan(planId, updates);
    if (!updated) return res.status(404).json({ error: "প্ল্যান পাওয়া যায়নি।" });
    res.json({ plan: updated });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/saas/admin/plans/:id", requireAuth, checkSaasAdmin, (req, res) => {
  try {
    const planId = req.params.id;
    if (planId === "free" || planId === "pro") {
      return res.status(400).json({ error: "ডিফল্ট সিস্টেম প্ল্যানসমূহ ডিলেট করা সম্ভব নয়।" });
    }
    const deleted = db.deletePlan(planId);
    if (!deleted) return res.status(404).json({ error: "প্ল্যান পাওয়া যায়নি।" });
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Admin Coupons endpoints
app.get("/api/saas/admin/coupons", requireAuth, checkSaasAdmin, (req, res) => {
  try {
    res.json({ coupons: db.getCoupons() });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/saas/admin/coupons", requireAuth, checkSaasAdmin, (req, res) => {
  try {
    const { code, discountPercent, targetPlanId, maxUses, expiryDate, isActive } = req.body;
    if (!code || !discountPercent || !targetPlanId) {
      return res.status(400).json({ error: "আবশ্যকীয় তথ্যসমূহ প্রদান করুন।" });
    }
    const coupon = {
      id: "coupon_" + Math.random().toString(36).substring(2, 11),
      code: code.trim().toUpperCase(),
      discountPercent: Number(discountPercent),
      targetPlanId,
      maxUses: maxUses ? Number(maxUses) : null,
      usesCount: 0,
      expiryDate: expiryDate || null,
      isActive: isActive !== false
    };
    db.createCoupon(coupon);
    res.status(201).json({ coupon });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.put("/api/saas/admin/coupons/:id", requireAuth, checkSaasAdmin, (req, res) => {
  try {
    const couponId = req.params.id;
    const { code, discountPercent, targetPlanId, maxUses, expiryDate, isActive } = req.body;
    const updates: any = {};
    if (code !== undefined) updates.code = code.trim().toUpperCase();
    if (discountPercent !== undefined) updates.discountPercent = Number(discountPercent);
    if (targetPlanId !== undefined) updates.targetPlanId = targetPlanId;
    if (maxUses !== undefined) updates.maxUses = maxUses ? Number(maxUses) : null;
    if (expiryDate !== undefined) updates.expiryDate = expiryDate || null;
    if (isActive !== undefined) updates.isActive = !!isActive;

    const updated = db.updateCoupon(couponId, updates);
    if (!updated) return res.status(404).json({ error: "কুপন পাওয়া যায়নি।" });
    res.json({ coupon: updated });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/saas/admin/coupons/:id", requireAuth, checkSaasAdmin, (req, res) => {
  try {
    const couponId = req.params.id;
    const deleted = db.deleteCoupon(couponId);
    if (!deleted) return res.status(404).json({ error: "কুপন পাওয়া যায়নি।" });
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// -------------------------------------------------------------
// GOOGLE OAUTH FOR GEMINI ACTIVATION
// -------------------------------------------------------------
app.get("/api/auth/google/gemini/url", requireAuth, (req, res) => {
  try {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const user = (req as any).user;
    const messId = user.activeMessId;
    
    if (!messId) {
      return res.status(400).json({ error: "কোনো মেস অ্যাক্টিভ নেই।" });
    }

    if (!clientId) {
      return res.json({ url: "", error: "GOOGLE_CLIENT_ID_MISSING" });
    }
    
    const appUrl = process.env.APP_URL || "http://localhost:3000";
    const redirectUri = `${appUrl}/api/auth/callback/google/gemini`;
    
    // Pass userId and messId so we can retrieve it in the callback
    const state = `${user.id}:${messId}`;
    
    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'openid email profile',
      access_type: 'offline',
      prompt: 'consent',
      state: state
    });
    
    res.json({ url: `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}` });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get(["/api/auth/callback/google/gemini", "/api/auth/callback/google/gemini/"], async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code) {
      return res.status(400).send("No Auth Code Provided");
    }
    if (!state) {
      return res.status(400).send("No State Parameter Found");
    }

    const [userId, messId] = (state as string).split(":");
    if (!userId || !messId) {
      return res.status(400).send("Invalid OAuth state: missing userId or messId");
    }

    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
    const appUrl = process.env.APP_URL || "http://localhost:3000";
    const redirectUri = `${appUrl}/api/auth/callback/google/gemini`;

    if (!clientId || !clientSecret) {
      return res.status(500).send("Google credentials are not configured on the server. Please check your system settings.");
    }

    // Exchange auth code for token
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        code: code as string,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: "authorization_code"
      })
    });

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      return res.status(500).send(`Failed to exchange token for Gemini Auth: ${errorText}`);
    }

    const tokenData = await tokenResponse.json();
    const accessToken = tokenData.access_token;

    // Fetch user details
    const userinfoResponse = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });

    if (!userinfoResponse.ok) {
      return res.status(500).send("Failed to retrieve user information from Google for Gemini.");
    }

    const googleUser = await userinfoResponse.json();
    const email = googleUser.email;

    if (!email) {
      return res.status(400).send("Email address was not provided by Google for Gemini Auth.");
    }

    // Verify user is still admin of the mess
    const user = db.getUserById(userId);
    if (!user) {
      return res.status(404).send("User not found.");
    }

    const role = user.messRoles[messId];
    if (role !== 'admin') {
      return res.status(403).send("Only a Mess Admin has permission to bind Gemini.");
    }

    // Update Mess details
    const updatedMess = db.updateMess(messId, {
      geminiActive: true,
      geminiGoogleAuthEmail: email
    }, userId);

    db.addAudit({
      messId,
      userId,
      userName: user.name,
      action: `জেমিনি এআই সক্রিয় করা হয়েছে (গুগল অ্যাকাউন্টঃ ${email})`
    });

    // Send successful popup postMessage back to app window and auto-close
    res.send(`
      <html>
        <head>
          <title>Activating Gemini with Google...</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background-color: #f0fdf4; color: #166534; }
            .card { background: white; padding: 2.5rem; border-radius: 1.5rem; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.05); text-align: center; max-width: 420px; border: 1px solid #bbf7d0; }
            .icon { font-size: 3rem; margin-bottom: 1rem; }
            h2 { font-size: 1.25rem; font-weight: 700; color: #14532d; margin: 0 0 0.5rem; }
            p { font-size: 0.875rem; color: #15803d; margin: 0; }
          </style>
        </head>
        <body>
          <div class="card">
            <div class="icon">🤖✅</div>
            <h2>জেমিনি এআই সফলভাবে সক্রিয় হয়েছে!</h2>
            <p>মেস ম্যানেজার অ্যাকাউন্ট ${email}-এর মাধ্যমে আপনার মেস "${updatedMess?.name}"-এর জন্য এআই অ্যাসিস্ট্যান্ট সক্রিয় করা হয়েছে।</p>
          </div>
          <script>
            try {
              if (window.opener) {
                window.opener.postMessage({
                  type: 'GEMINI_AUTH_SUCCESS',
                  email: ${JSON.stringify(email)},
                  messId: ${JSON.stringify(messId)}
                }, '*');
                setTimeout(() => window.close(), 1500);
              } else {
                window.location.href = '/';
              }
            } catch (err) {
              window.location.href = '/';
            }
          </script>
        </body>
      </html>
    `);
  } catch (err: any) {
    res.status(500).send(`Gemini activation failure: ${err.message}`);
  }
});

app.post("/api/auth/google/gemini/sso-simulation", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    if (!messId) {
      return res.status(400).json({ error: "কোনো মেস অ্যাক্টিভ নেই।" });
    }

    const role = user.messRoles[messId];
    if (role !== 'admin') {
      return res.status(403).json({ error: "অনুমতি নেই! শুধুমাত্র মেস এডমিন এটি করতে পারেন।" });
    }

    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: "অনুগ্রহ করে গুগল ইমেইল দিন।" });
    }

    const updatedMess = db.updateMess(messId, {
      geminiActive: true,
      geminiGoogleAuthEmail: email
    }, user.id);

    db.addAudit({
      messId,
      userId: user.id,
      userName: user.name,
      action: `জেমিনি এআই সক্রিয় করা হয়েছে (ডেভোলপার সিমুলেশন অ্যাকাউন্টঃ ${email})`
    });

    res.json({ success: true, email, mess: updatedMess });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/auth/google/gemini/disconnect", requireAuth, (req, res) => {
  try {
    const user = (req as any).user;
    const messId = user.activeMessId;
    if (!messId) {
      return res.status(400).json({ error: "কোনো মেস অ্যাক্টিভ নেই।" });
    }

    const role = user.messRoles[messId];
    if (role !== 'admin') {
      return res.status(403).json({ error: "অনুমতি নেই।" });
    }

    const updatedMess = db.updateMess(messId, {
      geminiActive: false,
      geminiGoogleAuthEmail: null
    }, user.id);

    db.addAudit({
      messId,
      userId: user.id,
      userName: user.name,
      action: `জেমিনি এআই নিষ্ক্রিয় করা হয়েছে (গুগল অ্যাকাউন্ট বিচ্ছিন্ন করা হয়েছে)`
    });

    res.json({ success: true, mess: updatedMess });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// -------------------------------------------------------------
// DYNAMIC AI AUDIO/TEXT REPORTS AND PREDICTION INSIGHTS
// -------------------------------------------------------------
app.post("/api/ai/analyze", requireAuth, async (req, res) => {
  try {
    // Lazy check API Key
    const apiKey = process.env.GEMINI_API_KEY;
    const user = (req as any).user;
    const messId = user.activeMessId;
    if (!messId) {
      return res.status(400).json({ error: "কোনো মেস অ্যাক্টিভ নেই।" });
    }

    const activeMess = db.getMessById(messId);
    if (!activeMess || !activeMess.geminiActive) {
      return res.status(403).json({ 
        error: "আপনার এই মেসের জন্য জেমিনি এআই নিষ্ক্রিয় রয়েছে। জেমিনি সক্রিয় করতে মেস ম্যানেজারকে সেটিংস ট্যাব থেকে গুগল অ্যাকাউন্ট লগইন করার পারমিশন প্রদান করতে বলুন।" 
      });
    }

    const { language } = req.body;
    const targetLang = language === 'bn' ? 'Bengali' : 'English';

    // Formulate database insights matching this mess
    const activeMonth = new Date().toISOString().substring(0, 7);
    const mData = db.calculateSettlement(messId, activeMonth);
    
    const dbState = db.getDBState();
    const activeExpenses = Object.values(dbState.expenses).filter(e => e.messId === messId && e.month === activeMonth);

    // Categories
    const aggregatedCats = activeExpenses.reduce((acc, curr) => {
      acc[curr.category] = (acc[curr.category] || 0) + curr.amount;
      return acc;
    }, {} as Record<string, number>);

    if (!apiKey || apiKey === "MY_GEMINI_API_KEY") {
      // Return a wonderful structured local rule-based intelligence if key is mock
      const staticMockInsights = language === 'bn' 
        ? `### 🤖 MessBook AI স্মার্ট পর্যবেক্ষণ রিপোর্ট (${activeMonth})
1. **বাজারের খরচ বিশ্লেষণ:**
   - চলতি মাসে এখন পর্যন্ত মোট খরচ হয়েছে **৳${mData.totalExpenses}** টাকা। আপনার মিল রেট দাঁড়িয়েছে **৳${mData.mealRate.toFixed(2)}** টাকায়।
   - চাল ও শাকসবজি ক্রয়ে সবচেয়ে বেশি অংশ ব্যয় বা গ্রোসারি (**৳${aggregatedCats.grocery || 0}**) মেটানো হয়েছে। মেসের জ্বালানি গ্যাস বাবদ খরচ স্বাভাবিক মাত্রায় আছে।

2. **মিল রেট নিয়ন্ত্রণ ও সাশ্রয়ী টিপস:**
   - মিল রেট **৳৮০**-র উপরে চলে গেলে মাসের ভাড়ায় চাপ পড়তে পারে। গ্রোসারিগুলো সরাসরি কারওয়ান বাজার বা লোকাল পাইকারি আড়ত থেকে এককালীন কিনলে মিল প্রতি অন্তত ৫ থেকে ১০ টাকা সাশ্রয় সম্ভব।
   - সবজি এবং আলুর আইটেম বেশি ব্যবহার করে মাংসের মিল কিছুটা কমালে পুষ্টিগুণ ঠিক রেখেই মেসের মিল রেট কামানো সম্ভব।

3. **পরিশোধ এবং ব্যালেন্স সতর্কবার্তা:**
   - মেম্বারদের ব্যালেন্স শিট অনুযায়ী, কয়েকজন মেম্বার ঋণাত্মক ব্যালেন্সে আছেন। মাস শেষের পূর্বে মেসফান্ড সচল রাখতে ডিপোজিট বাড়াতে বলুন!`
        : `### 🤖 MessBook AI Smart Audit Report (${activeMonth})
1. **Expense Categories Analysis:**
   - Total expenditures recorded for this month total **৳${mData.totalExpenses}** BDT, resulting in a meal rate of **৳${mData.mealRate.toFixed(2)}**.
   - Your highest spending category is Grocery (**৳${aggregatedCats.grocery || 0}**). Utility expenses remain steady.

2. **Meal Rate Optimization Tips:**
   - If your Meal Rate exceeds BDT 80, consider optimizing bulk purchases. Buying dry commodities (lentils, oil, rice) in bulk once a month saves up to 12% compared to daily retail runs.
   - Adjust the menu cadence slightly: inserting nutritious lentil (dal) varieties can stabilize dynamic meal costs.

3. **Financial Flow Warning:**
   - Keep a watchful eye on member liabilities! Friendly reminders for due deposits will ensure the manager does not spend out-of-pocket for weekly grocery runs.`;

      return res.json({ analysis: staticMockInsights });
    }

    // Call real Gemini Flash API
    const ai = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        }
      }
    });

    const systemPrompt = `You are "MessBook AI" - an expert financial accountant and Bengali mess cultural intelligence consultant. 
Your goal is to analyze the provided mess expenses and meal counts list, and generate a highly engaging, specific, and actionable financial report in ${targetLang}. 
Refer to Bengali cultural terms like "Bazar" (বাজার), "Manager" (ম্যানেজার), "Meal Rate" (মিল রেট), and "Bazaar List". 
Give solid advice on how the members can reduce their meal rates, buy items in bulk, prevent out-of-pocket manager expenses, and handle upcoming bill deadlines (Rent, Electricity).
Structure your response beautifully with descriptive Markdown, bold headings, alerts, and leaderboards.`;

    const userPrompt = `
Mess Details:
- Name: "${activeMess?.name}"
- Members count: ${activeMess?.members.length}
- Target month: ${activeMonth}

Current Month Stats:
- Total Expenses: ৳${mData.totalExpenses}
- Total Meals served: ${mData.totalMeals}
- Estimated Meal Rate: ৳${mData.mealRate}

Category Breakdown:
${JSON.stringify(aggregatedCats, null, 2)}

Members Summary:
${JSON.stringify(mData.memberSummaries.map(s => ({ name: s.name, balance: s.balance, meals: s.mealCount })), null, 2)}
    `;

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: userPrompt,
      config: {
        systemInstruction: systemPrompt,
        temperature: 0.7
      }
    });

    res.json({ analysis: response.text });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// -------------------------------------------------------------
// VITE DEV SERVER OR CLIENT PRODUCTION SERVING LAYER
// -------------------------------------------------------------
async function bootstrap() {
  if (process.env.NODE_ENV !== "production") {
    // Development middleware serving files dynamically
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
    console.log("Vite development server middleware loaded.");
  } else {
    // Production build artifacts serve
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
    console.log("Serving production build from 'dist'.");
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`MessBook server booted successfully at http://localhost:${PORT}`);
  });
}

bootstrap();
