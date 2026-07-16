require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');

const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(express.json());
app.use(express.static('public'));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 8 } // 8 hour session
}));

// Middleware: blocks access unless logged in
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  res.status(401).json({ error: 'Not authenticated. Please log in.' });
}

// LOGIN
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  db.query('SELECT * FROM users WHERE username = ?', [username], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Login failed. Please try again.' });
    }
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    const user = rows[0];
    bcrypt.compare(password, user.password_hash, (err, match) => {
      if (err || !match) {
        return res.status(401).json({ error: 'Invalid username or password.' });
      }
      req.session.userId = user.user_id;
      req.session.username = user.username;
      req.session.role = user.role;
      res.json({ message: 'Logged in successfully.', username: user.username, role: user.role });
    });
  });
});

// LOGOUT
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ message: 'Logged out.' });
  });
});

// CHECK SESSION (so the frontend knows if you're logged in on page load)
app.get('/api/session', (req, res) => {
  if (req.session && req.session.userId) {
    res.json({ loggedIn: true, username: req.session.username, role: req.session.role });
  } else {
    res.json({ loggedIn: false });
  }
});

// Connection POOL instead of a single connection — survives MySQL restarts,
// automatically reconnects, and handles multiple simultaneous requests safely.
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Quick sanity check on startup (pool connects lazily per-query, but this confirms credentials work)
db.getConnection((err, connection) => {
  if (err) {
    console.error('Database connection failed:', err.message);
    return;
  }
  console.log('Connected to MySQL database.');
  connection.release();
});

// Basic input validation: only allow reasonable invoice number formats
// (letters, numbers, hyphens, underscores, 1-50 chars). Rejects anything else
// before it ever reaches the database.
function isValidInvoiceNumber(value) {
  return typeof value === 'string' && /^[A-Za-z0-9\-_]{1,50}$/.test(value);
}

app.get('/api/purchase-orders/:invoiceNumber', requireAuth, (req, res) => {
  const invoiceNumber = req.params.invoiceNumber;

  if (!isValidInvoiceNumber(invoiceNumber)) {
    return res.status(400).json({ error: 'Invalid invoice number format.' });
  }

  // Parameterized query ($ placeholder) — this is what actually prevents SQL injection.
  // Never build queries with string concatenation like `WHERE invoice_number = '${invoiceNumber}'`.
  const query = `
    SELECT po.invoice_number, po.order_date, po.total_amount, po.status,
           s.name AS supplier_name, s.contact_info,
           pi.product_name, pi.quantity, pi.unit_price
    FROM purchase_orders po
    JOIN suppliers s ON po.supplier_id = s.supplier_id
    LEFT JOIN purchase_items pi ON po.po_id = pi.po_id
    WHERE po.invoice_number = ?
  `;

  db.query(query, [invoiceNumber], (err, results) => {
    if (err) {
      console.error('Query error:', err.message);
      // Never send raw error details to the browser — that can leak schema info to attackers.
      return res.status(500).json({ error: 'Something went wrong. Please try again.' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'Invoice not found.' });
    }
    res.json(results);
  });
});

// Helper: get supplier_id from a supplier name, or create the supplier if new
function getOrCreateSupplierId(name, contactInfo, callback) {
  db.query('SELECT supplier_id FROM suppliers WHERE name = ?', [name], (err, rows) => {
    if (err) return callback(err);
    if (rows.length > 0) return callback(null, rows[0].supplier_id);

    db.query(
      'INSERT INTO suppliers (name, contact_info) VALUES (?, ?)',
      [name, contactInfo || null],
      (err, result) => {
        if (err) return callback(err);
        callback(null, result.insertId);
      }
    );
  });
}

function logAction(req, action, invoiceNumber, details) {
  db.query(
    'INSERT INTO audit_log (user_id, username, action, invoice_number, details) VALUES (?, ?, ?, ?, ?)',
    [req.session.userId, req.session.username, action, invoiceNumber, details || null],
    (err) => {
      if (err) console.error('Failed to write audit log:', err.message);
    }
  );
}

// CREATE a new purchase order (with items)
app.post('/api/purchase-orders', requireAuth, (req, res) => {
  const { invoice_number, supplier_name, contact_info, order_date, status, notes, items } = req.body;

  if (!isValidInvoiceNumber(invoice_number)) {
    return res.status(400).json({ error: 'Invalid invoice number format.' });
  }
  if (!supplier_name || typeof supplier_name !== 'string') {
    return res.status(400).json({ error: 'Supplier name is required.' });
  }
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'At least one line item is required.' });
  }

  // Validate each item and compute total
  let total = 0;
  for (const item of items) {
    if (!item.product_name || item.quantity <= 0 || item.unit_price < 0) {
      return res.status(400).json({ error: 'Each item needs a valid product name, quantity > 0, and non-negative price.' });
    }
    total += item.quantity * item.unit_price;
  }

  getOrCreateSupplierId(supplier_name, contact_info, (err, supplierId) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Failed to resolve supplier.' });
    }

    const poQuery = `
      INSERT INTO purchase_orders (invoice_number, supplier_id, order_date, total_amount, status, notes)
      VALUES (?, ?, ?, ?, ?, ?)
    `;
    db.query(
      poQuery,
      [invoice_number, supplierId, order_date || null, total, status || 'pending', notes || null],
      (err, result) => {
        if (err) {
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'An invoice with this number already exists.' });
          }
          console.error(err);
          return res.status(500).json({ error: 'Failed to create purchase order.' });
        }

        const poId = result.insertId;
        const itemValues = items.map(i => [poId, i.product_name, i.quantity, i.unit_price]);
        db.query(
          'INSERT INTO purchase_items (po_id, product_name, quantity, unit_price) VALUES ?',
          [itemValues],
          (err) => {
            if (err) {
              console.error(err);
              return res.status(500).json({ error: 'Purchase order created, but items failed to save.' });
            }
            logAction(req, 'create', invoice_number, `Created with ${items.length} item(s), total ৳${total}`);
            res.status(201).json({ message: 'Purchase order created successfully.', invoice_number });
          }
        );
      }
    );
  });
});

// UPDATE an existing purchase order's status/notes (simple edit — not line items)
app.put('/api/purchase-orders/:invoiceNumber', requireAuth, (req, res) => {
  const invoiceNumber = req.params.invoiceNumber;
  const { status, notes } = req.body;

  if (!isValidInvoiceNumber(invoiceNumber)) {
    return res.status(400).json({ error: 'Invalid invoice number format.' });
  }
  const allowedStatuses = ['pending', 'paid', 'cancelled'];
  if (status && !allowedStatuses.includes(status)) {
    return res.status(400).json({ error: 'Status must be pending, paid, or cancelled.' });
  }

  db.query(
    'UPDATE purchase_orders SET status = COALESCE(?, status), notes = COALESCE(?, notes) WHERE invoice_number = ?',
    [status || null, notes || null, invoiceNumber],
    (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Failed to update purchase order.' });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Invoice not found.' });
      }
      logAction(req, 'update', invoiceNumber, `Status/notes updated: status=${status || 'unchanged'}, notes=${notes || 'unchanged'}`);
      res.json({ message: 'Purchase order updated successfully.' });
    }
  );
});

// DELETE a purchase order (and its items)
app.delete('/api/purchase-orders/:invoiceNumber', requireAuth, (req, res) => {
  const invoiceNumber = req.params.invoiceNumber;

  if (!isValidInvoiceNumber(invoiceNumber)) {
    return res.status(400).json({ error: 'Invalid invoice number format.' });
  }

  db.query('SELECT po_id FROM purchase_orders WHERE invoice_number = ?', [invoiceNumber], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Failed to look up invoice.' });
    }
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Invoice not found.' });
    }

    const poId = rows[0].po_id;
    db.query('DELETE FROM purchase_items WHERE po_id = ?', [poId], (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Failed to delete line items.' });
      }
      db.query('DELETE FROM purchase_orders WHERE po_id = ?', [poId], (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Failed to delete purchase order.' });
        }
        logAction(req, 'delete', invoiceNumber, `Invoice deleted`);
        res.json({ message: 'Purchase order deleted successfully.' });
      });
    });
  });
});

// DASHBOARD: summary stats with optional filters
app.get('/api/dashboard/summary', requireAuth, (req, res) => {
  const { startDate, endDate, status } = req.query;

  let whereClauses = [];
  let params = [];

  if (startDate) {
    whereClauses.push('po.order_date >= ?');
    params.push(startDate);
  }
  if (endDate) {
    whereClauses.push('po.order_date <= ?');
    params.push(endDate);
  }
  if (status && ['pending', 'paid', 'cancelled'].includes(status)) {
    whereClauses.push('po.status = ?');
    params.push(status);
  }

  const whereSQL = whereClauses.length > 0 ? 'WHERE ' + whereClauses.join(' AND ') : '';

  // 1. Overall totals + status breakdown
  const summaryQuery = `
    SELECT
      COUNT(*) AS total_invoices,
      COALESCE(SUM(po.total_amount), 0) AS total_spend,
      SUM(CASE WHEN po.status = 'paid' THEN po.total_amount ELSE 0 END) AS paid_spend,
      SUM(CASE WHEN po.status = 'pending' THEN po.total_amount ELSE 0 END) AS pending_spend,
      SUM(CASE WHEN po.status = 'cancelled' THEN po.total_amount ELSE 0 END) AS cancelled_spend,
      SUM(CASE WHEN po.status = 'paid' THEN 1 ELSE 0 END) AS paid_count,
      SUM(CASE WHEN po.status = 'pending' THEN 1 ELSE 0 END) AS pending_count,
      SUM(CASE WHEN po.status = 'cancelled' THEN 1 ELSE 0 END) AS cancelled_count
    FROM purchase_orders po
    ${whereSQL}
  `;

  // 2. Spend by supplier (top 10)
  const supplierQuery = `
    SELECT s.name AS supplier_name, SUM(po.total_amount) AS total_spend, COUNT(*) AS invoice_count
    FROM purchase_orders po
    JOIN suppliers s ON po.supplier_id = s.supplier_id
    ${whereSQL}
    GROUP BY s.name
    ORDER BY total_spend DESC
    LIMIT 10
  `;

  // 3. Monthly trend (last 12 months of matching data)
  const trendQuery = `
    SELECT DATE_FORMAT(po.order_date, '%Y-%m') AS month, SUM(po.total_amount) AS total_spend
    FROM purchase_orders po
    ${whereSQL}
    GROUP BY month
    ORDER BY month ASC
  `;

  db.query(summaryQuery, params, (err, summaryRows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Failed to load summary.' });
    }

    db.query(supplierQuery, params, (err, supplierRows) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Failed to load supplier breakdown.' });
      }

      db.query(trendQuery, params, (err, trendRows) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Failed to load trend data.' });
        }

        res.json({
          summary: summaryRows[0],
          bySupplier: supplierRows,
          trend: trendRows
        });
      });
    });
  });
});

app.get('/api/audit-log', requireAuth, (req, res) => {
  db.query(
    'SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 100',
    (err, rows) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Failed to load audit log.' });
      }
      res.json(rows);
    }
  );
});

app.get('/api/export/csv', requireAuth, (req, res) => {
  const query = `
    SELECT po.invoice_number, po.order_date, po.status, po.total_amount,
           s.name AS supplier_name
    FROM purchase_orders po
    JOIN suppliers s ON po.supplier_id = s.supplier_id
    ORDER BY po.order_date DESC
  `;
  db.query(query, (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Failed to export data.' });
    }

    const header = 'Invoice Number,Order Date,Supplier,Status,Total Amount\n';
    const csvRows = rows.map(r => {
      const date = r.order_date ? r.order_date.toISOString().split('T')[0] : '';
      // Escape commas/quotes in supplier names to keep the CSV valid
      const supplier = `"${(r.supplier_name || '').replace(/"/g, '""')}"`;
      return `${r.invoice_number},${date},${supplier},${r.status},${r.total_amount}`;
    }).join('\n');

    const csv = header + csvRows;
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=purchase_orders.csv');
    res.send(csv);
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});