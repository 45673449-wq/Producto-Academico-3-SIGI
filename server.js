const express = require('express');
const session = require('express-session');
const bcrypt  = require('bcrypt');
const path    = require('path');
const db      = require('./database');

try { require('./seed'); } catch(e) { /* seed ya ejecutado */ }

const app  = express();
const PORT = 5000;

// ─── Middlewares base ────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(session({
  secret: 'sigi-secret-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 2 * 60 * 60 * 1000 }
}));

app.use(express.static(path.join(__dirname, 'public')));

// ─── Utilidades de validación ────────────────────────────────────────────────
const PATRON_PELIGROSO = /[<>"'%;()&+\\]/;

function sanitizar(valor) {
  if (typeof valor !== 'string') return valor;
  return valor.trim();
}

function tienePeligrosos(valor) {
  return PATRON_PELIGROSO.test(valor);
}

// ─── Middleware de autenticación ─────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.usuario) return next();
  return res.redirect('/');
}

// ─── Rutas de páginas (protegidas) ──────────────────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/gestion', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'gestion.html'));
});

app.get('/consultas', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'consultas.html'));
});

// ─── API: Sesión ─────────────────────────────────────────────────────────────
app.get('/api/sesion', (req, res) => {
  if (req.session && req.session.usuario) {
    return res.json({ ok: true, usuario: req.session.usuario });
  }
  return res.status(401).json({ ok: false });
});

app.post('/api/login', (req, res, next) => {
  try {
    const email    = sanitizar(req.body.email    || '');
    const password = sanitizar(req.body.password || '');

    if (!email || !password) {
      return res.status(400).json({ ok: false, mensaje: 'Email y contraseña son obligatorios.' });
    }
    if (tienePeligrosos(email)) {
      return res.status(400).json({ ok: false, mensaje: 'El email contiene caracteres no permitidos.' });
    }

    const stmt = db.prepare('SELECT id, nombre, email, rol, password FROM usuarios WHERE email = ?');
    const usuario = stmt.get(email.toLowerCase());

    if (!usuario || !bcrypt.compareSync(password, usuario.password)) {
      return res.status(401).json({ ok: false, mensaje: 'Credenciales incorrectas.' });
    }

    const { password: _, ...datosPublicos } = usuario;
    req.session.usuario = datosPublicos;

    return res.json({ ok: true, usuario: datosPublicos });
  } catch (err) {
    next(err);
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ─── API: Productos ───────────────────────────────────────────────────────────
app.get('/api/productos', requireAuth, (req, res, next) => {
  try {
    const productos = db.prepare('SELECT * FROM productos ORDER BY nombre ASC').all();
    res.json(productos);
  } catch (err) {
    next(err);
  }
});

app.post('/api/productos', requireAuth, (req, res, next) => {
  try {
    let { sku, nombre, categoria, precio, stock } = req.body;

    sku       = sanitizar(sku       || '');
    nombre    = sanitizar(nombre    || '');
    categoria = sanitizar(categoria || '');

    if (!sku || !nombre || !categoria) {
      return res.status(400).json({ ok: false, mensaje: 'SKU, nombre y categoría son obligatorios.' });
    }
    if ([sku, nombre, categoria].some(tienePeligrosos)) {
      return res.status(400).json({ ok: false, mensaje: 'Se detectaron caracteres no permitidos.' });
    }

    precio = parseFloat(precio);
    stock  = parseInt(stock, 10);

    if (isNaN(precio) || precio < 0) {
      return res.status(400).json({ ok: false, mensaje: 'El precio debe ser un número positivo.' });
    }
    if (isNaN(stock) || stock < 0) {
      return res.status(400).json({ ok: false, mensaje: 'El stock debe ser un número entero positivo.' });
    }

    const existente = db.prepare('SELECT id FROM productos WHERE sku = ?').get(sku);
    if (existente) {
      return res.status(409).json({ ok: false, mensaje: `Ya existe un producto con SKU "${sku}".` });
    }

    const stmt = db.prepare(
      'INSERT INTO productos (sku, nombre, categoria, precio, stock) VALUES (?, ?, ?, ?, ?)'
    );
    const info = stmt.run(sku, nombre, categoria, precio, stock);

    res.status(201).json({ ok: true, id: info.lastInsertRowid });
  } catch (err) {
    next(err);
  }
});

// ─── API: Movimientos (Kardex) ────────────────────────────────────────────────
app.get('/api/movimientos', requireAuth, (req, res, next) => {
  try {
    const { sku, categoria } = req.query;
    let movimientos;

    if (sku) {
      const skuLimpio = sanitizar(sku);
      if (tienePeligrosos(skuLimpio)) {
        return res.status(400).json({ ok: false, mensaje: 'Parámetro SKU inválido.' });
      }
      movimientos = db.prepare(`
        SELECT m.id, p.sku, p.nombre, p.categoria, m.tipo, m.cantidad, m.fecha
        FROM movimientos m
        JOIN productos p ON p.id = m.producto_id
        WHERE p.sku = ?
        ORDER BY m.fecha DESC
      `).all(skuLimpio);
    } else if (categoria) {
      const catLimpia = sanitizar(categoria);
      if (tienePeligrosos(catLimpia)) {
        return res.status(400).json({ ok: false, mensaje: 'Parámetro categoría inválido.' });
      }
      movimientos = db.prepare(`
        SELECT m.id, p.sku, p.nombre, p.categoria, m.tipo, m.cantidad, m.fecha
        FROM movimientos m
        JOIN productos p ON p.id = m.producto_id
        WHERE p.categoria LIKE ?
        ORDER BY m.fecha DESC
      `).all(`%${catLimpia}%`);
    } else {
      movimientos = db.prepare(`
        SELECT m.id, p.sku, p.nombre, p.categoria, m.tipo, m.cantidad, m.fecha
        FROM movimientos m
        JOIN productos p ON p.id = m.producto_id
        ORDER BY m.fecha DESC
      `).all();
    }

    res.json(movimientos);
  } catch (err) {
    next(err);
  }
});

app.post('/api/movimientos', requireAuth, (req, res, next) => {
  try {
    let { producto_id, tipo, cantidad } = req.body;

    tipo     = sanitizar(tipo || '');
    cantidad = parseInt(cantidad, 10);

    if (!producto_id || !tipo) {
      return res.status(400).json({ ok: false, mensaje: 'Producto y tipo son obligatorios.' });
    }
    if (!['entrada', 'salida'].includes(tipo)) {
      return res.status(400).json({ ok: false, mensaje: 'Tipo debe ser "entrada" o "salida".' });
    }
    if (isNaN(cantidad) || cantidad <= 0) {
      return res.status(400).json({ ok: false, mensaje: 'La cantidad debe ser un número entero mayor a 0.' });
    }

    const producto = db.prepare('SELECT id, stock FROM productos WHERE id = ?').get(Number(producto_id));
    if (!producto) {
      return res.status(404).json({ ok: false, mensaje: 'Producto no encontrado.' });
    }
    if (tipo === 'salida' && producto.stock < cantidad) {
      return res.status(400).json({ ok: false, mensaje: 'Stock insuficiente para realizar la salida.' });
    }

    const nuevoStock = tipo === 'entrada'
      ? producto.stock + cantidad
      : producto.stock - cantidad;

    db.prepare('UPDATE productos SET stock = ? WHERE id = ?').run(nuevoStock, producto.id);
    const info = db.prepare(
      'INSERT INTO movimientos (producto_id, tipo, cantidad) VALUES (?, ?, ?)'
    ).run(producto.id, tipo, cantidad);

    res.status(201).json({ ok: true, id: info.lastInsertRowid, nuevoStock });
  } catch (err) {
    next(err);
  }
});

// ─── Manejador global de errores ─────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(`[ERROR ${new Date().toISOString()}] ${req.method} ${req.path}:`, err.message);
  console.error(err.stack);
  res.status(500).json({ ok: false, mensaje: 'Error en el sistema. Inténtelo de nuevo más tarde.' });
});

// ─── Inicio ───────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor SIGI listo en puerto ${PORT}`);
});
