const db = require('./database');
const bcrypt = require('bcrypt');

const hashAdmin = bcrypt.hashSync('admin123', 10);

try {
  // 1. Crear/actualizar usuarios — siempre garantiza que la contraseña sea correcta
  const upsert = db.prepare(`
    INSERT INTO usuarios (nombre, email, password, rol)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(email) DO UPDATE SET password = excluded.password, nombre = excluded.nombre, rol = excluded.rol
  `);
  upsert.run('Eneas Rivas', 'Eneas.Rivas@sigi.edu.pe', hashAdmin, 'admin');
  upsert.run('Administrador', 'admin@sigi.edu.pe', hashAdmin, 'admin');
  console.log("✅ Usuario Admin listo.");

  // 2. Crear los productos del PDF
  const productos = [
    { sku: 'SKU-001', nombre: 'Laptop HP 15', cat: 'Electronica', precio: 2500, stock: 15 },
    { sku: 'SKU-002', nombre: 'Polo Básico Talla M', cat: 'Ropa', precio: 35, stock: 3 },
    { sku: 'SKU-003', nombre: 'Arroz Costeño 5kg', cat: 'Alimentos', precio: 22.5, stock: 40 }
  ];

  const insertProd = db.prepare('INSERT OR IGNORE INTO productos (sku, nombre, categoria, precio, stock) VALUES (?, ?, ?, ?, ?)');

  productos.forEach(p => {
    insertProd.run(p.sku, p.nombre, p.cat, p.precio, p.stock);
  });

  console.log("✅ Productos del PDF cargados.");
} catch (err) {
  console.error("❌ Error:", err.message);
}
