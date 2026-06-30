const express    = require('express');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const { Pool }   = require('pg');
const http       = require('http');
const { Server } = require('socket.io');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());

// ─── BASE DE DATOS ───────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ─── CREAR TABLAS AL INICIAR ─────────────────────────────────────────────────
async function iniciarDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id          SERIAL PRIMARY KEY,
      nombre      TEXT NOT NULL,
      email       TEXT UNIQUE NOT NULL,
      password    TEXT NOT NULL,
      telefono    TEXT,
      rol         TEXT NOT NULL DEFAULT 'cliente',
      created_at  TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS tiendas (
      id          SERIAL PRIMARY KEY,
      nombre      TEXT NOT NULL,
      categoria   TEXT NOT NULL,
      emoji       TEXT DEFAULT '🏪',
      direccion   TEXT,
      telefono    TEXT,
      costo_domicilio INTEGER DEFAULT 2500,
      abierta     BOOLEAN DEFAULT true,
      owner_id    INTEGER REFERENCES usuarios(id),
      created_at  TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS productos (
      id          SERIAL PRIMARY KEY,
      tienda_id   INTEGER REFERENCES tiendas(id),
      nombre      TEXT NOT NULL,
      precio      INTEGER NOT NULL,
      emoji       TEXT DEFAULT '📦',
      categoria   TEXT DEFAULT 'General',
      activo      BOOLEAN DEFAULT true,
      stock       INTEGER DEFAULT 100,
      created_at  TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS pedidos (
      id              SERIAL PRIMARY KEY,
      cliente_id      INTEGER REFERENCES usuarios(id),
      tienda_id       INTEGER REFERENCES tiendas(id),
      domiciliario_id INTEGER REFERENCES usuarios(id),
      direccion       TEXT NOT NULL,
      referencia      TEXT,
      metodo_pago     TEXT DEFAULT 'efectivo',
      estado          TEXT DEFAULT 'pendiente',
      subtotal        INTEGER DEFAULT 0,
      domicilio       INTEGER DEFAULT 2500,
      total           INTEGER DEFAULT 0,
      created_at      TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS pedido_items (
      id          SERIAL PRIMARY KEY,
      pedido_id   INTEGER REFERENCES pedidos(id),
      producto_id INTEGER,
      nombre      TEXT NOT NULL,
      emoji       TEXT,
      precio      INTEGER NOT NULL,
      cantidad    INTEGER NOT NULL
    );
  `);
  console.log('✅ Tablas listas');
}

// ─── MIDDLEWARE AUTH ──────────────────────────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ mensaje: 'Sin token' });
  try {
    const token = header.replace('Bearer ', '');
    req.usuario = jwt.verify(token, process.env.JWT_SECRET || 'domiapp_secret_2026');
    next();
  } catch {
    res.status(401).json({ mensaje: 'Token inválido' });
  }
}

function soloRol(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.usuario.rol))
      return res.status(403).json({ mensaje: 'Sin permiso' });
    next();
  };
}

// ─── HEALTH ──────────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ ok: true, app: 'DomiApp Backend', version: '1.0' }));

// ─── AUTH ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/registro', async (req, res) => {
  try {
    const { nombre, email, password, telefono, rol = 'cliente' } = req.body;
    if (!nombre || !email || !password)
      return res.status(400).json({ mensaje: 'Faltan campos obligatorios' });

    const existe = await pool.query('SELECT id FROM usuarios WHERE email=$1', [email]);
    if (existe.rows.length > 0)
      return res.status(400).json({ mensaje: 'El correo ya está registrado' });

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO usuarios (nombre, email, password, telefono, rol) VALUES ($1,$2,$3,$4,$5) RETURNING id, nombre, email, rol',
      [nombre, email, hash, telefono || null, rol]
    );
    const usuario = result.rows[0];
    const token = jwt.sign(
      { id: usuario.id, nombre: usuario.nombre, rol: usuario.rol },
      process.env.JWT_SECRET || 'domiapp_secret_2026',
      { expiresIn: '30d' }
    );
    res.json({ token, id: usuario.id, nombre: usuario.nombre, rol: usuario.rol });
  } catch (err) {
    console.error(err);
    res.status(500).json({ mensaje: 'Error al registrar' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ mensaje: 'Faltan campos' });

    const result = await pool.query('SELECT * FROM usuarios WHERE email=$1', [email]);
    if (result.rows.length === 0)
      return res.status(401).json({ mensaje: 'Correo o contraseña incorrectos' });

    const usuario = result.rows[0];
    const ok = await bcrypt.compare(password, usuario.password);
    if (!ok) return res.status(401).json({ mensaje: 'Correo o contraseña incorrectos' });

    const token = jwt.sign(
      { id: usuario.id, nombre: usuario.nombre, rol: usuario.rol },
      process.env.JWT_SECRET || 'domiapp_secret_2026',
      { expiresIn: '30d' }
    );
    res.json({ token, id: usuario.id, nombre: usuario.nombre, rol: usuario.rol });
  } catch (err) {
    console.error(err);
    res.status(500).json({ mensaje: 'Error al ingresar' });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, nombre, email, telefono, rol FROM usuarios WHERE id=$1',
      [req.usuario.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ mensaje: 'Error' });
  }
});

// ─── TIENDAS ──────────────────────────────────────────────────────────────────
app.get('/api/tiendas', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM tiendas ORDER BY created_at DESC'
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ mensaje: 'Error al obtener tiendas' });
  }
});

app.get('/api/tiendas/:id', async (req, res) => {
  try {
    const tienda = await pool.query('SELECT * FROM tiendas WHERE id=$1', [req.params.id]);
    if (tienda.rows.length === 0) return res.status(404).json({ mensaje: 'Tienda no encontrada' });
    res.json(tienda.rows[0]);
  } catch (err) {
    res.status(500).json({ mensaje: 'Error' });
  }
});

app.post('/api/tiendas', auth, soloRol('tienda', 'admin'), async (req, res) => {
  try {
    const { nombre, categoria, emoji, direccion, telefono, costo_domicilio } = req.body;
    const result = await pool.query(
      'INSERT INTO tiendas (nombre, categoria, emoji, direccion, telefono, costo_domicilio, owner_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [nombre, categoria, emoji || '🏪', direccion, telefono, costo_domicilio || 2500, req.usuario.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ mensaje: 'Error al crear tienda' });
  }
});

app.put('/api/tiendas/:id', auth, soloRol('tienda', 'admin'), async (req, res) => {
  try {
    const { nombre, categoria, emoji, direccion, telefono, costo_domicilio, abierta } = req.body;
    const result = await pool.query(
      'UPDATE tiendas SET nombre=$1, categoria=$2, emoji=$3, direccion=$4, telefono=$5, costo_domicilio=$6, abierta=$7 WHERE id=$8 RETURNING *',
      [nombre, categoria, emoji, direccion, telefono, costo_domicilio, abierta, req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ mensaje: 'Error al actualizar tienda' });
  }
});

// Toggle abierta/cerrada
app.patch('/api/tiendas/:id/estado', auth, soloRol('tienda', 'admin'), async (req, res) => {
  try {
    const { abierta } = req.body;
    const result = await pool.query(
      'UPDATE tiendas SET abierta=$1 WHERE id=$2 AND owner_id=$3 RETURNING *',
      [abierta, req.params.id, req.usuario.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ mensaje: 'Error' });
  }
});

// ─── PRODUCTOS ────────────────────────────────────────────────────────────────
app.get('/api/tiendas/:id/productos', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM productos WHERE tienda_id=$1 ORDER BY categoria, nombre',
      [req.params.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ mensaje: 'Error al obtener productos' });
  }
});

app.post('/api/productos', auth, soloRol('tienda', 'admin'), async (req, res) => {
  try {
    const { tienda_id, nombre, precio, emoji, categoria, stock } = req.body;
    const result = await pool.query(
      'INSERT INTO productos (tienda_id, nombre, precio, emoji, categoria, stock) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [tienda_id, nombre, precio, emoji || '📦', categoria || 'General', stock || 100]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ mensaje: 'Error al crear producto' });
  }
});

app.put('/api/productos/:id', auth, soloRol('tienda', 'admin'), async (req, res) => {
  try {
    const { nombre, precio, emoji, categoria, activo, stock } = req.body;
    const result = await pool.query(
      'UPDATE productos SET nombre=$1, precio=$2, emoji=$3, categoria=$4, activo=$5, stock=$6 WHERE id=$7 RETURNING *',
      [nombre, precio, emoji, categoria, activo, stock, req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ mensaje: 'Error al actualizar producto' });
  }
});

app.delete('/api/productos/:id', auth, soloRol('tienda', 'admin'), async (req, res) => {
  try {
    await pool.query('UPDATE productos SET activo=false WHERE id=$1', [req.params.id]);
    res.json({ mensaje: 'Producto desactivado' });
  } catch (err) {
    res.status(500).json({ mensaje: 'Error' });
  }
});

// ─── PEDIDOS ──────────────────────────────────────────────────────────────────
app.post('/api/pedidos', auth, async (req, res) => {
  const client = await pool.connect();
  try {
    const { tienda_id, items, direccion, referencia, metodo_pago } = req.body;
    const subtotal = items.reduce((a, i) => a + i.precio * i.cantidad, 0);

    // Obtener costo domicilio de la tienda
    const tiendaRes = await client.query('SELECT costo_domicilio FROM tiendas WHERE id=$1', [tienda_id]);
    const domicilio = tiendaRes.rows[0]?.costo_domicilio || 2500;
    const total = subtotal + domicilio;

    await client.query('BEGIN');

    const pedidoRes = await client.query(
      'INSERT INTO pedidos (cliente_id, tienda_id, direccion, referencia, metodo_pago, subtotal, domicilio, total) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
      [req.usuario.id, tienda_id, direccion, referencia || null, metodo_pago || 'efectivo', subtotal, domicilio, total]
    );
    const pedido = pedidoRes.rows[0];

    // Insertar items
    for (const item of items) {
      await client.query(
        'INSERT INTO pedido_items (pedido_id, producto_id, nombre, emoji, precio, cantidad) VALUES ($1,$2,$3,$4,$5,$6)',
        [pedido.id, item.id || null, item.nombre, item.emoji || '📦', item.precio, item.cantidad]
      );
    }

    await client.query('COMMIT');

    // Notificar a la tienda por WebSocket
    io.to(`tienda-${tienda_id}`).emit('nuevo-pedido', {
      pedidoId: pedido.id,
      cliente: req.usuario.nombre,
      total,
      items: items.length
    });

    res.json({ pedidoId: pedido.id, total, estado: 'pendiente' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ mensaje: 'Error al crear pedido' });
  } finally {
    client.release();
  }
});

// Pedidos de la tienda (para panel-tienda)
app.get('/api/pedidos/tienda/:tiendaId', auth, soloRol('tienda', 'admin'), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.*, u.nombre as cliente_nombre, u.telefono as cliente_telefono
      FROM pedidos p
      JOIN usuarios u ON p.cliente_id = u.id
      WHERE p.tienda_id = $1
      ORDER BY p.created_at DESC
      LIMIT 50
    `, [req.params.tiendaId]);

    // Obtener items de cada pedido
    for (const pedido of result.rows) {
      const items = await pool.query('SELECT * FROM pedido_items WHERE pedido_id=$1', [pedido.id]);
      pedido.items = items.rows;
    }

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ mensaje: 'Error al obtener pedidos' });
  }
});

// Pedidos del cliente (historial)
app.get('/api/pedidos/mis-pedidos', auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.*, t.nombre as tienda_nombre, t.emoji as tienda_emoji
      FROM pedidos p
      JOIN tiendas t ON p.tienda_id = t.id
      WHERE p.cliente_id = $1
      ORDER BY p.created_at DESC
    `, [req.usuario.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ mensaje: 'Error' });
  }
});

// Pedido por ID con items
app.get('/api/pedidos/:id', auth, async (req, res) => {
  try {
    const pedidoRes = await pool.query(`
      SELECT p.*, t.nombre as tienda_nombre, t.emoji as tienda_emoji,
             u.nombre as cliente_nombre, u.telefono as cliente_telefono
      FROM pedidos p
      JOIN tiendas t ON p.tienda_id = t.id
      JOIN usuarios u ON p.cliente_id = u.id
      WHERE p.id = $1
    `, [req.params.id]);

    if (pedidoRes.rows.length === 0)
      return res.status(404).json({ mensaje: 'Pedido no encontrado' });

    const pedido = pedidoRes.rows[0];
    const items = await pool.query('SELECT * FROM pedido_items WHERE pedido_id=$1', [pedido.id]);
    pedido.items = items.rows;

    res.json(pedido);
  } catch (err) {
    res.status(500).json({ mensaje: 'Error' });
  }
});

// Cambiar estado del pedido
app.patch('/api/pedidos/:id/estado', auth, async (req, res) => {
  try {
    const { estado } = req.body;
    const estados = ['pendiente', 'aceptado', 'preparando', 'listo', 'en_camino', 'entregado', 'rechazado'];
    if (!estados.includes(estado))
      return res.status(400).json({ mensaje: 'Estado inválido' });

    const result = await pool.query(
      'UPDATE pedidos SET estado=$1 WHERE id=$2 RETURNING *, cliente_id, tienda_id',
      [estado, req.params.id]
    );
    const pedido = result.rows[0];

    // Notificar al cliente por WebSocket
    io.to(`cliente-${pedido.cliente_id}`).emit('pedido-actualizado', {
      pedidoId: pedido.id,
      estado
    });

    // Si está listo, notificar a domiciliarios disponibles
    if (estado === 'listo') {
      io.emit('pedido-listo-para-recoger', {
        pedidoId: pedido.id,
        tiendaId: pedido.tienda_id,
        total: pedido.total
      });
    }

    res.json(pedido);
  } catch (err) {
    res.status(500).json({ mensaje: 'Error al cambiar estado' });
  }
});

// Asignar domiciliario
app.patch('/api/pedidos/:id/asignar', auth, soloRol('domiciliario', 'admin'), async (req, res) => {
  try {
    const result = await pool.query(
      'UPDATE pedidos SET domiciliario_id=$1, estado=$2 WHERE id=$3 RETURNING *',
      [req.usuario.id, 'en_camino', req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ mensaje: 'Error al asignar' });
  }
});

// Pedidos disponibles para domiciliario
app.get('/api/pedidos/disponibles/domiciliario', auth, soloRol('domiciliario', 'admin'), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.*, t.nombre as tienda_nombre, t.direccion as tienda_dir
      FROM pedidos p
      JOIN tiendas t ON p.tienda_id = t.id
      WHERE p.estado = 'listo' AND p.domiciliario_id IS NULL
      ORDER BY p.created_at ASC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ mensaje: 'Error' });
  }
});

// ─── USUARIOS (admin) ─────────────────────────────────────────────────────────
app.get('/api/usuarios', auth, soloRol('admin'), async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, nombre, email, telefono, rol, created_at FROM usuarios ORDER BY created_at DESC'
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ mensaje: 'Error' });
  }
});

// ─── WEBSOCKET ────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log('🔌 Conectado:', socket.id);

  socket.on('join-tienda',       (id) => { socket.join(`tienda-${id}`);       console.log(`Tienda ${id} conectada`); });
  socket.on('join-cliente',      (id) => { socket.join(`cliente-${id}`);      });
  socket.on('join-domiciliario', (id) => { socket.join(`domiciliario-${id}`); });

  socket.on('disconnect', () => console.log('❌ Desconectado:', socket.id));
});

// ─── INICIAR SERVIDOR ─────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;

iniciarDB().then(() => {
  server.listen(PORT, () => console.log(`🚀 DomiApp corriendo en puerto ${PORT}`));
}).catch(err => {
  console.error('Error iniciando BD:', err);
  process.exit(1);
});
