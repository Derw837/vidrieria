require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"]
  }
});

app.use(cors());
app.use(express.json());

// Configuración de la base de datos
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '', 
  database: 'vidrieria_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Clave secreta para JWT
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware de autenticación
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acceso denegado' });
  }
  next();
};

// Rutas de administración (protegidas por authenticateToken y isAdmin)
app.get('/api/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [users] = await pool.query('SELECT id, username, role FROM users');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener usuarios' });
  }
});

app.post('/api/users', authenticateToken, isAdmin, async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
      [username, hashedPassword, role]
    );
    res.status(201).json({ message: 'Usuario creado exitosamente' });
  } catch (error) {
    res.status(500).json({ error: 'Error al crear usuario' });
  }
});

app.put('/api/users/:id/password', authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { newPassword } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, id]);
    res.json({ message: 'Contraseña actualizada exitosamente' });
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar contraseña' });
  }
});

app.delete('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM users WHERE id = ?', [id]);
    res.json({ message: 'Usuario eliminado exitosamente' });
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar usuario' });
  }
});

// Rutas para gestión de cortadores
app.post('/api/cortadores', authenticateToken, isAdmin, async (req, res) => {
  const { nombre } = req.body;
  try {
    await pool.query('INSERT INTO cortadores (nombre) VALUES (?)', [nombre]);
    res.status(201).json({ message: 'Cortador creado exitosamente' });
  } catch (error) {
    res.status(500).json({ error: 'Error al crear cortador' });
  }
});

app.delete('/api/cortadores/:id', authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM cortadores WHERE id = ?', [id]);
    res.json({ message: 'Cortador eliminado exitosamente' });
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar cortador' });
  }
});

// Ruta para registrar usuarios
app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashedPassword, role]);
    res.status(201).json({ message: 'Usuario creado exitosamente' });
  } catch (error) {
    res.status(500).json({ error: 'Error al crear el usuario' });
  }
});

// Ruta para iniciar sesión
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (users.length === 0) {
      return res.status(400).json({ error: 'Usuario no encontrado' });
    }
    const user = users[0];
    if (await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET);
      res.json({ token, role: user.role });
    } else {
      res.status(400).json({ error: 'Contraseña incorrecta' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Error al iniciar sesión' });
  }
});

// Ruta para obtener pedidos
app.get('/api/pedidos', authenticateToken, async (req, res) => {
  try {
    const [pedidos] = await pool.query('SELECT * FROM pedidos ORDER BY fecha_ingreso DESC');
    
    for (let pedido of pedidos) {
      const [productos] = await pool.query('SELECT * FROM productos_pedido WHERE pedido_id = ?', [pedido.id]);
      pedido.productos = productos;
    }
    
    res.json(pedidos);
  } catch (error) {
    console.error('Error al obtener pedidos:', error);
    res.status(500).json({ error: 'Error al obtener pedidos' });
  }
});

// Ruta pública para obtener pedidos (sin autenticación)
app.get('/api/pedidos-publicos', async (req, res) => {
  try {
    const [pedidos] = await pool.query('SELECT * FROM pedidos ORDER BY fecha_ingreso DESC');
    
    for (let pedido of pedidos) {
      const [productos] = await pool.query('SELECT * FROM productos_pedido WHERE pedido_id = ?', [pedido.id]);
      pedido.productos = productos;
    }
    
    res.json(pedidos);
  } catch (error) {
    console.error('Error al obtener pedidos:', error);
    res.status(500).json({ error: 'Error al obtener pedidos' });
  }
});

// Ruta para crear un nuevo pedido
app.post('/api/pedidos', authenticateToken, async (req, res) => {
  const { numero_factura, cliente, fecha_entrega, productos } = req.body;
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const [result] = await connection.query(
      'INSERT INTO pedidos (numero_factura, cliente, fecha_ingreso, fecha_entrega) VALUES (?, ?, NOW(), ?)',
      [numero_factura, cliente, fecha_entrega]
    );
    const pedidoId = result.insertId;

    for (const producto of productos) {
      await connection.query(
        'INSERT INTO productos_pedido (pedido_id, descripcion, cantidad, ingreso, egreso, total) VALUES (?, ?, ?, ?, ?, ?)',
        [pedidoId, producto.descripcion, producto.cantidad, producto.ingreso, producto.egreso, producto.total]
      );
    }

    await connection.commit();

    const [nuevoPedido] = await connection.query('SELECT * FROM pedidos WHERE id = ?', [pedidoId]);
    const [productosDelPedido] = await connection.query('SELECT * FROM productos_pedido WHERE pedido_id = ?', [pedidoId]);
    nuevoPedido[0].productos = productosDelPedido;

    io.emit('actualizacionPedidos');
    res.status(201).json(nuevoPedido[0]);
  } catch (error) {
    await connection.rollback();
    console.error('Error al crear el pedido:', error);
    res.status(500).json({ error: 'Error al crear el pedido' });
  } finally {
    connection.release();
  }
});

// Ruta para actualizar un pedido
app.put('/api/pedidos/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { numero_factura, cliente, fecha_entrega, estado, cortador, productos } = req.body;
  const userRole = req.user.role;
  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    let query = 'UPDATE pedidos SET ';
    const updateValues = [];
    const updateFields = [];

    if (numero_factura !== undefined) {
      updateFields.push('numero_factura = ?');
      updateValues.push(numero_factura);
    }
    if (cliente !== undefined) {
      updateFields.push('cliente = ?');
      updateValues.push(cliente);
    }
    if (fecha_entrega !== undefined) {
      updateFields.push('fecha_entrega = ?');
      updateValues.push(fecha_entrega);
    }
    if (estado !== undefined) {
      updateFields.push('estado = ?');
      updateValues.push(estado);
    }
    if (cortador !== undefined) {
      updateFields.push('cortador = ?');
      updateValues.push(cortador);
    }

    query += updateFields.join(', ');
    query += ' WHERE id = ?';
    updateValues.push(id);

    if (updateFields.length > 0) {
      await connection.query(query, updateValues);
    }

    if (productos && productos.length > 0) {
      await connection.query('DELETE FROM productos_pedido WHERE pedido_id = ?', [id]);
      for (const producto of productos) {
        await connection.query(
          'INSERT INTO productos_pedido (pedido_id, descripcion, cantidad, ingreso, egreso, total) VALUES (?, ?, ?, ?, ?, ?)',
          [id, producto.descripcion, producto.cantidad, producto.ingreso, producto.egreso, producto.total]
        );
      }
    }

    await connection.commit();

    const [updatedPedido] = await connection.query('SELECT * FROM pedidos WHERE id = ?', [id]);
    const [productosDelPedido] = await connection.query('SELECT * FROM productos_pedido WHERE pedido_id = ?', [id]);
    updatedPedido[0].productos = productosDelPedido;
    
    io.emit('actualizacionPedidos');
    
    let mensajeCambio = '';
    if (userRole === 'cortador') {
      if (estado) {
        mensajeCambio = `Pedido ${updatedPedido[0].numero_factura} - ${updatedPedido[0].cliente}: Se ha actualizado el estado a ${estado}`;
      }
    } else {
      if (estado) {
        mensajeCambio = `Pedido ${updatedPedido[0].numero_factura} - ${updatedPedido[0].cliente}: Se ha actualizado el estado a ${estado}`;
      }
      if (cortador) {
        mensajeCambio = `Pedido ${updatedPedido[0].numero_factura} - ${updatedPedido[0].cliente}: Se ha asignado al cortador ${cortador}`;
      }
    }
    
    if (mensajeCambio) {
      io.emit('pedidoActualizado', { 
        id: id,
        cambio: mensajeCambio,
        pedido: updatedPedido[0]
      });
    }

    res.json(updatedPedido[0]);
  } catch (error) {
    await connection.rollback();
    console.error('Error al actualizar el pedido:', error);
    res.status(500).json({ error: 'Error al actualizar el pedido' });
  } finally {
    connection.release();
  }
});

// Ruta para eliminar un pedido
app.delete('/api/pedidos/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    await connection.query('DELETE FROM productos_pedido WHERE pedido_id = ?', [id]);
    await connection.query('DELETE FROM pedidos WHERE id = ?', [id]);
    await connection.commit();
    io.emit('actualizacionPedidos');
    res.json({ message: 'Pedido eliminado exitosamente' });
  } catch (error) {
    await connection.rollback();
    console.error('Error al eliminar el pedido:', error);
    res.status(500).json({ error: 'Error al eliminar el pedido' });
  } finally {
    connection.release();
  }
});

// Ruta para obtener cortadores
app.get('/api/cortadores', authenticateToken, async (req, res) => {
  try {
    const [cortadores] = await pool.query('SELECT * FROM cortadores');
    res.json(cortadores);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener cortadores' });
  }
});

// Socket.io connection
io.on('connection', (socket) => {
  console.log('Nuevo cliente conectado');
  socket.on('disconnect', () => {
    console.log('Cliente desconectado');
  });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log(`Servidor corriendo en el puerto ${PORT}`));