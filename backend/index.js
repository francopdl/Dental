require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());

// Conexión MySQL con objeto (más seguro y flexible)
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
});

connection.connect(err => {
  if (err) {
    console.error('Error conectando a la base de datos:', err);
    process.exit(1); // termina si no hay conexión
  }
  console.log('✅ Conectado a la base de datos de Railway');
});

// Registro usuario
app.post('/register', async (req, res) => {
  const { mail, contraseña } = req.body;

  if (!mail || !contraseña) {
    return res.status(400).json({ error: 'Faltan mail o contraseña' });
  }

  connection.query(
    'SELECT * FROM usuarios WHERE mail = ?',
    [mail],
    async (err, results) => {
      if (err) {
        console.error('Error al buscar usuario:', err);
        return res.status(500).json({ error: 'Error interno' });
      }
      if (results.length > 0) {
        return res.status(400).json({ error: 'El mail ya está vinculado a una cuenta' });
      }

      try {
        const hashedPassword = await bcrypt.hash(contraseña, 10);
        connection.query(
          'INSERT INTO usuarios (mail, contraseña) VALUES (?, ?)',
          [mail, hashedPassword],
          (err, results) => {
            if (err) {
              console.error('Error al insertar usuario:', err);
              return res.status(500).json({ error: 'Error al crear usuario' });
            }
            res.status(201).json({ message: 'Usuario creado con éxito', id: results.insertId });
          }
        );
      } catch (hashError) {
        console.error('Error al hashear contraseña:', hashError);
        return res.status(500).json({ error: 'Error interno' });
      }
    }
  );
});

// Login usuario
app.post('/login', (req, res) => {
  const { mail, contraseña } = req.body;

  if (!mail || !contraseña) {
    return res.status(400).json({ error: 'Faltan mail o contraseña' });
  }

  connection.query(
    'SELECT * FROM usuarios WHERE mail = ?',
    [mail],
    async (err, results) => {
      if (err) {
        console.error('Error al buscar usuario:', err);
        return res.status(500).json({ error: 'Error interno' });
      }
      if (results.length === 0) {
        return res.status(400).json({ error: 'Usuario no encontrado' });
      }

      const user = results[0];
      const validPassword = await bcrypt.compare(contraseña, user.contraseña);

      if (!validPassword) {
        return res.status(400).json({ error: 'Contraseña incorrecta' });
      }

      // Aquí puedes generar un JWT o una cookie para sesión, por ahora respondemos OK
      res.json({ message: 'Login exitoso', userId: user.id });
    }
  );
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en el puerto ${PORT}`);
});
