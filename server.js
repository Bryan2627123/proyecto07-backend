const express = require('express');
const cors = require('cors');
require('dotenv').config();
const authRoutes = require('./authRoutes');
const app = express();

// Middlewares
app.use(cors());
app.use(express.json());

// Rutas
app.use('/', authRoutes);

// Iniciar servidor
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
