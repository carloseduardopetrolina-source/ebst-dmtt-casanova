require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
// Chave secreta exclusiva do servidor para assinar os tokens JWT
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// 1. Blindagem de Cabeçalhos HTTP (Helmet)
app.use(helmet({
  contentSecurityPolicy: false // Permite CDNs visuais do Tailwind/FontAwesome no front-end
}));

// Limite de payload ajustado para suportar fotos comprimidas e croqui
app.use(express.json({ limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// 2. Proteção contra Ataques de Força Bruta no Login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // Janela de 15 minutos
  max: 6, // Máximo de 6 tentativas por IP
  message: { erro: 'Muitas tentativas de login. Acesso bloqueado temporariamente por 15 minutos.' }
});

// 3. Banco de Dados Relacional SQLite no Servidor (Inacessível pelo navegador)
const db = new sqlite3.Database(path.join(__dirname, 'dmtt_bst_seguro.sqlite'));

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT NOT NULL,
      matricula TEXT NOT NULL,
      login TEXT UNIQUE NOT NULL,
      senha_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'operador')),
      criado_em DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS boletins (
      bst_numero TEXT PRIMARY KEY,
      dados_json TEXT NOT NULL,
      autor_registro TEXT NOT NULL,
      atualizado_em TEXT NOT NULL,
      timestamp_ms INTEGER NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS auditoria_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      usuario TEXT,
      acao TEXT,
      alvo TEXT,
      ip TEXT,
      data_hora DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Cria os usuários iniciais com senha criptografada (Hash Bcrypt Custo 12)
  db.get(`SELECT COUNT(*) as total FROM usuarios`, async (err, row) => {
    if (!err && row.total === 0) {
      const hashAdmin = await bcrypt.hash('dmtt@2026', 12);
      const hashOperador = await bcrypt.hash('123456', 12);
      db.run(
        `INSERT INTO usuarios (nome, matricula, login, senha_hash, role) VALUES (?, ?, ?, ?, ?)`,
        ['Administrador Geral DMTT', 'ADM-001', 'admin', hashAdmin, 'admin']
      );
      db.run(
        `INSERT INTO usuarios (nome, matricula, login, senha_hash, role) VALUES (?, ?, ?, ?, ?)`,
        ['Agente Operador Plantonista', 'OP-101', 'operador', hashOperador, 'operador']
      );
      console.log('Banco de Dados inicializado com criptografia Bcrypt.');
    }
  });
});

function registrarAuditoria(usuario, acao, alvo, ip) {
  db.run(`INSERT INTO auditoria_logs (usuario, acao, alvo, ip) VALUES (?, ?, ?, ?)`, [usuario, acao, alvo, ip]);
}

// 4. Middlewares de Autenticação JWT e Controle de Perfil (RBAC)
function autenticarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ erro: 'Token de autenticação ausente.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ erro: 'Sessão expirada ou token inválido. Faça login novamente.' });
    req.user = user;
    next();
  });
}

function exigirAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ erro: 'Acesso negado: operação exclusiva para Administrador.' });
  }
  next();
}

// ==================== ROTAS DA API SEGURA ====================

// Login com verificação Bcrypt e emissão de JWT
app.post('/api/login', loginLimiter, (req, res) => {
  const login = String(req.body.login || '').trim().toLowerCase();
  const senha = String(req.body.senha || '').trim();

  db.get(`SELECT * FROM usuarios WHERE login = ?`, [login], async (err, user) => {
    if (err || !user) {
      registrarAuditoria(login, 'FALHA_LOGIN', 'Sistema', req.ip);
      return res.status(401).json({ erro: 'Usuário ou senha inválidos!' });
    }

    const senhaCorreta = await bcrypt.compare(senha, user.senha_hash);
    if (!senhaCorreta) {
      registrarAuditoria(login, 'SENHA_INCORRETA', 'Sistema', req.ip);
      return res.status(401).json({ erro: 'Usuário ou senha inválidos!' });
    }

    const payload = { id: user.id, nome: user.nome, matricula: user.matricula, login: user.login, role: user.role };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

    registrarAuditoria(user.login, 'LOGIN_SUCESSO', 'Sistema', req.ip);
    res.json({ token, usuario: payload });
  });
});

// Listar usuários (Exclusivo Admin - nunca retorna o hash da senha)
app.get('/api/usuarios', autenticarToken, exigirAdmin, (req, res) => {
  db.all(`SELECT id, nome, matricula, login, role, criado_em FROM usuarios ORDER BY id ASC`, [], (err, rows) => {
    if (err) return res.status(500).json({ erro: 'Erro ao buscar usuários.' });
    res.json(rows);
  });
});

// Criar usuário (Exclusivo Admin)
app.post('/api/usuarios', autenticarToken, exigirAdmin, async (req, res) => {
  const nome = String(req.body.nome || '').trim();
  const matricula = String(req.body.matricula || '').trim();
  const login = String(req.body.login || '').trim().toLowerCase();
  const senha = String(req.body.senha || '').trim();
  const role = req.body.role === 'admin' ? 'admin' : 'operador';

  if (!nome || !matricula || !login || senha.length < 6) {
    return res.status(400).json({ erro: 'Preencha todos os campos (a senha deve ter no mínimo 6 caracteres).' });
  }

  const senhaHash = await bcrypt.hash(senha, 12);
  db.run(
    `INSERT INTO usuarios (nome, matricula, login, senha_hash, role) VALUES (?, ?, ?, ?, ?)`,
    [nome, matricula, login, senhaHash, role],
    function (err) {
      if (err) return res.status(400).json({ erro: 'Já existe um usuário com este login.' });
      registrarAuditoria(req.user.login, 'CRIAR_USUARIO', login, req.ip);
      res.json({ mensagem: 'Usuário criado com sucesso!' });
    }
  );
});

// Revogar usuário (Exclusivo Admin)
app.delete('/api/usuarios/:login', autenticarToken, exigirAdmin, (req, res) => {
  const loginAlvo = String(req.params.login || '').toLowerCase();
  if (loginAlvo === 'admin') return res.status(400).json({ erro: 'O Administrador principal não pode ser removido.' });

  db.run(`DELETE FROM usuarios WHERE login = ?`, [loginAlvo], function (err) {
    if (err) return res.status(500).json({ erro: 'Erro ao remover usuário.' });
    registrarAuditoria(req.user.login, 'REMOVER_USUARIO', loginAlvo, req.ip);
    res.json({ mensagem: 'Acesso revogado com sucesso.' });
  });
});

// Listar Boletins (Operador e Admin autenticados)
app.get('/api/boletins', autenticarToken, (req, res) => {
  db.all(`SELECT dados_json FROM boletins ORDER BY timestamp_ms DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ erro: 'Erro ao listar boletins.' });
    const lista = rows.map(r => JSON.parse(r.dados_json));
    res.json(lista);
  });
});

// Salvar ou Editar Boletim (Operador e Admin autenticados)
app.post('/api/boletins', autenticarToken, (req, res) => {
  const b = req.body;
  if (!b || !b.bst_numero) return res.status(400).json({ erro: 'Número de BST inválido.' });

  b.autor_registro = `${req.user.nome} (${req.user.login})`;
  b.atualizado_em = new Date().toLocaleString('pt-BR');
  b.timestamp_ms = Date.now();

  db.run(
    `INSERT INTO boletins (bst_numero, dados_json, autor_registro, atualizado_em, timestamp_ms)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(bst_numero) DO UPDATE SET
       dados_json = excluded.dados_json,
       autor_registro = excluded.autor_registro,
       atualizado_em = excluded.atualizado_em,
       timestamp_ms = excluded.timestamp_ms`,
    [b.bst_numero, JSON.stringify(b), b.autor_registro, b.atualizado_em, b.timestamp_ms],
    function (err) {
      if (err) return res.status(500).json({ erro: 'Erro ao gravar boletim no banco de dados.' });
      registrarAuditoria(req.user.login, 'SALVAR_BST', b.bst_numero, req.ip);
      res.json({ mensagem: 'Boletim salvo com segurança no servidor!', bst_numero: b.bst_numero });
    }
  );
});

// Excluir Boletim (EXCLUSIVO ADMINISTRADOR NO SERVIDOR)
app.delete('/api/boletins/:numero', autenticarToken, exigirAdmin, (req, res) => {
  const num = req.params.numero;
  db.run(`DELETE FROM boletins WHERE bst_numero = ?`, [num], function (err) {
    if (err) return res.status(500).json({ erro: 'Erro ao excluir boletim.' });
    registrarAuditoria(req.user.login, 'EXCLUIR_BST', num, req.ip);
    res.json({ mensagem: 'Boletim excluído com sucesso!' });
  });
});

app.listen(PORT, () => {
  console.log(`Servidor Seguro e-BST DMTT Casa Nova-BA rodando em http://localhost:${PORT}`);
});