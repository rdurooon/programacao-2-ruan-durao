const z = require('zod');
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { randomBytes, randomUUID, scryptSync, timingSafeEqual } = require('crypto');
const app = express();
app.use(cors());
app.use(bodyParser.json());
const users = [];
const sessions = new Map();
const perfisManuais = {};
const perfis = ['Administrador', 'Professor', 'Aluno'];
const emailAdmin = 'admin@email.com';
const senhaAdmin = 'Admin@123';
const saltAdmin = randomBytes(16).toString('hex');
users.push({
  id: randomUUID(),
  name: 'Administrador',
  email: emailAdmin,
  passwordHash: scryptSync(senhaAdmin, saltAdmin, 64).toString('hex'),
  salt: saltAdmin,
  perfil: 'Administrador'
});
const emailValidationSchema = z.object({
  email: z.string().email({ required_error: 'Email é necessario', invalid_type_error: 'Email não é valido.' }),
  confirmEmail: z.string().email({ required_error: 'Email de confirmação é necessario.', invalid_type_error: 'O email de confirmação deve ser valido.' })
}).refine(data => data.email === data.confirmEmail, {
  message: 'Emails devem ser iguais.',
  path: ['email', 'confirmEmail'],
});
const userRegistrationSchema = z.object({
  name: z.string().trim().min(1, 'Nome é necessario'),
  email: z.string().trim().email('Email não é valido.'),
  confirmEmail: z.string().trim().email('O email de confirmação deve ser valido.'),
  password: z.string().min(8, 'Senha deve ter 8 caracteres'),
  confirmPassword: z.string().min(1, 'Senha precisa ser confirmada.')
}).refine(data => data.email.toLowerCase() === data.confirmEmail.toLowerCase(), {
  message: 'Emails devem ser iguais.',
  path: ['confirmEmail'],
}).refine(data => data.password === data.confirmPassword, {
  message: 'Senhas devem ser iguais.',
  path: ['confirmPassword'],
});
app.post('/validateEmails', (req, res) => {
  try {
    emailValidationSchema.parse(req.body);
    res.send({ message: 'Emails validado com sucesso!' });
  } catch (error) {
    res.status(400).send(error);
  }
});
app.post('/register', (req, res) => {
  const result = userRegistrationSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).send({ errors: result.error.issues });
  }

  const { name, email, password } = result.data;
  const normalizedEmail = email.toLowerCase();
  if (users.some(user => user.email === normalizedEmail)) {
    return res.status(409).send({ message: 'Email já registrado.' });
  }

  const salt = randomBytes(16).toString('hex');
  const passwordHash = scryptSync(password, salt, 64).toString('hex');
  const perfil = z.enum(perfis).parse(perfisManuais[normalizedEmail] || 'Aluno');
  users.push({
    id: randomUUID(),
    name,
    email: normalizedEmail,
    passwordHash,
    salt,
    perfil
  });

  res.status(201).send({
    message: 'Usuário registrado com sucesso!',
    user: { name, email: normalizedEmail, perfil }
  });
});
const loginSchema = z.object({
  email: z.string().trim().email('Email não é valido.'),
  password: z.string().min(1, 'Senha é necessária.')
});
app.post('/login', (req, res) => {
  const result = loginSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).send({ errors: result.error.issues });
  }

  const user = users.find(item => item.email === result.data.email.toLowerCase());
  if (!user) {
    return res.status(401).send({ message: 'Email ou senha inválidos.' });
  }

  const passwordHash = scryptSync(result.data.password, user.salt, 64);
  const storedPasswordHash = Buffer.from(user.passwordHash, 'hex');
  if (!timingSafeEqual(passwordHash, storedPasswordHash)) {
    return res.status(401).send({ message: 'Email ou senha inválidos.' });
  }

  const token = randomBytes(32).toString('hex');
  sessions.set(token, user.id);
  res.send({
    token,
    user: { name: user.name, email: user.email, perfil: user.perfil }
  });
});
function verificarAutenticacao(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  const userId = token && sessions.get(token);
  const user = users.find(item => item.id === userId);
  if (!user) {
    return res.status(401).send({ mensagem: 'Autenticação necessária.' });
  }

  req.usuario = user;
  next();
}
function verificarPermissao(...perfisPermitidos) {
  return (req, res, next) => {
    if (!perfisPermitidos.includes(req.usuario.perfil)) {
      return res.status(403).send({ mensagem: 'Acesso negado.' });
    }

    next();
  };
}
app.post('/logout', verificarAutenticacao, (req, res) => {
  sessions.delete(req.headers.authorization.replace(/^Bearer\s+/i, ''));
  res.send({ mensagem: 'Sessão encerrada.' });
});
app.get('/admin', verificarAutenticacao, verificarPermissao('Administrador'), (req, res) => {
  res.send({ mensagem: 'Área do Administrador.' });
});
app.get('/professor', verificarAutenticacao, verificarPermissao('Professor'), (req, res) => {
  res.send({ mensagem: 'Área do Professor.' });
});
app.get('/aluno', verificarAutenticacao, verificarPermissao('Aluno'), (req, res) => {
  res.send({ mensagem: 'Área do Aluno.' });
});
app.listen(3000, () => console.log('Server running on port 3000'));