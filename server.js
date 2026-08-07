const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const fs = require("fs-extra");
const path = require("path");
const cors = require("cors");
const axios = require("axios");
const webPush = require('web-push');
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

// Una promesa rechazada sin capturar dentro de un handler async de Express 4
// (que no las atrapa solo) tumba el proceso entero en Node 15+ (comportamiento
// por defecto: terminar). Cualquier usuario autenticado podía tirar el
// servicio para todos con una sola petición (ver /add_finished y el guard de
// "__proto__" más abajo) — esto es la red de seguridad general para que un
// bug de ese tipo quede solo en el log, no tumbe el backend entero.
process.on("unhandledRejection", (reason) => {
  console.error("⚠️ Promesa rechazada sin capturar:", reason);
});

const app = express();

// En producción hay un Apache2 delante haciendo de proxy inverso por
// subdominio hacia este contenedor (ver CLAUDE.md) — Express no lo sabe por
// defecto, así que ve la conexión TCP del propio Apache para TODAS las
// peticiones en vez de la IP real de cada usuario. Sin esto, el rate
// limiting de más abajo trataría a todo el mundo como una sola IP
// compartiendo el mismo límite. "1" = confiar exactamente en ese salto
// inmediato (Apache añade X-Forwarded-For por defecto al hacer de proxy) —
// no más allá, para que nadie pueda falsificar esa cabecera y saltarse el
// límite fingiendo una IP distinta en cada petición.
app.set("trust proxy", 1);

// CORS restringido a los orígenes reales de la app (antes abierto a
// cualquier origen). El desktop (Electron) y el móvil/TV (Capacitor) cargan
// directamente la URL real de producción — no un esquema tipo capacitor://—
// así que su Origin es el mismo que el de un navegador normal en el sitio.
// Se permite también localhost/127.0.0.1 en cualquier puerto para
// desarrollo/pruebas locales. Peticiones sin cabecera Origin (curl,
// buenos_dias.sh, apps nativas que no la mandan) no se bloquean: CORS es una
// restricción del navegador, no protege nada frente a esos clientes.
const ALLOWED_ORIGINS = ["https://manga.yolli.xyz"];
const LOCAL_ORIGIN_RE = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;

app.use(cors({
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.includes(origin) || LOCAL_ORIGIN_RE.test(origin)) {
      return callback(null, true);
    }
    callback(new Error("Origen no permitido por CORS"));
  }
}));
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY;

// Limita intentos de fuerza bruta contra login/registro/notificaciones/admin
// desde fuera de la red local — la API es alcanzable desde internet, no solo
// desde la LAN, así que no hay ninguna otra capa que frene esto.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Demasiados intentos. Inténtalo de nuevo en unos minutos." }
});

// Los directorios de datos viven fuera del repo de backend/ (hermanos de
// backend/, frontend/, etc. en la carpeta wrapper), para que nunca queden
// mezclados con el código y se pierdan/aparezcan como cambios al tocar
// front o back. Por defecto se resuelven un nivel por encima de backend/
// (uso local sin Docker); en Docker, docker-compose fija estas variables de
// entorno para que apunten a los volúmenes montados en su lugar.
const STORAGE_DIR = process.env.MANGAS_DIR || path.join(__dirname, "..", "mangas");
const NOTIFICATIONS_DIR = process.env.NOTIFICATIONS_DIR || path.join(__dirname, "..", "notifications");
const SUBS_FILE = path.join(NOTIFICATIONS_DIR, "subscriptions.json");
const USERS_DIR = process.env.USERS_DIR || path.join(__dirname, "..", "users");
const USERS_FILE = path.join(USERS_DIR, "users.json");
// books/ contiene los .epub/.pdf reales, copiados a mano por el owner
// (nunca subidos desde la web) — compartidos entre todos los usuarios, igual
// que el manga no tiene contenido propio por cuenta. book_progress/ guarda
// solo el progreso de lectura por usuario, separado del contenido por el
// mismo motivo que mangas/ está separado de users/.
const BOOKS_DIR = process.env.BOOKS_DIR || path.join(__dirname, "..", "books");
const BOOK_PROGRESS_DIR = process.env.BOOK_PROGRESS_DIR || path.join(__dirname, "..", "book_progress");
// Portada elegida por un admin para cada libro (ver sección "Libros
// electrónicos" más abajo) — es un solo fichero compartido, no por usuario
// como book_progress/: todo el mundo ve la misma portada que el admin eligió.
const BOOK_COVERS_DIR = process.env.BOOK_COVERS_DIR || path.join(__dirname, "..", "book_covers");
const BOOK_COVERS_FILE = path.join(BOOK_COVERS_DIR, "covers.json");
const DEFAULT_PREFERENCES = { theme: "light", readingMode: "scroll", pageTurnMode: "swipe" };

// username termina siendo parte de un nombre de fichero (ver /register y
// readUserData/writeUserData) — solo caracteres seguros para una ruta.
const USERNAME_RE = /^[A-Za-z0-9_-]{3,32}$/;

// mangaName se usa como clave de objeto (data.finished[mangaName]) — con
// "__proto__" como valor, ese acceso devuelve Object.prototype en vez de
// undefined, y llamar a .includes()/.push() sobre eso lanza una excepción
// sin capturar dentro de un handler async, lo que tumba el proceso entero
// (ver el process.on('unhandledRejection') de arriba). Cualquier usuario
// autenticado podía tirar el backend con una sola petición a /add_finished.
const DANGEROUS_OBJECT_KEYS = new Set(["__proto__", "constructor", "prototype"]);
function isDangerousKey(key) {
  return DANGEROUS_OBJECT_KEYS.has(key);
}

// Límites generosos (muy por encima de cualquier uso real: el manhwa más
// largo del catálogo no llega a 5000 capítulos) para que una cuenta
// autenticada — aunque solo sea una invitada de baja confianza — no pueda
// hinchar sin límite su propio mangas/{username}.json.
const MAX_MANGA_NAME_LENGTH = 200;
const MAX_FAVORITES = 500;
const MAX_FINISHED_MANGAS = 500;
const MAX_CHAPTERS_PER_MANGA = 5000;
const MAX_LOCATOR_LENGTH = 500;

// Formatos de libro soportados y su Content-Type al servir el fichero.
const BOOK_FORMATS = {
  ".epub": "application/epub+zip",
  ".pdf": "application/pdf"
};

// Administradores fijos por ahora (no hay gestión de roles todavía).
const ADMIN_USERNAMES = new Set(["Joao"]);
function isAdmin(username) {
  return ADMIN_USERNAMES.has(username);
}

// Configura VAPID en tu backend (aunque aquí solo usamos la pública)
const vapidPublicKey = process.env.PUBLIC_KEY;
const vapidPrivateKey = process.env.PRIVATE_KEY;

webPush.setVapidDetails(
  'mailto:yoaojoao@dgmail.com',  // Reemplaza con tu correo
  vapidPublicKey,
  vapidPrivateKey
);

// Asegurarnos del directorio base
fs.ensureDirSync(STORAGE_DIR);
fs.ensureDirSync(NOTIFICATIONS_DIR);
fs.ensureDirSync(USERS_DIR);
fs.ensureDirSync(BOOKS_DIR);
fs.ensureDirSync(BOOK_PROGRESS_DIR);
fs.ensureDirSync(BOOK_COVERS_DIR);

// Middleware para validar el token
function authenticateToken(req, res, next) {
  const token = req.body.token || req.query.token;
  if (!token) return res.status(401).json({ error: "Token requerido" });

  // algorithms fijo explícitamente: recomendación de la propia librería
  // jsonwebtoken, para no depender solo de su inferencia automática por tipo
  // de secreto a la hora de descartar algoritmos no-HMAC.
  jwt.verify(token, SECRET_KEY, { algorithms: ["HS256"] }, async (err, payload) => {
    if (err) return res.status(403).json({ error: "Token caducado o incorrecto" });
    if (!payload || !payload.username) return res.status(403).json({ error: "Token inválido" });

    // tokenVersion permite invalidar tokens ya emitidos sin esperar a que
    // caduquen solos (hasta 24h) — se sube en /change_password y
    // /admin/reset_password, así que un token robado deja de servir en
    // cuanto la cuenta cambia de contraseña, no 24h después. Los tokens
    // firmados antes de que existiera este campo no lo llevan en el payload
    // (se tratan como versión 0), igual que las cuentas sin el campo
    // todavía en users.json — así desplegar esto no invalida de golpe
    // ninguna sesión ya activa.
    let users;
    try {
      users = await readUsers();
    } catch (readErr) {
      console.error("Error leyendo users.json en authenticateToken:", readErr);
      return res.status(500).json({ error: "Error interno del servidor" });
    }
    const account = users[payload.username];
    if (!account) return res.status(403).json({ error: "Token inválido" });
    if ((payload.tokenVersion || 0) !== (account.tokenVersion || 0)) {
      return res.status(403).json({ error: "Sesión invalidada, vuelve a iniciar sesión" });
    }

    req.user = payload;
    next();
  });
}

// Middleware para restringir endpoints a administradores (requiere authenticateToken antes)
function requireAdmin(req, res, next) {
  if (!isAdmin(req.user.username)) {
    return res.status(403).json({ error: "Requiere permisos de administrador" });
  }
  next();
}

// Helpers para el fichero users/users.json (cuentas: passwordHash + preferencias)
async function readUsers() {
  try {
    const content = await fs.readFile(USERS_FILE, "utf8");
    return JSON.parse(content);
  } catch {
    return {};
  }
}

async function writeUsers(users) {
  await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
}

// Migra automáticamente los perfiles que ya existían en mangas/*.json (creados
// bajo el antiguo modelo de contraseña global compartida) a cuentas reales con
// la contraseña global actual como contraseña por defecto. Idempotente: solo
// rellena los que todavía no tengan cuenta en users.json.
async function migrateLegacyProfiles() {
  const users = await readUsers();
  let files = [];
  try {
    files = await fs.readdir(STORAGE_DIR);
  } catch {
    return;
  }

  // LEGACY_MIGRATION_PASSWORD es un secreto propio, separado de PASSWORD
  // (que sigue siendo solo la clave de /send_notif, sin tocar buenos_dias.sh).
  // Antes ambos usos compartían la misma variable — si PASSWORD se filtraba
  // o se adivinaba por cualquiera de los dos motivos, cualquier cuenta
  // heredada que aún no se hubiera logueado (y por tanto seguía con esta
  // contraseña por defecto) quedaba accesible. Cae de vuelta a PASSWORD si
  // la nueva variable no está puesta, para no romper un despliegue existente
  // en silencio, pero avisando de que conviene fijarla aparte.
  const legacyPassword = process.env.LEGACY_MIGRATION_PASSWORD || process.env.PASSWORD;
  if (!process.env.LEGACY_MIGRATION_PASSWORD && process.env.PASSWORD) {
    console.warn("⚠️ LEGACY_MIGRATION_PASSWORD no está definida — usando PASSWORD como respaldo. Defínela por separado para no compartir el mismo secreto con /send_notif.");
  }
  let changed = false;
  const defaultPasswordHash = legacyPassword
    ? await bcrypt.hash(legacyPassword, 10)
    : null;

  for (const file of files) {
    if (!file.endsWith(".json")) continue;
    const username = path.basename(file, ".json");
    if (users[username] || !defaultPasswordHash) continue;
    users[username] = {
      passwordHash: defaultPasswordHash,
      mustChangePassword: true,
      preferences: { ...DEFAULT_PREFERENCES }
    };
    changed = true;
    console.log(`🔐 Perfil heredado migrado a cuenta: ${username} (contraseña por defecto, debe cambiarla)`);
  }

  if (changed) await writeUsers(users);
}

// Helpers para manejar el fichero JSON de cada usuario
async function readUserData(username) {
  const file = path.join(STORAGE_DIR, `${username}.json`);
  try {
    const content = await fs.readFile(file, "utf8");
    return JSON.parse(content);
  } catch {
    return { favorites: [], finished: {} };
  }
}

async function writeUserData(username, data) {
  const file = path.join(STORAGE_DIR, `${username}.json`);
  await fs.writeFile(file, JSON.stringify(data, null, 2));
}

// Helpers para book_progress/{username}.json — { [bookId]: { locator, updatedAt } }
async function readBookProgress(username) {
  const file = path.join(BOOK_PROGRESS_DIR, `${username}.json`);
  try {
    const content = await fs.readFile(file, "utf8");
    return JSON.parse(content);
  } catch {
    return {};
  }
}

async function writeBookProgress(username, data) {
  const file = path.join(BOOK_PROGRESS_DIR, `${username}.json`);
  await fs.writeFile(file, JSON.stringify(data, null, 2));
}

// Helpers para book_covers/covers.json — { [bookId]: { url, updatedAt, updatedBy } }
async function readBookCovers() {
  try {
    const content = await fs.readFile(BOOK_COVERS_FILE, "utf8");
    return JSON.parse(content);
  } catch {
    return {};
  }
}

async function writeBookCovers(covers) {
  await fs.writeFile(BOOK_COVERS_FILE, JSON.stringify(covers, null, 2));
}

// id de libro = nombre de fichero dentro de BOOKS_DIR. Igual que con
// username (ver USERNAME_RE más arriba, y el incidente documentado en
// CLAUDE.md), un id como "../users/users.json" no puede resolver fuera de
// BOOKS_DIR — se comprueba la ruta resuelta, no solo el string de entrada.
function resolveBookPath(id) {
  if (!id || typeof id !== "string") return null;
  const resolved = path.resolve(BOOKS_DIR, id);
  const base = path.resolve(BOOKS_DIR) + path.sep;
  if (!resolved.startsWith(base)) return null;
  const ext = path.extname(resolved).toLowerCase();
  if (!BOOK_FORMATS[ext]) return null;
  return resolved;
}

function titleFromFilename(filename) {
  return path.basename(filename, path.extname(filename))
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

// Carga suscripciones existentes o crea un array vacío
function loadSubscriptions() {
  try {
    const data = fs.readFileSync(SUBS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }
}

// Guarda suscripciones en el fichero
function saveSubscriptions(subs) {
  fs.writeFileSync(SUBS_FILE, JSON.stringify(subs, null, 2));
}

async function sendPushToAll(title, body) {
  const subscriptions = loadSubscriptions();
  const payload = JSON.stringify({ title, body });

  const results = await Promise.all(subscriptions.map(sub =>
    webPush.sendNotification(sub, payload)
      .then(() => ({ endpoint: sub.endpoint, ok: true }))
      .catch(err => {
        const invalid = err.statusCode === 404 || err.statusCode === 410;
        console.error(`❌ Error al enviar a ${sub.endpoint}`, err.statusCode || err);
        return { endpoint: sub.endpoint, ok: false, invalid };
      })
  ));

  const validSubs = [];
  let success = 0, failed = 0;

  for (const r of results) {
    if (r.ok) success++;
    else failed++;
    if (!r.invalid) {
      validSubs.push(subscriptions.find(s => s.endpoint === r.endpoint));
    }
  }

  if (validSubs.length !== subscriptions.length) {
    saveSubscriptions(validSubs);
  }

  return { success, failed };
}

// --- Códigos de invitación (solo un admin puede generarlos; de un solo uso y caducan) ---
const INVITE_TTL_MS = 30 * 60 * 1000;
let currentInvite = null; // { code, createdAt, used }

function inviteIsValid(invite) {
  return !!invite && !invite.used && Date.now() - invite.createdAt <= INVITE_TTL_MS;
}

app.post("/invite/current", authenticateToken, requireAdmin, (req, res) => {
  if (!inviteIsValid(currentInvite)) return res.json({ code: null });
  res.json({ code: currentInvite.code, expiresAt: currentInvite.createdAt + INVITE_TTL_MS });
});

app.post("/invite/generate", authenticateToken, requireAdmin, (req, res) => {
  currentInvite = { code: crypto.randomBytes(4).toString("hex").toUpperCase(), createdAt: Date.now(), used: false };
  res.json({ code: currentInvite.code, expiresAt: currentInvite.createdAt + INVITE_TTL_MS });
});

// --- Cuentas de usuario (usuario + contraseña propios) ---

app.post("/register", authLimiter, async (req, res) => {
  const { username, password, inviteCode } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "username y password son requeridos" });
  }
  // username acaba formando parte de una ruta de fichero (mangas/{username}.json,
  // ver readUserData/writeUserData) — sin este filtro, un username como
  // "../users/users" resuelve fuera de mangas/ y puede llegar a sobrescribir
  // users/users.json (carpeta hermana) con el JSON de favoritos/leídos,
  // destruyendo los hashes de contraseña de todas las cuentas.
  if (!USERNAME_RE.test(username)) {
    return res.status(400).json({ error: "El usuario debe tener entre 3 y 32 caracteres: letras, números, guiones o guiones bajos." });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: "La contraseña debe tener al menos 8 caracteres." });
  }
  if (!inviteCode || !inviteIsValid(currentInvite) || inviteCode !== currentInvite.code) {
    return res.status(403).json({ error: "Código de invitación inválido o caducado" });
  }

  const users = await readUsers();
  if (users[username]) {
    return res.status(409).json({ error: "Usuario ya existe" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  users[username] = {
    passwordHash,
    mustChangePassword: false,
    tokenVersion: 0,
    preferences: { ...DEFAULT_PREFERENCES }
  };
  await writeUsers(users);
  currentInvite.used = true;

  const mangaFile = path.join(STORAGE_DIR, `${username}.json`);
  if (!(await fs.pathExists(mangaFile))) {
    await fs.writeFile(mangaFile, JSON.stringify({ favorites: [], finished: {} }, null, 2));
  }

  const token = jwt.sign({ username, tokenVersion: 0 }, SECRET_KEY, { expiresIn: "24h" });
  res.json({ token, username, mustChangePassword: false, isAdmin: isAdmin(username), preferences: users[username].preferences });
});

app.post("/login", authLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "username y password son requeridos" });
  }

  const users = await readUsers();
  const account = users[username];
  if (!account || !(await bcrypt.compare(password, account.passwordHash))) {
    return res.status(403).json({ error: "Usuario o contraseña incorrectos" });
  }

  const token = jwt.sign({ username, tokenVersion: account.tokenVersion || 0 }, SECRET_KEY, { expiresIn: "24h" });
  res.json({
    token,
    username,
    mustChangePassword: !!account.mustChangePassword,
    isAdmin: isAdmin(username),
    preferences: account.preferences || DEFAULT_PREFERENCES
  });
});

app.post("/change_password", authenticateToken, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword) return res.status(400).json({ error: "newPassword es requerido" });
  if (newPassword.length < 8) return res.status(400).json({ error: "La contraseña debe tener al menos 8 caracteres." });

  const users = await readUsers();
  const account = users[req.user.username];
  if (!account) return res.status(404).json({ error: "Usuario no encontrado" });

  account.passwordHash = await bcrypt.hash(newPassword, 10);
  account.mustChangePassword = false;
  // Invalida cualquier token ya emitido para esta cuenta (ver
  // authenticateToken) — si alguien tenía un token robado, deja de servirle
  // en cuanto la contraseña cambia, no hasta que caduque solo.
  account.tokenVersion = (account.tokenVersion || 0) + 1;
  await writeUsers(users);
  res.json({ success: true });
});

// Genera una contraseña temporal legible (sin 0/O/1/l/I, que se confunden al
// leerla o copiarla a mano) para que un admin se la pueda pasar al usuario.
function generateRandomPassword(length = 12) {
  const charset = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
  let password = "";
  for (let i = 0; i < length; i++) {
    password += charset[crypto.randomInt(charset.length)];
  }
  return password;
}

// Solo un admin puede reiniciar la contraseña de otra cuenta. La nueva
// contraseña aleatoria se devuelve UNA vez en esta respuesta (no se guarda en
// claro en ningún sitio, solo su hash) para que el admin se la pase al
// usuario; mustChangePassword:true reutiliza el mismo modal de "cambia tu
// contraseña" que ya se muestra a los perfiles heredados en su primer login,
// así que el usuario la cambia por una suya en cuanto entre.
app.post("/admin/reset_password", authenticateToken, requireAdmin, async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: "username es requerido" });

  const users = await readUsers();
  const account = users[username];
  if (!account) return res.status(404).json({ error: "Usuario no encontrado" });

  const newPassword = generateRandomPassword();
  account.passwordHash = await bcrypt.hash(newPassword, 10);
  account.mustChangePassword = true;
  account.tokenVersion = (account.tokenVersion || 0) + 1; // ver /change_password
  await writeUsers(users);

  res.json({ success: true, username, newPassword });
});

app.post("/validate_token", authenticateToken, (req, res) => {
  res.json({ valid: true, username: req.user.username, isAdmin: isAdmin(req.user.username) });
});

app.post("/preferences", authenticateToken, async (req, res) => {
  const { preferences } = req.body;
  if (!preferences || typeof preferences !== "object") {
    return res.status(400).json({ error: "preferences es requerido" });
  }

  const users = await readUsers();
  const account = users[req.user.username];
  if (!account) return res.status(404).json({ error: "Usuario no encontrado" });

  account.preferences = { ...DEFAULT_PREFERENCES, ...account.preferences, ...preferences };
  await writeUsers(users);
  res.json({ success: true, preferences: account.preferences });
});

// --- Emparejamiento por QR (login en Smart TV sin escribir con el mando) ---
// Estado en memoria, efímero (se pierde al reiniciar), igual que lastChapters
// del job en background: no necesita persistir en disco.
const PAIRING_TTL_MS = 5 * 60 * 1000;
const pairings = new Map(); // pairingId -> { code, status, createdAt, username, token }

function cleanupExpiredPairings() {
  const now = Date.now();
  for (const [id, p] of pairings) {
    if (now - p.createdAt > PAIRING_TTL_MS) pairings.delete(id);
  }
}
setInterval(cleanupExpiredPairings, 60 * 1000);

app.post("/pair/create", (req, res) => {
  cleanupExpiredPairings();
  const pairingId = crypto.randomUUID();
  const code = crypto.randomBytes(4).toString("hex").toUpperCase(); // p.ej. "A1B2C3D4"
  pairings.set(pairingId, { code, status: "pending", createdAt: Date.now(), username: null, token: null });
  res.json({ pairingId, code });
});

app.get("/pair/status/:pairingId", (req, res) => {
  const pairing = pairings.get(req.params.pairingId);
  if (!pairing || Date.now() - pairing.createdAt > PAIRING_TTL_MS) {
    if (pairing) pairings.delete(req.params.pairingId);
    return res.json({ status: "expired" });
  }

  if (pairing.status === "confirmed") {
    const { token, username, mustChangePassword, isAdmin: admin, preferences } = pairing;
    pairings.delete(req.params.pairingId); // de un solo uso
    return res.json({ status: "confirmed", token, username, mustChangePassword, isAdmin: admin, preferences });
  }

  res.json({ status: "pending" });
});

app.post("/pair/confirm", authenticateToken, async (req, res) => {
  cleanupExpiredPairings();
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "code es requerido" });

  const entry = [...pairings.entries()].find(([, p]) => p.code === code && p.status === "pending");
  if (!entry) return res.status(404).json({ error: "Código inválido o caducado" });

  const users = await readUsers();
  const account = users[req.user.username];
  if (!account) return res.status(404).json({ error: "Usuario no encontrado" });

  const [, pairing] = entry;
  pairing.status = "confirmed";
  pairing.username = req.user.username;
  pairing.token = req.body.token;
  pairing.mustChangePassword = !!account.mustChangePassword;
  pairing.isAdmin = isAdmin(req.user.username);
  pairing.preferences = account.preferences || DEFAULT_PREFERENCES;
  res.json({ success: true });
});

// Proxy de imágenes
// Dominios reales desde los que jimov-api sirve imágenes de InManga
// (comprobado contra la API real, agosto 2026): miniaturas en inmanga.com,
// páginas de capítulo en intomanga.com (subdominios pack-*). Sin esta
// lista, /proxy era un proxy abierto — aceptaba cualquier URL con solo
// comprobar que era un string — así que cualquier usuario autenticado podía
// hacer que el servidor hiciera peticiones a cualquier destino (SSRF),
// incluida la propia red local donde vive este backend, y leer la
// respuesta a través del stream. Solo se permite https:// a estos dominios
// o subdominios suyos.
// Restringido también por prefijo de ruta, no solo por dominio: sin esto,
// una cuenta autenticada podía usar /proxy para pedir cualquier ruta de
// inmanga.com/intomanga.com, no solo imágenes — bajo impacto (son dominios
// de contenido legítimo) pero innecesario. /thumbnails/ e /images/ son los
// prefijos reales observados (miniaturas y páginas de capítulo respectivamente).
const ALLOWED_PROXY_RULES = [
  { host: "inmanga.com", pathPrefix: "/thumbnails/" },
  { host: "intomanga.com", pathPrefix: "/images/" }
];

function isAllowedProxyUrl(urlString) {
  let parsed;
  try {
    parsed = new URL(urlString);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:") return false;
  return ALLOWED_PROXY_RULES.some(({ host, pathPrefix }) =>
    (parsed.hostname === host || parsed.hostname.endsWith(`.${host}`)) &&
    parsed.pathname.startsWith(pathPrefix)
  );
}

// Streaming en vez de bufferizar la imagen entera en memoria antes de
// reenviarla: baja la latencia (el cliente empieza a recibir bytes antes)
// y el costo de memoria por request, que ahora importa más porque las
// descargas piden varias imágenes en paralelo (ver fetchImagesConcurrently
// en sw.js) en vez de una por una.
async function proxyImage(url, res) {
  const response = await axios.get(url, { responseType: "stream" });
  res.set("Content-Type", response.headers["content-type"]);
  response.data.on("error", err => {
    console.error("Error en el stream del proxy:", err);
    res.end();
  });
  response.data.pipe(res);
}

app.post("/proxy", authenticateToken, async (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== "string" || !isAllowedProxyUrl(url)) {
    return res.status(400).json({ error: "URL no válida" });
  }
  try {
    await proxyImage(url, res);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "No se pudo obtener la imagen" });
  }
});

// Variante GET del proxy: la usa la descarga por Background Fetch, que no
// admite requests con body ni con preflight CORS (solo GETs simples), así
// que el token viaja como query param en vez de en el body.
app.get("/proxy", authenticateToken, async (req, res) => {
  const { url } = req.query;
  if (!url || typeof url !== "string" || !isAllowedProxyUrl(url)) {
    return res.status(400).json({ error: "URL no válida" });
  }
  try {
    await proxyImage(url, res);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "No se pudo obtener la imagen" });
  }
});

// --- Libros electrónicos (EPUB/PDF) ---
// Los archivos viven en BOOKS_DIR, copiados a mano por el owner (nunca
// subidos desde la web). Se sirven directamente desde el backend, no a
// través de /proxy: son same-origin y propios, así que no hace falta la
// indirección de CORS/SSRF que sí necesitan las imágenes de InManga.

app.get("/books", authenticateToken, async (req, res) => {
  let files;
  try {
    files = await fs.readdir(BOOKS_DIR);
  } catch {
    return res.json({ success: true, books: [] });
  }

  const covers = await readBookCovers();

  const books = [];
  for (const file of files) {
    const ext = path.extname(file).toLowerCase();
    if (!BOOK_FORMATS[ext]) continue;
    const fullPath = path.join(BOOKS_DIR, file);
    try {
      const stat = await fs.stat(fullPath);
      if (!stat.isFile()) continue;
      books.push({
        id: file,
        title: titleFromFilename(file),
        format: ext.slice(1),
        sizeBytes: stat.size,
        coverUrl: covers[file]?.url || null
      });
    } catch {
      // fichero desapareció entre el readdir y el stat: se omite sin más
    }
  }

  res.json({ success: true, books });
});

app.get("/books/:id/file", authenticateToken, async (req, res) => {
  const fullPath = resolveBookPath(req.params.id);
  if (!fullPath || !(await fs.pathExists(fullPath))) {
    return res.status(404).json({ error: "Libro no encontrado" });
  }
  const ext = path.extname(fullPath).toLowerCase();
  res.set("Content-Type", BOOK_FORMATS[ext]);
  const stream = fs.createReadStream(fullPath);
  stream.on("error", err => {
    console.error("Error leyendo el libro:", err);
    res.end();
  });
  stream.pipe(res);
});

app.get("/books/progress", authenticateToken, async (req, res) => {
  const progress = await readBookProgress(req.user.username);
  res.json({ success: true, progress });
});

app.post("/books/:id/progress", authenticateToken, async (req, res) => {
  const fullPath = resolveBookPath(req.params.id);
  if (!fullPath) return res.status(400).json({ error: "id de libro no válido" });

  const { locator, percent } = req.body;
  if (typeof locator !== "string" || !locator || locator.length > MAX_LOCATOR_LENGTH) {
    return res.status(400).json({ error: "locator no válido" });
  }
  // percent es opcional (clientes antiguos, o formatos donde no se pueda
  // calcular) — cuando viene, tiene que ser un número real 0-100. Se usa en
  // la biblioteca para clasificar cada libro entre "en progreso"/"terminado"
  // sin tener que abrir el libro para saberlo.
  let normalizedPercent = null;
  if (percent !== undefined && percent !== null) {
    if (typeof percent !== "number" || !Number.isFinite(percent) || percent < 0 || percent > 100) {
      return res.status(400).json({ error: "percent no válido" });
    }
    normalizedPercent = Math.round(percent);
  }

  const username = req.user.username;
  const progress = await readBookProgress(username);
  // Si esta actualización no trae un percent (cliente antiguo, o un
  // reenvío del locator local sin recalcularlo — ver resolveStartingLocator/
  // syncPendingOfflineProgress en el frontend), no se debe pisar un percent
  // numérico ya conocido con null: eso borraría de golpe la clasificación
  // "en progreso"/"terminado" de un libro que ya se sabía en qué punto iba.
  const existing = progress[req.params.id];
  const finalPercent = normalizedPercent !== null
    ? normalizedPercent
    : (typeof existing?.percent === "number" ? existing.percent : null);
  progress[req.params.id] = { locator, percent: finalPercent, updatedAt: new Date().toISOString() };
  await writeBookProgress(username, progress);
  res.json({ success: true, progress: progress[req.params.id] });
});

// Portadas de libros elegidas a mano por un admin (no hay metadata real de
// EPUB/PDF que la app extraiga) — se buscan candidatas en Open Library (su
// API de búsqueda y su servicio de portadas son públicos, sin API key; a
// diferencia de la API de Google Books, que sin clave devuelve 429 "quota
// exceeded" — comprobado en vivo, no es una opción viable sin pedirle al
// owner que gestione una clave). El admin elige una entre los resultados —
// no todas tienen portada real, Open Library sirve un placeholder gris
// diminuto cuando no la tiene, así que se ve a simple vista en la rejilla
// de resultados cuál conviene elegir — y queda guardada para que la vean
// todos los usuarios por igual (ver GET /books).
const MAX_COVER_QUERY_LENGTH = 200;

app.post("/admin/books/:id/cover_search", authenticateToken, requireAdmin, async (req, res) => {
  if (!resolveBookPath(req.params.id)) {
    return res.status(400).json({ error: "id de libro no válido" });
  }

  const query = (typeof req.body.query === "string" && req.body.query.trim())
    ? req.body.query.trim().slice(0, MAX_COVER_QUERY_LENGTH)
    : titleFromFilename(req.params.id);

  try {
    const response = await axios.get("https://openlibrary.org/search.json", {
      params: { title: query, limit: 20 },
      timeout: 10000
    });
    const results = (response.data.docs || [])
      .filter(doc => doc.cover_i)
      .slice(0, 16)
      .map(doc => ({
        title: doc.title || null,
        authors: doc.author_name || [],
        thumbnail: `https://covers.openlibrary.org/b/id/${doc.cover_i}-M.jpg`,
        fullImage: `https://covers.openlibrary.org/b/id/${doc.cover_i}-L.jpg`
      }));
    res.json({ success: true, results });
  } catch (err) {
    console.error("Error buscando portadas:", err);
    res.status(500).json({ error: "No se pudo buscar portadas" });
  }
});

app.post("/admin/books/:id/cover", authenticateToken, requireAdmin, async (req, res) => {
  if (!resolveBookPath(req.params.id)) {
    return res.status(400).json({ error: "id de libro no válido" });
  }

  const { coverUrl } = req.body;
  // coverUrl: null quita la portada elegida (vuelve a la generada en el
  // cliente). Si no, tiene que ser una URL https:// real.
  if (coverUrl !== null && (typeof coverUrl !== "string" || !/^https:\/\//.test(coverUrl))) {
    return res.status(400).json({ error: "coverUrl no válida" });
  }

  const covers = await readBookCovers();
  if (coverUrl === null) {
    delete covers[req.params.id];
  } else {
    covers[req.params.id] = { url: coverUrl, updatedAt: new Date().toISOString(), updatedBy: req.user.username };
  }
  await writeBookCovers(covers);
  res.json({ success: true, coverUrl: coverUrl });
});

app.get('/vapidPublicKey', (req, res) => {
  res.json({ vapidPublicKey });
});

// Estado de disponibilidad de InManga, mantenido por el chequeo dedicado de
// abajo (cada 10 min) — solo lee el valor cacheado, no dispara una prueba
// nueva contra la API externa en cada carga de página.
app.get('/manga_source_status', (req, res) => {
  res.json({ available: apiAvailability.available, lastCheckedAt: apiAvailability.lastCheckedAt });
});

// Requiere sesión: antes cualquiera en internet podía mandar un endpoint
// inventado sin límite, inflando notifications/subscriptions.json y
// disparando un push real de "Nueva suscripción" a todos los usuarios reales
// cada vez, gratis y sin ninguna cuenta. La suscripción en sí sigue sin
// atarse a un usuario concreto (los pushes siguen siendo para todos, mismo
// diseño de siempre) — el token solo demuestra que quien llama tiene una
// cuenta válida, no identifica de quién es la suscripción.
app.post('/subscribe', authenticateToken, async (req, res) => {
  const { subscription } = req.body;

  // Validación de forma, no solo de que exista `endpoint`: una suscripción
  // Web Push real siempre trae también las claves de cifrado.
  if (
    !subscription ||
    typeof subscription.endpoint !== "string" ||
    !subscription.keys ||
    typeof subscription.keys.p256dh !== "string" ||
    typeof subscription.keys.auth !== "string"
  ) {
    return res.status(400).json({ error: 'Suscripción inválida' });
  }

  let subscriptions = loadSubscriptions();

  // Evitamos duplicados: comparamos por endpoint
  const exists = subscriptions.find(sub => sub.endpoint === subscription.endpoint);
  if (!exists) {
    subscriptions.push(subscription);
    saveSubscriptions(subscriptions);
    console.log('📥 Nueva suscripción añadida:', subscription.endpoint);
    await sendPushToAll("Nueva suscripción", "Un usuario se ha suscrito a las notificaciones");
  } else {
    console.log('🔄 Subscripción ya existente:', subscription.endpoint);
  }
  return res.status(201).json({ success: true });
});

// Compara en tiempo constante para no filtrar la contraseña carácter a
// carácter vía diferencias de tiempo de respuesta (crypto.timingSafeEqual
// exige buffers del mismo tamaño, así que primero se igualan longitudes).
function safeCompare(a, b) {
  const bufA = Buffer.from(String(a ?? ""));
  const bufB = Buffer.from(String(b ?? ""));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

app.post("/send_notif", authLimiter, async (req, res) => {
  const { password, title, body } = req.body;
  if (!process.env.PASSWORD || !safeCompare(password, process.env.PASSWORD)) {
    return res.status(403).json({ error: "Contraseña incorrecta" });
  }
  await sendPushToAll(title, body);
  res.json('Sended');
});

// Añadir manga a favoritos
app.post("/add_fav", authenticateToken, async (req, res) => {
  const { mangaName } = req.body;
  const username = req.user.username;
  if (!mangaName || typeof mangaName !== "string") {
    return res.status(400).json({ error: "mangaName es requerido" });
  }
  if (mangaName.length > MAX_MANGA_NAME_LENGTH) {
    return res.status(400).json({ error: "mangaName demasiado largo" });
  }
  const data = await readUserData(username);
  if (!data.favorites.includes(mangaName)) {
    if (data.favorites.length >= MAX_FAVORITES) {
      return res.status(400).json({ error: `Límite de ${MAX_FAVORITES} favoritos alcanzado` });
    }
    data.favorites.push(mangaName);
    await writeUserData(username, data);
  }
  res.json({ success: true, favorites: data.favorites });
});

// Eliminar manga de favoritos
app.post("/remove_fav", authenticateToken, async (req, res) => {
  const { mangaName } = req.body;
  const username = req.user.username;
  if (!mangaName) {
    return res.status(400).json({ error: "mangaName es requerido" });
  }
  const data = await readUserData(username);
  data.favorites = data.favorites.filter(m => m !== mangaName);
  await writeUserData(username, data);
  res.json({ success: true, favorites: data.favorites });
});

// Obtener lista de favoritos
app.post("/get_favorites", authenticateToken, async (req, res) => {
  const data = await readUserData(req.user.username);
  res.json({ success: true, favorites: data.favorites });
});

// Añadir capítulo terminado
app.post("/add_finished", authenticateToken, async (req, res) => {
  const { mangaName, chapterNumber } = req.body;
  const username = req.user.username;
  if (!mangaName || !chapterNumber) {
    return res.status(400).json({ error: "mangaName y chapterNumber son requeridos" });
  }
  if (isDangerousKey(mangaName)) {
    return res.status(400).json({ error: "mangaName no válido" });
  }
  if (typeof mangaName !== "string" || mangaName.length > MAX_MANGA_NAME_LENGTH) {
    return res.status(400).json({ error: "mangaName no válido" });
  }
  const data = await readUserData(username);
  if (!data.finished[mangaName]) {
    if (Object.keys(data.finished).length >= MAX_FINISHED_MANGAS) {
      return res.status(400).json({ error: `Límite de ${MAX_FINISHED_MANGAS} mangas con progreso alcanzado` });
    }
    data.finished[mangaName] = [];
  }
  const chStr = chapterNumber.toString();
  if (!data.finished[mangaName].includes(chStr)) {
    if (data.finished[mangaName].length >= MAX_CHAPTERS_PER_MANGA) {
      return res.status(400).json({ error: `Límite de ${MAX_CHAPTERS_PER_MANGA} capítulos alcanzado` });
    }
    data.finished[mangaName].push(chStr);
    await writeUserData(username, data);
  }
  res.json({ success: true, finishedChapters: data.finished[mangaName] });
});

// Obtener capítulos terminados de un manga
app.post("/get_finished", authenticateToken, async (req, res) => {
  const { mangaName } = req.body;
  const username = req.user.username;
  if (!mangaName) {
    return res.status(400).json({ error: "mangaName es requerido" });
  }
  if (isDangerousKey(mangaName)) {
    return res.status(400).json({ error: "mangaName no válido" });
  }
  const data = await readUserData(username);
  const chapters = data.finished[mangaName] || [];
  res.json({ success: true, mangaName, finishedChapters: chapters });
});

// Estado de disponibilidad de InManga, mutado ÚNICAMENTE por
// checkApiAvailability() (chequeo dedicado cada 10 min, más abajo). El resto
// del código (job de favoritos, endpoint /manga_source_status) solo lo lee.
let apiAvailability = { available: true, lastCheckedAt: 0 };

async function checkApiAvailability() {
  let isUp;
  try {
    const response = await axios.get(`https://jimov-api.vercel.app/manga/inmanga/filter?search=Dandadan&type=0`);
    isUp = !!(response.data && response.data.results[0].title !== '');
  } catch (err) {
    isUp = false;
  }

  if (isUp && !apiAvailability.available) {
    apiAvailability.available = true;
    await sendPushToAll("InManga vuelve a estar disponible", "La página InManga está disponible. Ya puedes volver a leer mangas!! :)");
  } else if (!isUp && apiAvailability.available) {
    apiAvailability.available = false;
    await sendPushToAll("InManga no disponible", "La página InManga no está disponible temporalmente. No se podrán obtener los capítulos de los mangas.");
  }
  apiAvailability.lastCheckedAt = Date.now();
}

function startApiAvailabilityChecker() {
  const INTERVAL = 10 * 60 * 1000; // cada 10 minutos

  async function tick() {
    try {
      await checkApiAvailability();
    } catch (err) {
      console.error('Error comprobando disponibilidad de InManga:', err);
    } finally {
      setTimeout(tick, INTERVAL);
    }
  }

  // primera comprobación inmediata, para que /manga_source_status y el job
  // de favoritos arranquen con un estado real desde el primer momento
  tick();
}

async function startBackgroundTask() {
  const INTERVAL = 60 * 1000; // por ejemplo, cada 1 minuto
  let lastChapters = {
    "mangas": {}
  };

  async function job() {
    try {
      console.log('🕒 Tarea en background iniciada');
      if (apiAvailability.available) {
        const allFavorites = await getAllFavorites();
        await getLatestChapters(allFavorites, lastChapters)
        console.log(lastChapters);
      } else {
        console.log('InManga no disponible, se omite la comprobación de nuevos capítulos');
      }
    } catch (err) {
      console.error('Error en tarea en background:', err);
    } finally {
      // programa siguiente ejecución
      setTimeout(job, INTERVAL);
    }
  }

  // inicia la primera ejecución tras el delay
  setTimeout(job, INTERVAL);
}

migrateLegacyProfiles()
  .then(() => {
    startBackgroundTask();
    startApiAvailabilityChecker();
  })
  .catch(err => {
    console.error('Error migrando perfiles heredados:', err);
    startBackgroundTask();
    startApiAvailabilityChecker();
  });

// Manejador de errores genérico — tiene que ir después de todas las rutas.
// Sin esto, Express usa su manejador por defecto, que devuelve una traza de
// pila completa (rutas absolutas del servidor incluidas, ver el rechazo de
// CORS de arriba) a cualquiera que la dispare, sin importar si es un fallo
// de CORS, un JSON mal formado en el body, o cualquier otro error.
app.use((err, req, res, next) => {
  if (err && err.message === "Origen no permitido por CORS") {
    return res.status(403).json({ error: "Origen no permitido" });
  }
  console.error("Error no controlado:", err);
  res.status(500).json({ error: "Error interno del servidor" });
});

// Iniciar el servidor
app.listen(PORT, () => {
  console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
});

//Aqui crea una funcion que obtenga los mangas favoritos de todos los usuarios en una lista sin repetidos
async function getAllFavorites() {
  const files = await fs.readdir(STORAGE_DIR);
  const favoritesSet = new Set();

  for (const file of files) {
    if (file.endsWith(".json")) {
      const data = await readUserData(path.basename(file, ".json"));
      data.favorites.forEach(manga => favoritesSet.add(manga));
    }
  }

  return Array.from(favoritesSet);
}

//Aqui crea una funcion que recibiendo una lista de nombres de mangas, obtenga el ultimo capitulo publicado de cada uno
// Nota: la detección de caída/recuperación de InManga vive por completo en
// checkApiAvailability() (chequeo dedicado cada 10 min); esta función solo
// se llama cuando apiAvailability.available === true (ver job() arriba), así
// que no necesita volver a comprobar disponibilidad ni notificarla.
async function getLatestChapters(mangaNames, lastChapters) {
  for (const manga of mangaNames) {
    try {
      const response = await axios.get(`https://jimov-api.vercel.app/manga/inmanga/filter?search=${encodeURIComponent(manga)}&type=0`);
      if (response.data && response.data.results[0].title !== '') {
        //Quedarse con el resultado cuya propiedad title sea igual a manga
        const foundManga = response.data.results.find(m => m.title === manga);
        const mangaInfo = await axios.get(`https://jimov-api.vercel.app${foundManga.url}`);
        //Obtener el capitulo mas reciente del manga en mangaInfo.data.chapters con la propiedad number mas alta
        const latestChapter = mangaInfo.data.chapters.reduce((max, chapter) => {
          return chapter.number > max.number ? chapter : max;
        }, mangaInfo.data.chapters[0]);
        //Si no existe el manga en la lista de clave valor lastChapters.mangas({}), lo añadimos
        if (!lastChapters.mangas[manga]) {
          lastChapters.mangas[manga] = [latestChapter.number];
        } else {
          if (lastChapters.mangas[manga] < latestChapter.number) {
            lastChapters.mangas[manga] = [latestChapter.number];
            await sendPushToAll(`Nuevo Capitulo de ${manga}`, `Ya esta disponible el capítulo ${latestChapter.number} del manga ${manga}`);
          }
        }
      }
    } catch (err) {
    }
  }
  return lastChapters;
}
