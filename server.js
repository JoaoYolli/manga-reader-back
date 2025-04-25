const express   = require("express");
const bodyParser= require("body-parser");
const jwt = require("jsonwebtoken");
const fs        = require("fs-extra");
const path      = require("path");
const cors      = require("cors");
const axios     = require("axios");
require("dotenv").config();

const app       = express();
app.use(cors());
app.use(bodyParser.json());

const PORT            = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY;
const STORAGE_DIR     = "./mangas";

// Asegurarnos del directorio base
fs.ensureDirSync(STORAGE_DIR);

// Middleware para validar el token
function authenticateToken(req, res, next) {
    const { token } = req.body;
    if (!token) return res.status(401).json({ error: "Token requerido" });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Token caducado o incorrecto" });
        req.user = user;
        next();
    });
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

// Endpoint para obtener el token (se devuelve siempre el mismo)
app.post("/get_token", (req, res) => {
    const { password } = req.body;
    if (password !== process.env.PASSWORD) {
        return res.status(403).json({ error: "Contraseña incorrecta" });
    }

    const token = jwt.sign({ user: "authorized" }, SECRET_KEY, { expiresIn: "24h" });
    res.json({ token });
});

// Proxy de imágenes (sin cambios relevantes)
app.post("/proxy", authenticateToken, async (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "URL no válida" });
  }
  try {
    const response = await axios.get(url, { responseType: "arraybuffer" });
    res.set("Content-Type", response.headers["content-type"]);
    res.send(response.data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "No se pudo obtener la imagen" });
  }
});

app.post("/create_user", authenticateToken, async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "username requerido" });
    const file = path.join(STORAGE_DIR, `${username}.json`);
    if (await fs.pathExists(file)) {
      return res.status(409).json({ error: "Usuario ya existe" });
    }
    await fs.writeFile(file, JSON.stringify({ favorites: [], finished: {} }, null, 2));
    res.json({ success: true });
  });
  

app.post("/list_users", authenticateToken, (req, res) => {
    const files = fs.readdirSync(STORAGE_DIR);
    // Filtrar solo .json y quitar extensión
    const users = files
      .filter(f => f.endsWith(".json"))
      .map(f => path.basename(f, ".json"));
    res.json({ users });
  });
  

// Añadir manga a favoritos
app.post("/add_fav", authenticateToken, async (req, res) => {
  const { username, mangaName } = req.body;
  if (!username || !mangaName) {
    return res.status(400).json({ error: "username y mangaName son requeridos" });
  }
  const data = await readUserData(username);
  if (!data.favorites.includes(mangaName)) {
    data.favorites.push(mangaName);
    await writeUserData(username, data);
  }
  res.json({ success: true, favorites: data.favorites });
});

// Eliminar manga de favoritos
app.post("/remove_fav", authenticateToken, async (req, res) => {
  const { username, mangaName } = req.body;
  if (!username || !mangaName) {
    return res.status(400).json({ error: "username y mangaName son requeridos" });
  }
  const data = await readUserData(username);
  data.favorites = data.favorites.filter(m => m !== mangaName);
  await writeUserData(username, data);
  res.json({ success: true, favorites: data.favorites });
});

// Obtener lista de favoritos
app.post("/get_favorites", authenticateToken, async (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ error: "username es requerido" });
  }
  const data = await readUserData(username);
  res.json({ success: true, favorites: data.favorites });
});

// Añadir capítulo terminado
app.post("/add_finished", authenticateToken, async (req, res) => {
  const { username, mangaName, chapterNumber } = req.body;
  if (!username || !mangaName || !chapterNumber) {
    return res.status(400).json({ error: "username, mangaName y chapterNumber son requeridos" });
  }
  const data = await readUserData(username);
  if (!data.finished[mangaName]) data.finished[mangaName] = [];
  const chStr = chapterNumber.toString();
  if (!data.finished[mangaName].includes(chStr)) {
    data.finished[mangaName].push(chStr);
    await writeUserData(username, data);
  }
  res.json({ success: true, finishedChapters: data.finished[mangaName] });
});

// Obtener capítulos terminados de un manga
app.post("/get_finished", authenticateToken, async (req, res) => {
  const { username, mangaName } = req.body;
  if (!username || !mangaName) {
    return res.status(400).json({ error: "username y mangaName son requeridos" });
  }
  const data = await readUserData(username);
  const chapters = data.finished[mangaName] || [];
  res.json({ success: true, mangaName, finishedChapters: chapters });
});

app.listen(PORT, () => {
  console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
});
