const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const fs = require("fs-extra");
const path = require("path");
const cors = require("cors");
const axios = require("axios");
const webPush = require('web-push');
require("dotenv").config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY;
const STORAGE_DIR = "./mangas";
const SUBS_FILE = path.join('./notifications/subscriptions.json');

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
fs.ensureDirSync('./notifications');

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

app.get('/vapidPublicKey', (req, res) => {
  res.json({ vapidPublicKey });
});

app.post('/subscribe', async (req, res) => {
  const subscription = req.body;

  // Validación básica
  if (!subscription || !subscription.endpoint) {
    return res.status(400).json({ error: 'Subscripción inválida: falta endpoint' });
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

app.post("/send_notif", async (req, res) => {
  const { password, title, body } = req.body;
  if (password !== process.env.PASSWORD) {
    return res.status(403).json({ error: "Contraseña incorrecta" });
  }
  await sendPushToAll(title, body);
  const token = jwt.sign({ user: "authorized" }, SECRET_KEY, { expiresIn: "24h" });
  res.json('Sended');
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

async function startBackgroundTask() {
  const INTERVAL = 60 * 1000; // por ejemplo, cada 1 minuto
  let lastChapters = {
    "mangas": {},
    "inMangaWorks": true
  };

  async function job() {
    try {
      console.log('🕒 Tarea en background iniciada');
      // Ejemplo: enviar un recordatorio o verificar algo
      // console.log('Obteniendo mangas favoritos de todos los usuarios...');
      const allFavorites = await getAllFavorites();
      // console.log(allFavorites)
      await getLatestChapters(allFavorites, lastChapters)
      console.log(lastChapters);
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

startBackgroundTask();
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
async function getLatestChapters(mangaNames, lastChapters) {

  if (lastChapters.inMangaWorks === false) {
    const response = await axios.get(`https://jimov-api.vercel.app/manga/inmanga/filter?search=Dandadan&type=0`);
    if (response.data && response.data.results[0].title !== '') {
      lastChapters.inMangaWorks = true;
      //notificar a todos los usuarios que InManga no esta disponible
      await sendPushToAll("InManga vuelve a estar disponible", "La página InManga está disponible. Ya puedes volver a leer mangas!! :)");
    }
  } else {
    //Haz una peticion a un api y si no devuelve nada la pagina esta caida(no hace falta comprobar lo que devuelve solo si devuelve algo)
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
          // console.log(latestChapter)
          //Si no existe el manga en la lista de clave valor lastChapters.mangas({}), lo añadimos
          if (!lastChapters.mangas[manga]) {
            lastChapters.mangas[manga] = [latestChapter.number];
          } else {
            if (lastChapters.mangas[manga] < latestChapter.number) {
              // console.log('Si envia')
              lastChapters.mangas[manga] = [latestChapter.number];
              await sendPushToAll(`Nuevo Capitulo de ${manga}`, `Ya esta disponible el capítulo ${latestChapter.number} del manga ${manga}`);
            }/*else{
              console.log(lastChapters.mangas[manga][0])
              console.log(`No hay nuevo capítulo de ${manga}, el último es ${latestChapter.number}`);
            }*/
          }
          // console.log(lastChapters)
        } else {
          lastChapters.inMangaWorks = false;
          //notificar a todos los usuarios que InManga no esta disponible
          await sendPushToAll("InManga no disponible", "La página InManga no está disponible temporalmente. No se podrán obtener los capítulos de los mangas.");
        }
      } catch (err) {
      }
    }
  }
  return lastChapters;

}
