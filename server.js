const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const fs = require("fs-extra");
const path = require("path");
const cors = require("cors");
const axios = require('axios');

require("dotenv").config();

const app = express();

// Habilitar CORS para permitir solicitudes de cualquier origen
app.use(cors());
app.use(bodyParser.json());

// Configuración
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY;
const STORAGE_DIR = "./mangas";

// Crear el directorio base si no existe
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

// Endpoint para el proxy
app.post('/proxy', authenticateToken, async (req, res) => {
    const { token, url } = req.body;
    // Validar la URL
    if (!url || typeof url !== 'string') {
        return res.status(400).json({ error: 'URL no válida' });
    }

    try {
        // Hacer la solicitud a la URL proporcionada
        const response = await axios.get(url, { responseType: 'arraybuffer' });

        // Retornar el contenido de la imagen con el tipo adecuado
        res.set('Content-Type', response.headers['content-type']);
        res.send(response.data);
    } catch (error) {
        console.error('Error al obtener la imagen:', error.message);
        res.status(500).json({ error: 'No se pudo obtener la imagen' });
    }
});

// Endpoint para obtener un token
app.post("/get_token", (req, res) => {
    const { password } = req.body;
    if (password !== process.env.PASSWORD) {
        return res.status(403).json({ error: "Contraseña incorrecta" });
    }

    const token = jwt.sign({ user: "authorized" }, SECRET_KEY, { expiresIn: "24h" });
    res.json({ token });
});

// Endpoint para validar token
app.post("/validate_token", authenticateToken, (req, res) => {
    return res.status(200).json({ valid: "Token válido" });
});

// Endpoint para añadir un manga a favoritos
app.post("/add_fav", authenticateToken, async (req, res) => {
    const { mangaName } = req.body;
    if (!mangaName) {
        return res.status(400).json({ error: "Nombre del manga es requerido" });
    }

    const favoritesFile = path.join(STORAGE_DIR, "favorites.txt");

    try {
        // Leer favoritos actuales
        const favorites = (await fs.readFile(favoritesFile, "utf-8").catch(() => "")).split("\n").filter(Boolean);
        if (!favorites.includes(mangaName)) {
            favorites.push(mangaName);
            await fs.writeFile(favoritesFile, favorites.join("\n"));
        }
        res.json({ success: true, message: `Manga "${mangaName}" añadido a favoritos.` });
    } catch (err) {
        res.status(500).json({ error: "Error al añadir el manga a favoritos" });
    }
});

// Endpoint para eliminar un manga de favoritos
app.post("/remove_fav", authenticateToken, async (req, res) => {
    const { mangaName } = req.body;
    if (!mangaName) {
        return res.status(400).json({ error: "Nombre del manga es requerido" });
    }

    const favoritesFile = path.join(STORAGE_DIR, "favorites.txt");

    try {
        // Leer favoritos actuales
        const favorites = (await fs.readFile(favoritesFile, "utf-8").catch(() => "")).split("\n").filter(Boolean);
        const updatedFavorites = favorites.filter(name => name !== mangaName);

        await fs.writeFile(favoritesFile, updatedFavorites.join("\n"));
        res.json({ success: true, message: `Manga "${mangaName}" eliminado de favoritos.` });
    } catch (err) {
        res.status(500).json({ error: "Error al eliminar el manga de favoritos" });
    }
});

// Endpoint para obtener la lista de mangas favoritos
app.post("/get_favorites", authenticateToken, async (req, res) => {
    const favoritesFile = path.join(STORAGE_DIR, "favorites.txt");

    try {
        const favorites = (await fs.readFile(favoritesFile, "utf-8").catch(() => "")).split("\n").filter(Boolean);
        res.json({ success: true, favorites });
    } catch (err) {
        res.status(500).json({ error: "Error al obtener los mangas favoritos" });
    }
});

// Endpoint para añadir capítulos terminados
app.post("/add_finished", authenticateToken, async (req, res) => {
    const { mangaName, chapterNumber } = req.body;
    if (!mangaName || !chapterNumber) {
        return res.status(400).json({ error: "Manga y capítulo son requeridos" });
    }

    const mangaPath = path.join(STORAGE_DIR, mangaName);
    const listFile = path.join(mangaPath, "list.txt");

    try {
        await fs.ensureDir(mangaPath);
        const chapters = (await fs.readFile(listFile, "utf-8").catch(() => "")).split("\n").filter(Boolean);
        if (!chapters.includes(chapterNumber.toString())) {
            chapters.push(chapterNumber.toString());
            await fs.writeFile(listFile, chapters.join("\n"));
        }
        res.json({ success: true, message: `Capítulo ${chapterNumber} añadido a ${mangaName}` });
    } catch (err) {
        res.status(500).json({ error: "Error al guardar el capítulo" });
    }
});

// Endpoint para obtener capítulos terminados
app.post("/get_finished", authenticateToken, async (req, res) => {
    const { mangaName } = req.body;
    if (!mangaName) {
        return res.status(400).json({ error: "Nombre del manga es requerido" });
    }

    const listFile = path.join(STORAGE_DIR, mangaName, "list.txt");

    try {
        const chapters = (await fs.readFile(listFile, "utf-8").catch(() => "")).split("\n").filter(Boolean);
        res.json({ mangaName, finishedChapters: chapters });
    } catch (err) {
        res.status(500).json({ error: "Error al leer los capítulos terminados" });
    }
});

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
});
