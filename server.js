// server.js
require("dotenv").config();
const express = require("express");
const net = require("net");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET || "secret";
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

async function initDB() {
    console.log("Iniciando configuração do banco de dados...");
    await pool.query("create table if not exists gps_users(id serial primary key, username text unique, password text, created_at timestamp default now())");
    await pool.query("create table if not exists gps_devices(id serial primary key, user_id int, name text, imei text unique, created_at timestamp default now())");
    await pool.query(`
        create table if not exists gps_positions(
            id serial primary key,
            device_id text,
            frame_type int,
            raw_data text,
            lat double precision,
            lon double precision,
            time_stamp timestamp,
            created_at timestamp default now()
        )
    `);
    console.log("Banco de dados configurado com sucesso.");
}
initDB();

// ----------------------------------------------------------
// ROTAS DE USUÁRIOS (REGISTRO / LOGIN)
// ----------------------------------------------------------

app.post("/register", async (req, res) => {
    console.log("REQUISIÇÃO POST /register recebida. Dados:", req.body);
    try {
        let { username, password } = req.body;
        let userExists = await pool.query("select * from gps_users where username=$1", [username]);
        if (userExists.rowCount > 0) {
            console.log(`Usuário já existe: ${username}`);
            return res.status(400).json({ error: "Usuário já existe" });
        }
        let hash = await bcrypt.hash(password, 10);
        await pool.query("insert into gps_users(username, password) values($1, $2)", [username, hash]);
        console.log(`Usuário cadastrado com sucesso: ${username}`);
        res.json({ success: true });
    } catch (e) {
        console.log("Erro ao registrar usuário:", e.message);
        res.status(500).json({ error: e.message });
    }
});

app.post("/login", async (req, res) => {
    console.log("REQUISIÇÃO POST /login recebida. Dados:", req.body);
    try {
        let { username, password } = req.body;
        let userRow = await pool.query("select * from gps_users where username=$1", [username]);
        if (userRow.rowCount === 0) {
            console.log(`Falha no login - Usuário não encontrado: ${username}`);
            return res.status(400).json({ error: "Credenciais inválidas" });
        }
        let user = userRow.rows[0];
        let match = await bcrypt.compare(password, user.password);
        if (!match) {
            console.log(`Falha no login - Senha inválida para o usuário: ${username}`);
            return res.status(400).json({ error: "Credenciais inválidas" });
        }
        let token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "1d" });
        console.log(`Usuário logado com sucesso: ${username}`);
        res.json({ token });
    } catch (e) {
        console.log("Erro ao realizar login:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// ----------------------------------------------------------
// MIDDLEWARE DE AUTENTICAÇÃO
// ----------------------------------------------------------

function auth(req, res, next) {
    console.log("Middleware de autenticação acionado.");
    try {
        let header = req.headers.authorization;
        if (!header) {
            console.log("Nenhum token fornecido no cabeçalho Authorization.");
            return res.status(401).json({ error: "Sem token" });
        }
        let token = header.split(" ")[1];
        let decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (e) {
        console.log("Token inválido ou inexistente.");
        res.status(401).json({ error: "Token inválido" });
    }
}

// ----------------------------------------------------------
// ROTAS DIVERSAS
// ----------------------------------------------------------

app.get("/profile", auth, (req, res) => {
    console.log("GET /profile - Usuário autenticado:", req.user);
    res.json({ id: req.user.id, username: req.user.username });
});

app.get("/", (req, res) => {
    console.log("GET / (Página inicial /public/index.html)");
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ----------------------------------------------------------
// ROTAS DE DISPOSITIVOS
// ----------------------------------------------------------

app.post("/api/devices", auth, async (req, res) => {
    console.log("REQUISIÇÃO POST /api/devices recebida. Dados:", req.body, "Usuário autenticado:", req.user);
    try {
        let { name, imei } = req.body;
        let check = await pool.query("select * from gps_devices where imei=$1", [imei]);
        if (check.rowCount > 0) {
            console.log("Falha ao inserir dispositivo - IMEI já existe:", imei);
            return res.status(400).json({ error: "Este IMEI já está cadastrado" });
        }
        await pool.query("insert into gps_devices(user_id, name, imei) values($1, $2, $3)", [req.user.id, name, imei]);
        console.log(`Dispositivo inserido com sucesso: nome='${name}', IMEI='${imei}'`);
        res.json({ success: true });
    } catch (e) {
        console.log("Erro ao inserir dispositivo:", e.message);
        res.status(500).json({ error: e.message });
    }
});

app.get("/api/devices", auth, async (req, res) => {
    console.log("GET /api/devices - Usuário:", req.user);
    try {
        let result = await pool.query("select * from gps_devices where user_id=$1 order by created_at desc", [req.user.id]);
        console.log(`Dispositivos retornados para o usuário ${req.user.id}: ${result.rowCount}`);
        res.json(result.rows);
    } catch (e) {
        console.log("Erro ao buscar dispositivos:", e.message);
        res.status(500).json({ error: e.message });
    }
});

// ----------------------------------------------------------
// ROTAS DE POSIÇÃO / LOCALIZAÇÃO
// ----------------------------------------------------------

app.get("/api/positions/last", auth, async (req, res) => {
    console.log("GET /api/positions/last - Query params:", req.query);
    let imei = req.query.imei;
    if (!imei) return res.json({ error: "Nenhum IMEI fornecido" });
    try {
        let result = await pool.query(`
            select * from gps_positions 
            where device_id=$1 and lat is not null and lon is not null 
            order by time_stamp desc limit 1
        `, [imei]);
        if (result.rowCount === 0) {
            console.log(`Nenhuma posição encontrada para IMEI=${imei}`);
            return res.json({});
        }
        let row = result.rows[0];
        console.log(`Última posição do IMEI=${imei}: lat=${row.lat}, lon=${row.lon}, time=${row.time_stamp}`);
        res.json({
            lat: row.lat,
            lon: row.lon,
            time: row.time_stamp
        });
    } catch (e) {
        console.log("Erro em /api/positions/last:", e.message);
        res.json({ error: e.message });
    }
});

app.get("/api/positions/live", auth, async (req, res) => {
    console.log("GET /api/positions/live - Listar últimas posições de cada dispositivo.");
    try {
        let result = await pool.query(`
            select device_id as imei, lat, lon 
            from (
                select device_id, lat, lon, 
                row_number() over (partition by device_id order by time_stamp desc) as rn 
                from gps_positions 
                where lat is not null and lon is not null
            ) t 
            where rn=1
        `);
        console.log(`Posições ao vivo retornadas: ${result.rowCount}`);
        res.json(result.rows);
    } catch (e) {
        console.log("Erro em /api/positions/live:", e.message);
        res.json({ error: e.message });
    }
});

// ----------------------------------------------------------
// INICIALIZAÇÃO DO SERVIDOR HTTP
// ----------------------------------------------------------

app.listen(4000, () => {
    console.log("Servidor HTTP rodando na porta 4000");
});

// ----------------------------------------------------------
// FUNÇÕES DE SUPORTE PARA O PROTOCOLO GT06
// ----------------------------------------------------------

function crc16X25(buf) {
    let crc = 0xffff;
    for (let i = 0; i < buf.length; i++) {
        crc ^= buf[i] & 0xff;
        for (let j = 0; j < 8; j++) {
            if ((crc & 1) !== 0) {
                crc = (crc >>> 1) ^ 0x8408;
            } else {
                crc = crc >>> 1;
            }
        }
    }
    return (~crc) & 0xffff;
}

function parseImeiHex(hex) {
    if (hex.length < 14) return null;
    return hex.substring(1);
}

function encodeCommand(gt06Password, content, language) {
    console.log("[GT06] encodeCommand - Senha:", gt06Password, "Conteúdo:", content, "Idioma:", language);
    let c = Buffer.from(content, "ascii");
    let bodyLength = 1 + 1 + 4 + c.length + 2 + 2 + (language ? 2 : 0);
    let packet = Buffer.alloc(bodyLength + 4);
    packet[0] = 0x78;
    packet[1] = 0x78;
    packet[2] = bodyLength;
    packet[3] = 0x80;
    packet[4] = c.length + 4;
    packet.writeUInt32BE(0, 5);
    c.copy(packet, 9);
    let idx = 9 + c.length;
    if (language) {
        packet.writeUInt16BE(2, idx);
        idx += 2;
    }
    packet.writeUInt16BE(0, idx);
    let crc = crc16X25(packet.subarray(2, bodyLength + 2));
    packet.writeUInt16BE(crc, idx + 2);
    packet[bodyLength + 2 + 2] = 0x0d;
    packet[bodyLength + 2 + 3] = 0x0a;
    console.log("[GT06] Pacote de comando codificado:", packet);
    return packet;
}

function decodeFrame(buffer) {
    console.log("[GT06] decodeFrame - Recebendo pacote bruto:", buffer);
    if (buffer.length < 5) return null;
    let start = (buffer[0] === 0x78 && buffer[1] === 0x78) ? 2 : ((buffer[0] === 0x79 && buffer[1] === 0x79) ? 4 : 0);
    if (!start) {
        console.log("[GT06] Início de pacote inválido:", buffer[0], buffer[1]);
        return null;
    }
    let length;
    if (start === 2) {
        if (buffer.length < 3) return null;
        length = buffer[2];
        if (buffer.length < length + 4) return null;
    } else {
        if (buffer.length < 4) return null;
        length = buffer.readUInt16BE(2);
        if (buffer.length < length + 6) return null;
    }
    let end = start + length;
    if (buffer[end] !== 0x0d || buffer[end + 1] !== 0x0a) {
        console.log("[GT06] Falha - não encontrou 0x0d0a no final do pacote");
        return null;
    }
    let frame = buffer.subarray(0, end + (start === 2 ? 4 : 6));
    let leftover = buffer.subarray(end + (start === 2 ? 4 : 6));
    let dataForCrc = frame.subarray(start === 2 ? 2 : 2, frame.length - 4);
    let readCrc = frame.readUInt16BE(frame.length - 4);
    let calc = crc16X25(dataForCrc);
    if (calc !== readCrc) {
        console.log("[GT06] Erro de CRC - calculado:", calc.toString(16), "lido:", readCrc.toString(16));
        return { frame: null, leftover };
    }
    console.log("[GT06] Pacote decodificado com sucesso:", frame);
    return { frame, leftover };
}

function respond(socket, frame, type, content, extended) {
    console.log(`[GT06] respond - Tipo:${type}, Estendido:${extended}, Conteúdo:`, content);
    if (!socket.destroyed) {
        let head = extended ? 0x7979 : 0x7878;
        let length = extended
            ? (2 + 1 + (content ? content.length : 0) + 2 + 2)
            : (1 + (content ? content.length : 0) + 2 + 2);
        let answer = Buffer.alloc(extended ? length + 4 : length + 4);
        answer[0] = head >> 8;
        answer[1] = head & 0xff;
        if (extended) {
            answer.writeUInt16BE(length, 2);
            answer[4] = type;
            if (content && content.length > 0) {
                content.copy(answer, 5);
            }
            let i = content ? 5 + content.length : 5;
            let msgIndex = frame.readUInt16BE(frame.length - 4);
            answer.writeUInt16BE(msgIndex, i);
            let c = crc16X25(answer.subarray(2, i + 2));
            answer.writeUInt16BE(c, i + 2);
            answer[i + 4] = 0x0d;
            answer[i + 5] = 0x0a;
        } else {
            answer[2] = length;
            answer[3] = type;
            if (content && content.length > 0) {
                content.copy(answer, 4);
            }
            let i = content ? 4 + content.length : 4;
            let msgIndex = frame.readUInt16BE(frame.length - 4);
            answer.writeUInt16BE(msgIndex, i);
            let c = crc16X25(answer.subarray(2, i + 2));
            answer.writeUInt16BE(c, i + 2);
            answer[i + 4] = 0x0d;
            answer[i + 5] = 0x0a;
        }
        console.log("[GT06] Enviando resposta ao dispositivo:", answer);
        socket.write(answer);
    }
}

function decodeGps(content) {
    console.log("[GT06] decodeGps - Conteúdo bruto:", content);
    if (content.length < 12) return null;
    let y = content[0];
    let m = content[1];
    let d = content[2];
    let hh = content[3];
    let mm = content[4];
    let ss = content[5];
    let dateStr = `20${y.toString().padStart(2, '0')}-${m.toString().padStart(2, '0')}-${d.toString().padStart(2, '0')} ${hh.toString().padStart(2, '0')}:${mm.toString().padStart(2, '0')}:${ss.toString().padStart(2, '0')}`;
    let latRaw = content.readUInt32BE(6) / (60 * 30000);
    let lonRaw = content.readUInt32BE(10) / (60 * 30000);
    let lat = latRaw;
    let lon = lonRaw;
    console.log(`[GT06] GPS decodificado: Lat=${lat}, Lon=${lon}, Data/Hora=${dateStr}`);
    return { lat, lon, time: dateStr };
}

// ----------------------------------------------------------
// LÓGICA DE DECODIFICAÇÃO DO GT06
// ----------------------------------------------------------

let deviceSessions = {};
let partialData = new WeakMap();

async function insertData(deviceId, frameType, rawData, lat, lon, time_stamp) {
    console.log(`[GT06] Salvando dados: IMEI=${deviceId}, frameType=${frameType}, lat=${lat}, lon=${lon}, time=${time_stamp}`);
    await pool.query(`
        insert into gps_positions(device_id, frame_type, raw_data, lat, lon, time_stamp)
        values($1, $2, $3, $4, $5, $6)
    `, [
        deviceId,
        frameType,
        rawData,
        lat,
        lon,
        time_stamp
    ]);
}

function decodeGt06(socket, frame) {
    console.log("[GT06] decodeGt06 chamado para processar frame.");
    let start = (frame[0] === 0x78 && frame[1] === 0x78) ? 2 : 4;
    let type = frame[start];
    let content = frame.subarray(start + 1, frame.length - 4);
    if (type === 0x01) {
        let imeiHex = content.subarray(0, 8).toString("hex");
        let imei = parseImeiHex(imeiHex);
        console.log(`[GT06] Pacote de Login. IMEI HEX=${imeiHex}, IMEI parseado=${imei}`);
        if (!imei) return;
        deviceSessions[socket.id] = imei;
        respond(socket, frame, type, Buffer.alloc(0), false);
        console.log(`[GT06] Inserindo pacote de login no banco. IMEI=${imei}`);
        insertData(imei, type, frame.toString("hex"), null, null, new Date());
    } else if (type === 0x10) {
        let imei = deviceSessions[socket.id] || "";
        console.log(`[GT06] Pacote de GPS. IMEI=${imei}`);
        let gps = decodeGps(content);
        if (gps) {
            respond(socket, frame, type, Buffer.alloc(0), false);
            console.log(`[GT06] Salvando posição GPS: IMEI=${imei}, Lat=${gps.lat}, Lon=${gps.lon}, Hora=${gps.time}`);
            insertData(imei, type, frame.toString("hex"), gps.lat, gps.lon, gps.time);
        } else {
            respond(socket, frame, type, Buffer.alloc(0), false);
            console.log("[GT06] Dados GPS inválidos, armazenando somente o rawData.");
            insertData(imei, type, frame.toString("hex"), null, null, new Date());
        }
    } else {
        console.log(`[GT06] Pacote de outro tipo. type=${type}`);
        respond(socket, frame, type, Buffer.alloc(0), false);
        let imei = deviceSessions[socket.id] || "";
        console.log(`[GT06] Salvando pacote não-GPS. IMEI=${imei}`);
        insertData(imei, type, frame.toString("hex"), null, null, new Date());
    }
}

// ----------------------------------------------------------
// SERVIDOR TCP PARA O PROTOCOLO GT06
// ----------------------------------------------------------

let server = net.createServer(socket => {
    socket.id = `${socket.remoteAddress}:${socket.remotePort}:${Date.now()}`;
    console.log(`[GT06] Nova conexão TCP: ${socket.id}`);
    partialData.set(socket, Buffer.alloc(0));

    socket.on("data", data => {
        console.log(`[GT06] Dados recebidos de ${socket.id}:`, data);
        let buffer = Buffer.concat([partialData.get(socket), data]);
        for (; ;) {
            let result = decodeFrame(buffer);
            if (!result || !result.frame) {
                if (result && !result.frame) {
                    console.log("[GT06] Erro ao decodificar frame ou CRC inválido.");
                }
                partialData.set(socket, result ? result.leftover : buffer);
                break;
            }
            decodeGt06(socket, result.frame);
            buffer = result.leftover;
            if (buffer.length === 0) {
                partialData.set(socket, Buffer.alloc(0));
                break;
            }
        }
    });

    socket.on("end", () => {
        console.log(`[GT06] Conexão TCP finalizada: ${socket.id}`);
        partialData.delete(socket);
    });
});

server.listen(5023, () => {
    console.log("Servidor TCP GT06 rodando na porta 5023");
});

// ----------------------------------------------------------
// FUNÇÕES PARA ENVIO DE COMANDOS
// ----------------------------------------------------------

function sendCommand(deviceId, cmdType, model, alternative, pass, lang, text) {
    console.log("[GT06] sendCommand", { deviceId, cmdType, model, alternative, pass, lang, text });
    if (cmdType === "engineStop") {
        if (model === "G109") {
            return encodeCommand(pass, "DYD#", lang);
        } else if (alternative) {
            return encodeCommand(pass, "DYD," + pass + "#", lang);
        } else {
            return encodeCommand(pass, "Relay,1#", lang);
        }
    } else if (cmdType === "engineResume") {
        if (model === "G109") {
            return encodeCommand(pass, "HFYD#", lang);
        } else if (alternative) {
            return encodeCommand(pass, "HFYD," + pass + "#", lang);
        } else {
            return encodeCommand(pass, "Relay,0#", lang);
        }
    } else if (cmdType === "custom") {
        return encodeCommand(pass, text, lang);
    }
    console.log("[GT06] Tipo de comando não reconhecido, retornando null.");
    return null;
}

module.exports = {
    server,
    sendCommand,
    setDevicePassword: (id, pass) => { },
    setDeviceModel: (id, model) => { },
    setLanguage: (id, lang) => { },
    setAlternative: (id, alt) => { },
    sendToDevice: (id, cmdType, text) => {
        let pass = "123456";
        let model = "";
        let alt = false;
        let lng = false;
        return sendCommand(id, cmdType, model, alt, pass, lng, text || "");
    }
};
