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
    await pool.query("create table if not exists gps_users(id serial primary key, username text unique, password text, created_at timestamp default now())");
    await pool.query("create table if not exists gps_positions(id serial primary key, device_id text, frame_type int, raw_data text, created_at timestamp default now())");
    await pool.query("create table if not exists gps_devices(id serial primary key, user_id int, name text, imei text unique, created_at timestamp default now())");
}
initDB();

app.post("/register", async (req, res) => {
    try {
        let { username, password } = req.body;
        let userExists = await pool.query("select * from gps_users where username=$1", [username]);
        if (userExists.rowCount > 0) {
            return res.status(400).json({ error: "User already exists" });
        }
        let hash = await bcrypt.hash(password, 10);
        await pool.query("insert into gps_users(username, password) values($1, $2)", [username, hash]);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post("/login", async (req, res) => {
    try {
        let { username, password } = req.body;
        let userRow = await pool.query("select * from gps_users where username=$1", [username]);
        if (userRow.rowCount === 0) {
            return res.status(400).json({ error: "Invalid credentials" });
        }
        let user = userRow.rows[0];
        let match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(400).json({ error: "Invalid credentials" });
        }
        let token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "1d" });
        res.json({ token });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

function auth(req, res, next) {
    try {
        let header = req.headers.authorization;
        if (!header) return res.status(401).json({ error: "No token" });
        let token = header.split(" ")[1];
        let decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (e) {
        res.status(401).json({ error: "Invalid token" });
    }
}

app.get("/profile", auth, (req, res) => {
    res.json({ id: req.user.id, username: req.user.username });
});

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.post("/api/devices", auth, async (req, res) => {
    try {
        let { name, imei } = req.body;
        let check = await pool.query("select * from gps_devices where imei=$1", [imei]);
        if (check.rowCount > 0) {
            return res.status(400).json({ error: "This IMEI is already registered" });
        }
        await pool.query("insert into gps_devices(user_id, name, imei) values($1, $2, $3)", [req.user.id, name, imei]);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get("/api/devices", auth, async (req, res) => {
    try {
        let result = await pool.query("select * from gps_devices where user_id=$1 order by created_at desc", [req.user.id]);
        res.json(result.rows);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.listen(3000);

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
    return packet;
}

function decodeFrame(buffer) {
    if (buffer.length < 5) return null;
    let start = buffer[0] === 0x78 && buffer[1] === 0x78 ? 2 : (buffer[0] === 0x79 && buffer[1] === 0x79 ? 4 : 0);
    if (!start) return null;
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
    if (buffer[end] !== 0x0d || buffer[end + 1] !== 0x0a) return null;
    let frame = buffer.subarray(0, end + (start === 2 ? 4 : 6));
    let leftover = buffer.subarray(end + (start === 2 ? 4 : 6));
    let dataForCrc = frame.subarray(start === 2 ? 2 : 2, frame.length - 4);
    let readCrc = frame.readUInt16BE(frame.length - 4);
    let calc = crc16X25(dataForCrc);
    if (calc !== readCrc) return { frame: null, leftover };
    return { frame, leftover };
}

function respond(socket, frame, type, content, extended) {
    if (!socket.destroyed) {
        let head = extended ? 0x7979 : 0x7878;
        let length = extended
            ? 2 + 1 + (content ? content.length : 0) + 2 + 2
            : 1 + (content ? content.length : 0) + 2 + 2;
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
        socket.write(answer);
    }
}

async function insertData(deviceId, frameType, rawData) {
    await pool.query("insert into gps_positions(device_id, frame_type, raw_data) values($1, $2, $3)", [
        deviceId,
        frameType,
        rawData
    ]);
}

let deviceSessions = {};
let partialData = new WeakMap();
let passwordMap = {};
let modelMap = {};
let languageMap = {};
let alternativeMap = {};

function decodeGt06(socket, frame) {
    let start = frame[0] === 0x78 && frame[1] === 0x78 ? 2 : 4;
    let type = frame[start];
    let content = frame.subarray(start + 1, frame.length - 4);
    if (type === 0x01) {
        let imeiHex = content.subarray(0, 8).toString("hex");
        let imei = parseImeiHex(imeiHex);
        if (!imei) return;
        deviceSessions[socket.id] = imei;
        respond(socket, frame, type, Buffer.alloc(0), false);
        insertData(imei, type, frame.toString("hex"));
    } else if (type === 0x23) {
        respond(socket, frame, type, Buffer.alloc(0), false);
        let d = deviceSessions[socket.id] || "";
        insertData(d, type, frame.toString("hex"));
    } else if (type === 0x2a) {
        let text = "NA&&NA&&0##";
        let r = Buffer.alloc(text.length + 5);
        r[0] = text.length;
        r.writeUInt32BE(0, 1);
        r.write(text, 5, "ascii");
        respond(socket, frame, 0x97, r, true);
        let dd = deviceSessions[socket.id] || "";
        insertData(dd, type, frame.toString("hex"));
    } else if (type === 0x8a) {
        let dt = new Date();
        let buf = Buffer.alloc(6);
        buf[0] = dt.getUTCFullYear() - 2000;
        buf[1] = dt.getUTCMonth() + 1;
        buf[2] = dt.getUTCDate();
        buf[3] = dt.getUTCHours();
        buf[4] = dt.getUTCMinutes();
        buf[5] = dt.getUTCSeconds();
        respond(socket, frame, 0x8a, buf, false);
        let dd = deviceSessions[socket.id] || "";
        insertData(dd, type, frame.toString("hex"));
    } else {
        respond(socket, frame, type, Buffer.alloc(0), false);
        let dd = deviceSessions[socket.id] || "";
        insertData(dd, type, frame.toString("hex"));
    }
}

let server = net.createServer(socket => {
    socket.id = socket.remoteAddress + ":" + socket.remotePort + ":" + Date.now();
    partialData.set(socket, Buffer.alloc(0));
    socket.on("data", data => {
        let buffer = Buffer.concat([partialData.get(socket), data]);
        for (; ;) {
            let result = decodeFrame(buffer);
            if (!result || !result.frame) {
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
        partialData.delete(socket);
    });
});

server.listen(5023);

function sendCommand(deviceId, cmdType, model, alternative, pass, lang, text) {
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
    return null;
}

module.exports = {
    server,
    sendCommand,
    setDevicePassword: (id, pass) => { passwordMap[id] = pass; },
    setDeviceModel: (id, model) => { modelMap[id] = model; },
    setLanguage: (id, lang) => { languageMap[id] = lang; },
    setAlternative: (id, alt) => { alternativeMap[id] = alt; },
    sendToDevice: (id, cmdType, text) => {
        let pass = passwordMap[id] || "123456";
        let model = modelMap[id] || "";
        let alt = alternativeMap[id] || false;
        let lang = languageMap[id] || false;
        return sendCommand(id, cmdType, model, alt, pass, lang, text || "");
    }
};
