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
    console.log("Initializing database...");
    await pool.query("create table if not exists gps_users(id serial primary key, username text unique, password text, created_at timestamp default now())");
    await pool.query("create table if not exists gps_devices(id serial primary key, user_id int, name text, imei text unique, created_at timestamp default now())");
    await pool.query(`create table if not exists gps_positions(
        id serial primary key,
        device_id text,
        frame_type int,
        raw_data text,
        lat double precision,
        lon double precision,
        time_stamp timestamp,
        created_at timestamp default now()
    )`);
    console.log("Database initialized.");
}
initDB();

app.post("/register", async (req, res) => {
    console.log("POST /register", req.body);
    try {
        let { username, password } = req.body;
        let userExists = await pool.query("select * from gps_users where username=$1", [username]);
        if (userExists.rowCount > 0) {
            console.log("User already exists:", username);
            return res.status(400).json({ error: "User already exists" });
        }
        let hash = await bcrypt.hash(password, 10);
        await pool.query("insert into gps_users(username, password) values($1, $2)", [username, hash]);
        console.log("User registered:", username);
        res.json({ success: true });
    } catch (e) {
        console.log("Error in /register:", e.message);
        res.status(500).json({ error: e.message });
    }
});

app.post("/login", async (req, res) => {
    console.log("POST /login", req.body);
    try {
        let { username, password } = req.body;
        let userRow = await pool.query("select * from gps_users where username=$1", [username]);
        if (userRow.rowCount === 0) {
            console.log("Invalid username:", username);
            return res.status(400).json({ error: "Invalid credentials" });
        }
        let user = userRow.rows[0];
        let match = await bcrypt.compare(password, user.password);
        if (!match) {
            console.log("Invalid password for user:", username);
            return res.status(400).json({ error: "Invalid credentials" });
        }
        let token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "1d" });
        console.log("User logged in:", username);
        res.json({ token });
    } catch (e) {
        console.log("Error in /login:", e.message);
        res.status(500).json({ error: e.message });
    }
});

function auth(req, res, next) {
    console.log("Auth middleware");
    try {
        let header = req.headers.authorization;
        if (!header) {
            console.log("No token provided");
            return res.status(401).json({ error: "No token" });
        }
        let token = header.split(" ")[1];
        let decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (e) {
        console.log("Invalid token");
        res.status(401).json({ error: "Invalid token" });
    }
}

app.get("/profile", auth, (req, res) => {
    console.log("GET /profile", req.user);
    res.json({ id: req.user.id, username: req.user.username });
});

app.get("/", (req, res) => {
    console.log("GET /");
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.post("/api/devices", auth, async (req, res) => {
    console.log("POST /api/devices", req.body, "user:", req.user);
    try {
        let { name, imei } = req.body;
        let check = await pool.query("select * from gps_devices where imei=$1", [imei]);
        if (check.rowCount > 0) {
            console.log("IMEI already registered:", imei);
            return res.status(400).json({ error: "This IMEI is already registered" });
        }
        await pool.query("insert into gps_devices(user_id, name, imei) values($1, $2, $3)", [req.user.id, name, imei]);
        console.log("Device inserted:", name, imei);
        res.json({ success: true });
    } catch (e) {
        console.log("Error in /api/devices:", e.message);
        res.status(500).json({ error: e.message });
    }
});

app.get("/api/devices", auth, async (req, res) => {
    console.log("GET /api/devices", "user:", req.user);
    try {
        let result = await pool.query("select * from gps_devices where user_id=$1 order by created_at desc", [req.user.id]);
        res.json(result.rows);
    } catch (e) {
        console.log("Error in /api/devices:", e.message);
        res.status(500).json({ error: e.message });
    }
});

app.get("/api/positions/last", auth, async (req, res) => {
    console.log("GET /api/positions/last", req.query);
    let imei = req.query.imei;
    if (!imei) return res.json({ error: "No IMEI" });
    try {
        let result = await pool.query("select * from gps_positions where device_id=$1 and lat is not null and lon is not null order by time_stamp desc limit 1", [imei]);
        if (result.rowCount === 0) return res.json({});
        let row = result.rows[0];
        console.log("Last position for", imei, row.lat, row.lon, row.time_stamp);
        res.json({
            lat: row.lat,
            lon: row.lon,
            time: row.time_stamp
        });
    } catch (e) {
        console.log("Error in /api/positions/last:", e.message);
        res.json({ error: e.message });
    }
});

app.get("/api/positions/live", auth, async (req, res) => {
    console.log("GET /api/positions/live");
    try {
        let result = await pool.query("select device_id as imei, lat, lon from (select device_id, lat, lon, row_number() over (partition by device_id order by time_stamp desc) as rn from gps_positions where lat is not null and lon is not null) t where rn=1");
        res.json(result.rows);
    } catch (e) {
        console.log("Error in /api/positions/live:", e.message);
        res.json({ error: e.message });
    }
});

app.listen(4000, () => {
    console.log("HTTP server running on port 4000");
});

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
    console.log("encodeCommand", gt06Password, content, language);
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
    console.log("decodeFrame", buffer);
    if (buffer.length < 5) return null;
    let start = (buffer[0] === 0x78 && buffer[1] === 0x78) ? 2 : ((buffer[0] === 0x79 && buffer[1] === 0x79) ? 4 : 0);
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
    if (calc !== readCrc) {
        console.log("CRC mismatch");
        return { frame: null, leftover };
    }
    console.log("Decoded frame", frame);
    return { frame, leftover };
}

function respond(socket, frame, type, content, extended) {
    console.log("respond", type, extended, content);
    if (!socket.destroyed) {
        let head = extended ? 0x7979 : 0x7878;
        let length = extended ? (2 + 1 + (content ? content.length : 0) + 2 + 2) : (1 + (content ? content.length : 0) + 2 + 2);
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
        console.log("Sending response", answer);
        socket.write(answer);
    }
}

function decodeGps(content) {
    console.log("decodeGps", content);
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
    console.log("Decoded GPS lat/lon/time", lat, lon, dateStr);
    return { lat, lon, time: dateStr };
}

let deviceSessions = {};
let partialData = new WeakMap();

function decodeGt06(socket, frame) {
    console.log("decodeGt06 invoked");
    let start = (frame[0] === 0x78 && frame[1] === 0x78) ? 2 : 4;
    let type = frame[start];
    let content = frame.subarray(start + 1, frame.length - 4);
    if (type === 0x01) {
        let imeiHex = content.subarray(0, 8).toString("hex");
        let imei = parseImeiHex(imeiHex);
        console.log("Login packet, IMEI hex:", imeiHex, "parsed:", imei);
        if (!imei) return;
        deviceSessions[socket.id] = imei;
        respond(socket, frame, type, Buffer.alloc(0), false);
        console.log("Inserting login data for IMEI:", imei);
        insertData(imei, type, frame.toString("hex"), null, null, new Date());
    } else if (type === 0x10) {
        let imei = deviceSessions[socket.id] || "";
        console.log("GPS data packet, IMEI:", imei);
        let gps = decodeGps(content);
        if (gps) {
            respond(socket, frame, type, Buffer.alloc(0), false);
            console.log("Inserting GPS data for IMEI:", imei, gps.lat, gps.lon, gps.time);
            insertData(imei, type, frame.toString("hex"), gps.lat, gps.lon, gps.time);
        } else {
            respond(socket, frame, type, Buffer.alloc(0), false);
            console.log("Invalid GPS data, storing raw");
            insertData(imei, type, frame.toString("hex"), null, null, new Date());
        }
    } else {
        console.log("Other packet type:", type);
        respond(socket, frame, type, Buffer.alloc(0), false);
        let imei = deviceSessions[socket.id] || "";
        console.log("Inserting non-GPS data for IMEI:", imei);
        insertData(imei, type, frame.toString("hex"), null, null, new Date());
    }
}

let server = net.createServer(socket => {
    socket.id = socket.remoteAddress + ":" + socket.remotePort + ":" + Date.now();
    console.log("New TCP connection:", socket.id);
    partialData.set(socket, Buffer.alloc(0));
    socket.on("data", data => {
        console.log("TCP data from", socket.id, data);
        let buffer = Buffer.concat([partialData.get(socket), data]);
        for (; ;) {
            let result = decodeFrame(buffer);
            if (!result || !result.frame) {
                if (result && !result.frame) console.log("Frame decode failure or CRC mismatch");
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
        console.log("TCP connection ended:", socket.id);
        partialData.delete(socket);
    });
});

server.listen(5023, () => {
    console.log("TCP server running on port 5023");
});

function sendCommand(deviceId, cmdType, model, alternative, pass, lang, text) {
    console.log("sendCommand", deviceId, cmdType, model, alternative, pass, lang, text);
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
