// server.js

const express = require('express')
const session = require('express-session')
const bodyParser = require('body-parser')
const sqlite3 = require('sqlite3').verbose()
const net = require('net')
const app = express()
const db = new sqlite3.Database('database.db')

db.serialize(() => {
    db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      password TEXT,
      role TEXT
    )
  `)

    db.run(`
    CREATE TABLE IF NOT EXISTS devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      imei TEXT,
      userId INTEGER,
      name TEXT,
      plate TEXT,
      brand TEXT,
      model TEXT,
      year TEXT,
      color TEXT
    )
  `)

    db.run(`
    CREATE TABLE IF NOT EXISTS positions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      deviceId INTEGER,
      timestamp DATETIME,
      latitude REAL,
      longitude REAL,
      speed REAL
    )
  `)

    db.get(`SELECT COUNT(*) as count FROM users`, (err, row) => {
        if (!err && row && row.count === 0) {
            db.run(`INSERT INTO users (username,password,role) VALUES ('admin','1234','master')`)
        }
    })
})

app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }))
app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())
app.use(express.static('public'))

app.get('/', (req, res) => {
    if (!req.session.user) { res.redirect('/login.html') } else { res.redirect('/dashboard.html') }
})

app.post('/login', (req, res) => {
    db.get(`SELECT * FROM users WHERE username=? AND password=?`, [req.body.username, req.body.password], (err, row) => {
        if (!row) { res.send('fail') } else { req.session.user = row; res.send('ok') }
    })
})

app.get('/logout', (req, res) => {
    req.session.destroy(() => { res.redirect('/login.html') })
})

app.get('/user', (req, res) => {
    if (!req.session.user) { res.json({ error: true }) } else { res.json(req.session.user) }
})

app.get('/devices', (req, res) => {
    if (!req.session.user) { res.json([]); return }
    db.all(`SELECT * FROM devices WHERE userId=?`, [req.session.user.id], (err, rows) => {
        res.json(rows || [])
    })
})

app.post('/devices', (req, res) => {
    if (!req.session.user) { res.json({ error: true }); return }
    let { imei, name, plate, brand, model, year, color } = req.body
    db.run(`
    INSERT INTO devices (imei,userId,name,plate,brand,model,year,color)
    VALUES (?,?,?,?,?,?,?,?)
  `, [imei, req.session.user.id, name || '', plate || '', brand || '', model || '', year || '', color || ''], function (e) {
        res.json({ id: this.lastID })
    })
})

app.get('/positions', (req, res) => {
    if (!req.session.user) { res.json([]); return }
    db.all(`
    SELECT p.* FROM positions p
    INNER JOIN devices d ON p.deviceId=d.id
    WHERE d.userId=? AND p.deviceId=?
    ORDER BY p.id DESC LIMIT 50
  `, [req.session.user.id, req.query.deviceId], (err, rows) => {
        res.json(rows || [])
    })
})

app.listen(4000, () => { })

const parsePacket = (data) => {
    if (data.length < 10) return null
    if (data[0] === 0x78 && data[1] === 0x78) {
        let length = data[2]
        let protocol = data[3]
        if (protocol === 0x01) {
            let imei = data.slice(4, 12).toString('hex')
            return { type: 'login', imei }
        }
        if (protocol === 0x12) {
            let year = data[4]
            let month = data[5]
            let day = data[6]
            let hour = data[7]
            let min = data[8]
            let sec = data[9]
            let gpsLenSat = data[10]
            let lat = (data[11] << 24) + (data[12] << 16) + (data[13] << 8) + (data[14])
            let lon = (data[15] << 24) + (data[16] << 16) + (data[17] << 8) + (data[18])
            let speed = data[19]
            let latDec = lat / 30000 / 60
            let lonDec = lon / 30000 / 60
            return { type: 'location', date: `20${year}-${month}-${day} ${hour}:${min}:${sec}`, lat: latDec, lon: lonDec, speed }
        }
    }
    return null
}

const tcpServer = net.createServer((socket) => {
    socket.on('data', (buf) => {
        console.log('Pacote recebido:', buf.toString('hex'))
        let p = parsePacket(buf)
        console.log('Pacote parseado:', p)
        if (p && p.type === 'login') {
            socket.write(Buffer.from([0x78, 0x78, 0x05, 0x01, 0x00, 0x01, 0xD9, 0xDC, 0x0D, 0x0A]))
        }
        if (p && p.type === 'location') {
            db.all(`SELECT id,imei FROM devices`, (err, rows) => {
                let dev = rows.find(r => r.imei === p.imei)
                if (dev) {
                    db.run(`
            INSERT INTO positions (deviceId,timestamp,latitude,longitude,speed)
            VALUES (?,?,?,?,?)
          `, [dev.id, new Date(), p.lat, p.lon, p.speed])
                }
            })
            socket.write(Buffer.from([0x78, 0x78, 0x05, 0x12, 0x00, 0x01, 0x00, 0x00, 0x0D, 0x0A]))
        }
    })
    socket.on('error', () => { })
})

tcpServer.listen(5000, () => { })
