// public/script.js

let map
let marker
async function initMap() {
    map = new google.maps.Map(document.getElementById('map'), { center: { lat: 0, lng: 0 }, zoom: 2 })
    let r = await fetch('/user')
    let user = await r.json()
    if (!user.id) location = '/login.html'
    document.getElementById('userInfo').innerText = 'Logado como ' + user.username
    loadDevices()
}
async function loadDevices() {
    let r = await fetch('/devices')
    let ds = await r.json()
    let sel = document.getElementById('deviceSelect')
    sel.innerHTML = ''
    ds.forEach(d => {
        let o = document.createElement('option')
        o.value = d.id
        o.textContent = `ID:${d.id} IMEI:${d.imei} ${d.name || ''} ${d.plate || ''}`
        sel.appendChild(o)
    })
}
async function registerDevice() {
    let imei = document.getElementById('imeiField').value
    let name = document.getElementById('nameField').value
    let plate = document.getElementById('plateField').value
    let brand = document.getElementById('brandField').value
    let model = document.getElementById('modelField').value
    let year = document.getElementById('yearField').value
    let color = document.getElementById('colorField').value
    if (!imei) return
    await fetch('/devices', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ imei, name, plate, brand, model, year, color })
    })
    loadDevices()
}
async function loadPositions() {
    let sel = document.getElementById('deviceSelect')
    if (!sel.value) return
    let r = await fetch('/positions?deviceId=' + sel.value)
    let p = await r.json()
    let div = document.getElementById('positions')
    div.innerHTML = ''
    p.forEach(pos => {
        let d = document.createElement('div')
        d.textContent = `Data: ${pos.timestamp}, Lat: ${pos.latitude}, Lng: ${pos.longitude}, Speed: ${pos.speed}`
        div.appendChild(d)
    })
    if (p.length > 0) {
        let lat = p[0].latitude
        let lng = p[0].longitude
        map.setCenter({ lat, lng })
        map.setZoom(14)
        if (!marker) { marker = new google.maps.Marker({ map }) }
        marker.setPosition({ lat, lng })
    }
}
