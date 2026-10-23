const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const axios = require('axios');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Middleware para ma-parse ang JSON payloads gikan sa Webhooks
app.use(express.json());
// I-serve ang static files gikan sa 'public' folder
app.use(express.static(path.join(__dirname, 'public')));

// === REAL HONEYPOT WEBHOOK ENDPOINT ===
app.post('/api/webhook/attack', async (req, res) => {
    try {
        const { ip, domain, shellType, payload } = req.body;
        
        if (!ip) {
            return res.status(400).json({ error: 'Attacker IP is required' });
        }

        // Kuhaon ang tinuod nga GeoLocation sa attacker IP gamit ang ip-api.com
        const geoRes = await axios.get(`http://ip-api.com/json/${ip}`);
        const geo = geoRes.data;

        const threatData = {
            id: 'hp_' + Date.now(),
            domain: domain || 'honeypot-target.com',
            ip: ip,
            country: geo.country || 'Unknown',
            code: geo.countryCode || 'US',
            lat: geo.lat || 0,
            lng: geo.lon || 0,
            shellType: shellType || 'PHP WebShell',
            payload: payload || 'Unknown Exploit Attempt',
            severity: 'Critical',
            time: new Date().toLocaleTimeString()
        };

        // I-broadcast diretso sa 3D Globe ang T actitud nga attack!
        io.emit('threat_alert', threatData);
        
        console.log(`[REAL ATTACK CAUGHT] IP: ${ip} (${geo.country})`);
        res.status(200).json({ status: 'success', message: 'Real threat broadcasted' });
    } catch (e) {
        console.error('Webhook Error:', e.message);
        res.status(500).json({ error: e.message });
    }
});

io.on('connection', (socket) => {
    console.log('Dashboard client connected:', socket.id);

    socket.on('disconnect', () => {
        console.log('Dashboard client disconnected:', socket.id);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT} (Real Honeypot Mode)`);
});
