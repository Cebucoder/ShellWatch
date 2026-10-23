const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const axios = require('axios');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// I-serve ang static files gikan sa 'public' folder
app.use(express.static(path.join(__dirname, 'public')));

// Socket.io Connection para sa Real-time Logs
io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    // Function to push live detected threat with GeoIP
    const pushThreat = async (ip, domain, shellType, payload) => {
        try {
            // Resolve IP to GeoLocation via GeoIP API
            const geoRes = await axios.get(`http://ip-api.com/json/${ip}`);
            const geo = geoRes.data;

            const threatData = {
                id: 'ws_' + Date.now(),
                domain: domain,
                ip: ip,
                country: geo.country || 'Philippines',
                code: geo.countryCode || 'PH',
                lat: geo.lat || 10.3157,
                lng: geo.lon || 123.8854,
                shellType: shellType,
                payload: payload,
                severity: 'Critical',
                time: new Date().toLocaleTimeString()
            };

            // I-send diretso sa connected frontend dashboard
            socket.emit('threat_alert', threatData);
        } catch (e) {
            console.error('GeoIP Resolution Error:', e.message);
        }
    };

    // Simulated threat loop kada 5 segundos para sa connected client
    const interval = setInterval(() => {
        pushThreat(
            '112.198.45.' + Math.floor(Math.random() * 200),
            'compromised-site-' + Math.floor(Math.random() * 1000) + '.com',
            Math.random() > 0.5 ? 'WP Shell' : 'PHP WebShell',
            'WSO WebShell v4 /eval'
        );
    }, 5000);

    socket.on('disconnect', () => {
        clearInterval(interval);
        console.log('Client disconnected:', socket.id);
    });
});

// Gamita ang PORT nga ihatag sa Render o default sa 3000 kung local
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
