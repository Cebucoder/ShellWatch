// const express = require('express');
// const http = require('http');
// const { Server } = require('socket.io');
// const path = require('path');
// const axios = require('axios');

// const app = express();
// const server = http.createServer(app);
// const io = new Server(server);

// // Middleware para ma-parse ang JSON payloads gikan sa Webhooks
// app.use(express.json());
// // I-serve ang static files gikan sa 'public' folder
// app.use(express.static(path.join(__dirname, 'public')));

// // === REAL HONEYPOT WEBHOOK ENDPOINT ===
// app.post('/api/webhook/attack', async (req, res) => {
//     try {
//         const { ip, domain, shellType, payload } = req.body;
        
//         if (!ip) {
//             return res.status(400).json({ error: 'Attacker IP is required' });
//         }

//         // Kuhaon ang tinuod nga GeoLocation sa attacker IP gamit ang ip-api.com
//         const geoRes = await axios.get(`http://ip-api.com/json/${ip}`);
//         const geo = geoRes.data;

//         const threatData = {
//             id: 'hp_' + Date.now(),
//             domain: domain || 'honeypot-target.com',
//             ip: ip,
//             country: geo.country || 'Unknown',
//             code: geo.countryCode || 'US',
//             lat: geo.lat || 0,
//             lng: geo.lon || 0,
//             shellType: shellType || 'PHP WebShell',
//             payload: payload || 'Unknown Exploit Attempt',
//             severity: 'Critical',
//             time: new Date().toLocaleTimeString()
//         };

//         // I-broadcast diretso sa 3D Globe ang T actitud nga attack!
//         io.emit('threat_alert', threatData);
        
//         console.log(`[REAL ATTACK CAUGHT] IP: ${ip} (${geo.country})`);
//         res.status(200).json({ status: 'success', message: 'Real threat broadcasted' });
//     } catch (e) {
//         console.error('Webhook Error:', e.message);
//         res.status(500).json({ error: e.message });
//     }
// });

// io.on('connection', (socket) => {
//     console.log('Dashboard client connected:', socket.id);

//     socket.on('disconnect', () => {
//         console.log('Dashboard client disconnected:', socket.id);
//     });
// });

// const PORT = process.env.PORT || 3000;
// server.listen(PORT, () => {
//     console.log(`Server is running on port ${PORT} (Real Honeypot Mode)`);
// });




const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const axios = require('axios');
const net = require('net');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json({ limit: '16kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

// Basic health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', service: 'ShellWatch' });
});

app.post('/api/webhook/attack', async (req, res) => {
    try {
        if (!WEBHOOK_SECRET) {
            console.error('WEBHOOK_SECRET is not configured');
            return res.status(503).json({ error: 'Webhook not configured' });
        }

        const suppliedSecret = req.get('x-shellwatch-secret');

        if (typeof suppliedSecret !== 'string' ||
            suppliedSecret.length !== WEBHOOK_SECRET.length ||
            !require('crypto').timingSafeEqual(
                Buffer.from(suppliedSecret),
                Buffer.from(WEBHOOK_SECRET)
            )) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const { ip, domain, shellType, payload } = req.body || {};

        if (typeof ip !== 'string' || !net.isIP(ip)) {
            return res.status(400).json({ error: 'Invalid IP address' });
        }

        // Geolocation is optional. Alerts still work if lookup fails.
        let country = 'Unknown';
        let code = '';
        let lat = null;
        let lng = null;

        try {
            const response = await axios.get(
                `https://ipwho.is/${encodeURIComponent(ip)}`,
                { timeout: 2500 }
            );

            const geo = response.data;

            if (geo.success === true) {
                country = geo.country || 'Unknown';
                code = geo.country_code || '';

                if (Number.isFinite(geo.latitude) &&
                    Number.isFinite(geo.longitude)) {
                    lat = geo.latitude;
                    lng = geo.longitude;
                }
            }
        } catch (error) {
            console.warn('Geolocation unavailable:', error.message);
        }

        const threatData = {
            id: `hp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
            domain: typeof domain === 'string'
                ? domain.slice(0, 253)
                : 'Unknown',
            ip,
            country,
            code,
            lat,
            lng,
            shellType: typeof shellType === 'string'
                ? shellType.slice(0, 100)
                : 'Suspicious Request',
            payload: typeof payload === 'string'
                ? payload.slice(0, 1000)
                : 'Unknown',
            severity: 'Review',
            time: new Date().toISOString()
        };

        io.emit('threat_alert', threatData);

        console.log(
            `[ShellWatch] Alert received: ${ip} | ${domain || 'Unknown'}`
        );

        return res.json({ status: 'success', threat: threatData.id });
    } catch (error) {
        console.error('Webhook error:', error.message);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

io.on('connection', (socket) => {
    console.log('Dashboard connected:', socket.id);

    socket.on('disconnect', () => {
        console.log('Dashboard disconnected:', socket.id);
    });
});

server.listen(PORT, () => {
    console.log(`ShellWatch listening on port ${PORT}`);
});
