// Node.js Backend Server (server.js)
const WebSocket = require('ws');
const axios = require('axios');

const wss = new WebSocket.Server({ port: 8080 });
console.log('[ShellWatch Backend] WebSocket Listening on ws://localhost:8080');

wss.on('connection', (ws) => {
    console.log('Client connected to threat stream.');

    // Function to push live detected threat
    const pushThreat = async (ip, domain, shellType, payload) => {
        try {
            // Resolve IP to GeoLocation via GeoIP API
            const geoRes = await axios.get(`http://ip-api.com/json/${ip}`);
            const geo = geoRes.data;

            const threatData = {
                id: 'ws_' + Date.now(),
                domain: domain,
                ip: ip,
                country: geo.country || 'Unknown',
                code: geo.countryCode || 'US',
                lat: geo.lat || 0,
                lng: geo.lon || 0,
                shellType: shellType, // 'WP', 'PHP', etc.
                payload: payload,
                severity: 'Critical',
                time: 'Just now'
            };

            ws.send(JSON.stringify(threatData));
        } catch (e) {
            console.error('GeoIP Resolution Error:', e);
        }
    };

    // Example: Push event every 5 seconds
    setInterval(() => {
        pushThreat('112.198.45.101', 'compromised-site.com', 'WP', 'WSO WebShell v4');
    }, 5000);
});
