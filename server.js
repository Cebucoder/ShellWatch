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

'use strict';

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const axios = require('axios');
const net = require('net');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 3000;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY;

const io = new Server(server, {
    cors: {
        origin: process.env.DASHBOARD_ORIGIN || false
    }
});

app.disable('x-powered-by');

app.use(express.json({
    limit: '16kb',
    strict: true
}));

app.use(express.static(path.join(__dirname, 'public')));

// --------------------------------------------------
// HEALTH CHECK
// --------------------------------------------------

app.get('/api/health', (req, res) => {
    res.set('Cache-Control', 'no-store');

    res.json({
        status: 'ok',
        service: 'ShellWatch',
        urlscanConfigured: Boolean(URLSCAN_API_KEY)
    });
});

// --------------------------------------------------
// HELPER FUNCTIONS
// --------------------------------------------------

function isValidWebhookSecret(suppliedSecret) {
    if (
        typeof WEBHOOK_SECRET !== 'string' ||
        !WEBHOOK_SECRET ||
        typeof suppliedSecret !== 'string'
    ) {
        return false;
    }

    const expected = Buffer.from(WEBHOOK_SECRET, 'utf8');
    const supplied = Buffer.from(suppliedSecret, 'utf8');

    return expected.length === supplied.length &&
        crypto.timingSafeEqual(expected, supplied);
}

function cleanString(value, maxLength, fallback = '') {
    if (typeof value !== 'string') {
        return fallback;
    }

    const cleaned = value
        .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
        .trim()
        .slice(0, maxLength);

    return cleaned || fallback;
}

function isPublicIPv4(ip) {
    const parts = ip.split('.').map(Number);

    if (
        parts.length !== 4 ||
        parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)
    ) {
        return false;
    }

    const [a, b, c] = parts;

    // Exclude private, loopback, link-local, documentation,
    // benchmarking, multicast, and other reserved ranges.
    if (
        a === 0 ||
        a === 10 ||
        a === 127 ||
        a >= 224 ||
        (a === 100 && b >= 64 && b <= 127) ||
        (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        (a === 192 && b === 0) ||
        (a === 192 && b === 88 && c === 99) ||
        (a === 198 && (b === 18 || b === 19)) ||
        (a === 198 && b === 51 && c === 100) ||
        (a === 203 && b === 0 && c === 113)
    ) {
        return false;
    }

    return true;
}

function isPublicIPv6(ip) {
    const normalized = ip.toLowerCase();

    if (
        normalized === '::' ||
        normalized === '::1' ||
        normalized.startsWith('fc') ||
        normalized.startsWith('fd') ||
        /^fe[89ab]/.test(normalized) ||
        normalized.startsWith('ff') ||
        normalized.startsWith('::ffff:')
    ) {
        return false;
    }

    return true;
}

// --------------------------------------------------
// URLSCAN SEARCH API
// This searches historical URLScan results.
// --------------------------------------------------

app.get('/api/urlscan-search', async (req, res) => {
    const query = typeof req.query.q === 'string'
        ? req.query.q.trim()
        : '';

    if (!query || query.length > 300) {
        return res.status(400).json({
            error: 'Invalid search query. Provide a query up to 300 characters.'
        });
    }

    if (!URLSCAN_API_KEY) {
        console.error('[URLScan] URLSCAN_API_KEY is not configured.');

        return res.status(503).json({
            error: 'URLScan API key is not configured on the server.'
        });
    }

    try {
        const response = await axios.get(
            'https://urlscan.io/api/v1/search/',
            {
                params: {
                    q: query,
                    size: 8
                },
                headers: {
                    'api-key': URLSCAN_API_KEY,
                    'Accept': 'application/json'
                },
                timeout: 15000,
                maxRedirects: 0
            }
        );

        const results = Array.isArray(response.data?.results)
            ? response.data.results
            : [];

        console.log(
            `[URLScan] Search successful | Results: ${results.length}`
        );

        return res.json({
            status: 'success',
            total: response.data?.total ?? results.length,
            results
        });

    } catch (error) {
        const upstreamStatus = error.response?.status || null;

        console.error('[URLScan] Search failed:', {
            status: upstreamStatus,
            code: error.code || null,
            message: error.message
        });

        let message = 'URLScan search request failed.';

        if (upstreamStatus === 401 || upstreamStatus === 403) {
            message = 'URLScan rejected the API key or access.';
        } else if (upstreamStatus === 429) {
            message = 'URLScan rate limit reached. Try again later.';
        } else if (error.code === 'ECONNABORTED') {
            message = 'URLScan request timed out.';
        } else if (!upstreamStatus) {
            message = 'Could not connect to URLScan. Check server connectivity.';
        }

        return res.status(502).json({
            error: message,
            upstreamStatus,
            code: error.code || null
        });
    }
});

// --------------------------------------------------
// PHP SECURITY WEBHOOK
// Receives authenticated security events.
// --------------------------------------------------

app.post('/api/webhook/attack', async (req, res) => {
    try {
        if (!WEBHOOK_SECRET) {
            console.error('[ShellWatch] WEBHOOK_SECRET is not configured.');

            return res.status(503).json({
                error: 'Webhook not configured'
            });
        }

        const suppliedSecret = req.get('X-ShellWatch-Secret');

        if (!isValidWebhookSecret(suppliedSecret)) {
            return res.status(401).json({
                error: 'Unauthorized'
            });
        }

        const body = req.body || {};
        const ip = typeof body.ip === 'string' ? body.ip.trim() : '';

        if (!net.isIP(ip)) {
            return res.status(400).json({
                error: 'Invalid IP address'
            });
        }

        const domain = cleanString(body.domain, 253, 'Unknown');
        const shellType = cleanString(
            body.shellType,
            100,
            'Suspicious Activity'
        );
        const payload = cleanString(
            body.payload,
            500,
            'Security event detected'
        );

        let country = 'Unknown';
        let code = '';
        let lat = null;
        let lng = null;

        const ipVersion = net.isIP(ip);
        const publicIp = ipVersion === 4
            ? isPublicIPv4(ip)
            : isPublicIPv6(ip);

        // Geolocation is optional and must not block event reporting.
        if (publicIp) {
            try {
                const geoResponse = await axios.get(
                    `https://ipwho.is/${encodeURIComponent(ip)}`,
                    {
                        timeout: 2500,
                        maxRedirects: 0
                    }
                );

                const geo = geoResponse.data;

                if (geo && geo.success === true) {
                    country = cleanString(
                        geo.country,
                        100,
                        'Unknown'
                    );

                    code = cleanString(
                        geo.country_code,
                        2,
                        ''
                    );

                    if (
                        typeof geo.latitude === 'number' &&
                        Number.isFinite(geo.latitude) &&
                        geo.latitude >= -90 &&
                        geo.latitude <= 90 &&
                        typeof geo.longitude === 'number' &&
                        Number.isFinite(geo.longitude) &&
                        geo.longitude >= -180 &&
                        geo.longitude <= 180
                    ) {
                        lat = geo.latitude;
                        lng = geo.longitude;
                    }
                }
            } catch (error) {
                console.warn(
                    '[ShellWatch] Geolocation unavailable:',
                    error.message
                );
            }
        }

        const threatData = {
            id: `hp_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
            domain,
            ip,
            country,
            code,
            lat,
            lng,
            shellType,
            payload,
            severity: 'Review',
            time: new Date().toISOString(),
            source: 'PHP Honeypot Webhook'
        };

        // Broadcast the authenticated, validated event to connected dashboards.
        io.emit('threat_alert', threatData);

        console.log(
            `[ShellWatch] Event accepted | IP: ${ip} | Domain: ${domain} | Type: ${shellType}`
        );

        return res.status(200).json({
            status: 'success',
            message: 'Security event accepted',
            threat: threatData.id
        });

    } catch (error) {
        console.error('[ShellWatch] Webhook error:', error.message);

        return res.status(500).json({
            error: 'Internal server error'
        });
    }
});

// --------------------------------------------------
// ERROR HANDLING
// --------------------------------------------------

app.use((err, req, res, next) => {
    if (res.headersSent) {
        return next(err);
    }

    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        return res.status(400).json({
            error: 'Invalid JSON request body.'
        });
    }

    if (err && err.status === 413) {
        return res.status(413).json({
            error: 'Request body too large.'
        });
    }

    console.error('[ShellWatch] Request error:', err.message);

    return res.status(500).json({
        error: 'Internal server error.'
    });
});

// --------------------------------------------------
// SOCKET.IO DASHBOARD CONNECTIONS
// --------------------------------------------------

io.on('connection', (socket) => {
    console.log('[ShellWatch] Dashboard connected:', socket.id);

    socket.on('disconnect', () => {
        console.log('[ShellWatch] Dashboard disconnected:', socket.id);
    });
});

// --------------------------------------------------
// START SERVER LAST
// --------------------------------------------------

server.listen(PORT, () => {
    console.log(`[ShellWatch] Server listening on port ${PORT}`);
    console.log(
        `[ShellWatch] URLScan API key configured: ${Boolean(URLSCAN_API_KEY)}`
    );
    console.log(
        `[ShellWatch] Webhook secret configured: ${Boolean(WEBHOOK_SECRET)}`
    );
});

