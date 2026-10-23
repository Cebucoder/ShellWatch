const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// I-serve ang static files gikan sa 'public' folder
app.use(express.static(path.join(__dirname, 'public')));

// WebSocket Connection para sa Real-time Logs
io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    // Mock live threat generator para sa dashboard feed
    const interval = setInterval(() => {
        const mockLiveThreat = {
            domain: "example-compromised-site.com",
            ip: "192.168." + Math.floor(Math.random() * 255) + "." + Math.floor(Math.random() * 255),
            country: "Philippines",
            lat: 10.3157,
            lng: 123.8854,
            shell: "WSO Web Shell",
            severity: "Critical",
            time: new Date().toLocaleTimeString()
        };
        socket.emit('threat_alert', mockLiveThreat);
    }, 5000); // Mag-send ug update kada 5 segundos

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
