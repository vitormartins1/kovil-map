import { log } from './utils.js';
import { Platform } from './platform.js';

let socket = null;
let reconnectInterval = 2000;
let eventHandlers = {};

export const Socket = {
    connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = "127.0.0.1:8000"; // Hardcoded for now, or use window.location.host
        const url = Platform.buildWebSocketUrl(`${protocol}//${host}/ws`);

        socket = new WebSocket(url);

        socket.onopen = () => {
            log("WebSocket Connected", "success");
            reconnectInterval = 2000;
        };

        socket.onmessage = (event) => {
            // Use requestAnimationFrame to avoid blocking the UI thread with too many updates
            requestAnimationFrame(() => {
                try {
                    const msg = JSON.parse(event.data);
                    if (msg.type && eventHandlers[msg.type]) {
                        eventHandlers[msg.type].forEach(handler => handler(msg.payload));
                    }
                } catch (e) {
                    console.error("WS Error:", e);
                }
            });
        };

        socket.onclose = () => {
            log("WebSocket Disconnected. Reconnecting...", "warn");
            setTimeout(Socket.connect, reconnectInterval);
            reconnectInterval = Math.min(reconnectInterval * 2, 30000);
        };

        socket.onerror = (err) => {
            console.error("WebSocket Error:", err);
            socket.close();
        };
    },

    on(eventType, handler) {
        if (!eventHandlers[eventType]) {
            eventHandlers[eventType] = [];
        }
        eventHandlers[eventType].push(handler);
    },

    off(eventType, handler) {
        if (!eventHandlers[eventType]) return;
        eventHandlers[eventType] = eventHandlers[eventType].filter(h => h !== handler);
    }
};
