let client = null;
let isReady = false;
let pairingCode = null;
let initializationPromise = null;

function initialize() {
    if (initializationPromise) return initializationPromise;
    initializationPromise = (async () => {
        const { Client, LocalAuth } = require('whatsapp-web.js');
        client = new Client({
            authStrategy: new LocalAuth(),
            puppeteer: { args: ['--no-sandbox', '--disable-setuid-sandbox'] }
        });
        client.on('qr', (qr) => {
            pairingCode = qr;
            console.log('[WhatsApp] QR code ready for pairing.');
        });
        client.on('ready', () => {
            isReady = true;
            pairingCode = null;
            console.log('[WhatsApp] Bot is ready.');
        });
        client.on('auth_failure', () => {
            isReady = false;
            console.warn('[WhatsApp] Authentication failed.');
        });
        client.on('disconnected', () => {
            isReady = false;
        });
        await client.initialize();
    })().catch((error) => {
        initializationPromise = null;
        console.error('[WhatsApp] Initialization failed.');
        throw error;
    });
    return initializationPromise;
}

function normalizeNumber(number) {
    if (typeof number !== 'string') throw new Error('Registered WhatsApp number is invalid');
    let normalized = number.replace(/[^0-9]/g, '');
    if (normalized.length === 10) normalized = `91${normalized}`;
    if (normalized.length < 10 || normalized.length > 15) {
        throw new Error('Registered WhatsApp number is invalid');
    }
    return normalized;
}

async function sendOTP(number, otp) {
    if (!client || !isReady) throw new Error('WhatsApp transport is not ready');
    if (typeof otp !== 'string' || !/^\d{6}$/.test(otp)) throw new Error('OTP is invalid');
    const chatId = `${normalizeNumber(number)}@c.us`;
    await client.sendMessage(chatId, `Your password reset code is ${otp}. It expires in 5 minutes.`);
    return true;
}

async function sendMessage(number, message) {
    if (!client || !isReady) {
        console.warn('[WhatsApp] Bot is not ready. Message was not sent.');
        return false;
    }
    try {
        await client.sendMessage(`${normalizeNumber(number)}@c.us`, message);
        return true;
    } catch {
        console.error('[WhatsApp] Message could not be sent.');
        return false;
    }
}

function getStatus() {
    return { ready: isReady, pairingCode };
}

module.exports = { initialize, sendOTP, sendMessage, getStatus };
