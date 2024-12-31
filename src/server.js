/**
 *  DaFaFlare. Best Solutions Anti DDoS, Bot Spam, Proxy and etc.
 *  Copyright (C) DaFaFlare 2019-2025. All rights reserved.
 */

import https from 'https';
import * as fs from 'fs/promises';
import path from 'path';
import mime from 'mime-types';
import url from 'url';
import { autoBlacklist } from './middleware/autoBlacklist.js'
import { randomStatus } from './middleware/randomStatus.js';
import gradient from 'gradient-string';
import title from 'node-bash-title';
import { exec } from 'child_process';
const startTime = process.hrtime();

const setCmdSizeAndClear = (width, height) => {
    const command = `mode con: cols=${width} lines=${height}`;

    exec(command, (err, stdout, stderr) => {
        if (err) {
            return;
        }
        if (stderr) {
            return;
        }
    });
};

setCmdSizeAndClear(110, 30);

const setting = JSON.parse(await fs.readFile('./setting.json', 'utf-8'));

function elapsedTime() {
    const elapsedTime = process.hrtime(startTime);
    const totalSeconds = elapsedTime[0] + elapsedTime[1] / 1e9;
    const days = Math.floor(totalSeconds / 86400);
    const hours = Math.floor((totalSeconds % 86400) / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = Math.floor(totalSeconds % 60);

    const formattedTime = `${days}:${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;

    title(`DaFaFlare Ⅳ | Server Runtime: ${formattedTime}\r`);
}

setInterval(elapsedTime, 0.1);
export const __dirname = path.resolve();
const cache = path.join(__dirname, './cache');
const www = path.join(__dirname, './www');
const ssl = path.join(__dirname, 'src/ssl');

const logs = './denied.log';

const sslOptions = {
    key: await fs.readFile(path.join(ssl, 'growtopia.key.pem')),
    cert: await fs.readFile(path.join(ssl, 'growtopia.pem'))
}

const blockedUserAgent = [
    "python-requests",
    "python",
    "Python-urllib",
    "node-fetch",
    "axios",
    "Go-http-client",
    "Mozilla",
    "Chrome",
    "Safari",
    "Firefox",
    "Edge",
    "Opera",
    "Thunder Client",
    "Postman",
    "insomnia",
    "curl",
    "Wget",
    "HttpClient",
    "okhttp",
];

const now = new Date();
const day = String(now.getDate()).padStart(2, '0');
const month = String(now.getMonth() + 1).padStart(2, '0');
const year = now.getFullYear();
const hours = String(now.getHours()).padStart(2, '0');
const minutes = String(now.getMinutes()).padStart(2, '0');
const seconds = String(now.getSeconds()).padStart(2, '0');
const timestamp = `${day}-${month}-${year} ${hours}:${minutes}:${seconds}`;

export async function serverStatic(res, filePath) {
    try {
        const statusCodes = randomStatus();
        const data = await fs.readFile(filePath);
        const ext = path.extname(filePath).toLowerCase();
        const contentType = mime.lookup(ext) || 'application/octet-stream';

        res.writeHead(statusCodes, { 'Server': 'DaFaFlare', 'Content-Type': contentType });
        res.end(data);
    } catch (err) {
        const errorFile = path.join(www, 'err', '404.html');
        await serverStatic(res, errorFile);
    }
}

export function validUserAgent(req) {
    const userAgent = req.headers['user-agent'] || '';
    const accept = req.headers['accept'] || '';

    if (!userAgent.includes('UbiServices_SDK')) {
        return false;
    }

    if (accept === '*/*') {
        return true;
    }

    return false;
}

const server = https.createServer(sslOptions, async (req, res) => {
    const rawIp =
        req.headers['cf-connecting-ip']?.split(', ')[0] ||
        req.headers['x-forwarded-for'] ||
        req.headers['x-real-ip'] ||
        req.connection.remoteAddress ||
        req.socket.remoteAddress;

    const ip = rawIp.replace(/^.*:/, '');
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;
    const userAgent = req.headers['user-agent'] || '';

    autoBlacklist(req, res);

    if (pathname === '/growtopia/server_data.php') {

        const isBlocked = blockedUserAgent.some((blocked) =>
            userAgent.toLowerCase().includes(blocked.toLowerCase())
        );

        if (isBlocked) {
            await fs.appendFile(logs, `[${timestamp}] | IP Address > [${ip}] | User-Agent > [${userAgent}].\n`);
            const errorFilePath = path.join(www, 'err', '406.html');
            await serverStatic(res, errorFilePath);
            return;
        }

        if (!validUserAgent(req)) {
            const errorFilePath = path.join(www, 'err', '406.html');
            await serverStatic(res, errorFilePath);
            return;
        }

        process.stdout.write(gradient.vice(`[LOGS] GrowtopiaPS Login > [${ip}] | Request Url > [${req.url}]\r`));

        const maint = setting.Server.maintenance;
        if (maint === true) {
            res.writeHead(200, { 'Server': 'DaFaFlare', 'Content-Type': 'text/html' });
            res.end(`server|${setting.Server.ip}
                port|${setting.Server.port}
                type|1
                loginurl|${setting.Server.loginurl}
                maint|${setting.Server.maintenanceMessage} -- DaFaFlare
                beta_server|127.0.0.1
                beta_port|17091
                beta_type|1
                meta|DaFaFlare
                RTENDMARKERBS1001`);
            return;
        }
        res.writeHead(200, { 'Server': 'DaFaFlare', 'Content-Type': 'text/html' });
        res.end(`server|${setting.Server.ip}
            port|${setting.Server.port}
            type|1
            loginurl|${setting.Server.loginurl}
            #maint|${setting.Server.maintenanceMessage}
            beta_server|127.0.0.1
            beta_port|17091
            beta_type|1
            meta|DaFaFlare
            RTENDMARKERBS1001`);
    }

    if (pathname === '/') {
        const filePath = path.join(www, 'index.html');
        await serverStatic(res, filePath);
        return;
    }

    if (pathname.startsWith('/cache')) {
        const isBlocked = blockedUserAgent.some((blocked) =>
            userAgent.toLowerCase().includes(blocked.toLowerCase())
        );

        if (isBlocked) {
            const errorFilePath = path.join(www, 'err', '403.html');
            await serverStatic(res, errorFilePath);
            return;
        }

        if (!validUserAgent(req)) {
            const errorFilePath = path.join(www, 'err', '403.html');
            await serverStatic(res, errorFilePath);
            return;
        }

        process.stdout.write(gradient.vice(`[LOGS] GrowtopiaPS Login > [${ip}] | Request Url > [${req.url}] with Method [${req.method}]\r`));

        const filePath = path.join(cache, pathname.replace('/cache', ''));
        await serverStatic(res, filePath);
        return;
    }

    const errorFilePath = path.join(www, 'err', '404.html');
    await serverStatic(res, errorFilePath);
    return;
});

server.setTimeout(setting.Settings.setTimeout);
server.keepAliveTimeout = setting.Settings.keepAliveTimeout;
server.headersTimeout = setting.Settings.headersTimeout;

server.on('connection', (socket) => {
    socket.setTimeout(5000);
    socket.on('end', () => socket.destroy());
});

server.listen(443, () => {
    console.clear();
    console.log(gradient.vice(`    
    ╔═════════════════════════════════════════════════════════════════════════════════╗
    ║                                                                                 ║
    ║   ▓█████▄  ▄▄▄        █████▒▄▄▄        █████▒██▓    ▄▄▄       ██▀███  ▓█████    ║
    ║   ▒██▀ ██▌▒████▄    ▓██   ▒▒████▄    ▓██   ▒▓██▒   ▒████▄    ▓██ ▒ ██▒▓█   ▀    ║
    ║   ░██   █▌▒██  ▀█▄  ▒████ ░▒██  ▀█▄  ▒████ ░▒██░   ▒██  ▀█▄  ▓██ ░▄█ ▒▒███      ║
    ║   ░▓█▄   ▌░██▄▄▄▄██ ░▓█▒  ░░██▄▄▄▄██ ░▓█▒  ░▒██░   ░██▄▄▄▄██ ▒██▀▀█▄  ▒▓█  ▄    ║
    ║   ░▒████▓  ▓█   ▓██▒░▒█░    ▓█   ▓██▒░▒█░   ░██████▒▓█   ▓██▒░██▓ ▒██▒░▒████▒   ║
    ║   ▒▒▓  ▒  ▒▒   ▓▒█░ ▒ ░    ▒▒   ▓▒█░ ▒ ░   ░ ▒░▓  ░▒▒   ▓▒█░░ ▒▓ ░▒▓░░░ ▒░ ░    ║
    ║   ░ ▒  ▒   ▒   ▒▒ ░ ░       ▒   ▒▒ ░ ░     ░ ░ ▒  ░ ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ░  ░    ║
    ║   ░ ░  ░   ░   ▒    ░ ░     ░   ▒    ░ ░     ░ ░    ░   ▒     ░░   ░    ░       ║
    ║   ░          ░  ░             ░  ░           ░  ░     ░  ░   ░        ░  ░      ║
    ║   ░                                                                             ║
    ║═════════════════════════════════════════════════════════════════════════════════║
    ║                                                                                 ║
    ║   [INFO] DaFaFlare Active [√] | Synchronized [SSL] [WWW] [CACHE] [MIDDLEWARE]   ║
    ║   [SYSTEM] Operational & Listening on Port 443                                  ║
    ║                                                                                 ║
    ╚═════════════════════════════════════════════════════════════════════════════════╝
    `));
});
