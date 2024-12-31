/**
 * DaFaFlare. autoBlacklist Middleware.
 */

import { serverStatic, validUserAgent } from '../server.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import gradient from 'gradient-string';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const www = path.join(__dirname, '../../www');
const settingPath = path.join(__dirname, '../../setting.json');
const blacklistLog = path.join(__dirname, '../../blacklist.log');

const now = new Date();
const day = String(now.getDate()).padStart(2, '0');
const month = String(now.getMonth() + 1).padStart(2, '0');
const year = now.getFullYear();
const hours = String(now.getHours()).padStart(2, '0');
const minutes = String(now.getMinutes()).padStart(2, '0');
const seconds = String(now.getSeconds()).padStart(2, '0');
const timestamp = `${day}-${month}-${year} ${hours}:${minutes}:${seconds}`;

let setting;
try {
    setting = JSON.parse(fs.readFileSync(settingPath, 'utf-8'));
} catch (err) {
    console.log(gradient.vice('[ERROR] Failed to read setting.json configuration'));
    process.exit(1);
}

const {
    autoBlacklist: { rateLimitWindow, maxRequests, blacklistDuration },
} = setting;

const requestTracker = {};

function IPBlocked(ip) {
    fs.appendFileSync(blacklistLog, `[${timestamp}] | IP Address Blacklist > [${ip}]\n`);
}

export async function autoBlacklist(req, res) {
    const rawIp =
        req.headers['cf-connecting-ip']?.split(', ')[0] ||
        req.headers['x-forwarded-for'] ||
        req.headers['x-real-ip'] ||
        req.connection.remoteAddress ||
        req.socket.remoteAddress;

    const ip = rawIp.replace(/^.*:/, '');

    if (validUserAgent(req)) {
        const filePath = path.join(www, 'index.html');
        await serverStatic(res, filePath);
        return;
    }

    const logsBlacklist = fs.readFileSync(blacklistLog, 'utf-8');
    if (logsBlacklist.includes(ip)) {
        const errorFilePath = path.join(www, 'err', '403.html');
        await serverStatic(res, errorFilePath);
        return;
    }


    if (!requestTracker[ip]) {
        requestTracker[ip] = [];
    }

    const now = Date.now();
    requestTracker[ip] = requestTracker[ip].filter((timestamp) => now - timestamp < rateLimitWindow);

    requestTracker[ip].push(now);

    if (requestTracker[ip].length > maxRequests) {

        process.stdout.write(gradient.vice(`[SYSTEM] | ${timestamp} | IP Address > [${ip}] Blocked for security reason due suspicious.\n`));

        IPBlocked(ip);

        setTimeout(() => {
            const updatedBlacklistLog = fs.readFileSync(logsBlacklist, 'utf-8')
                .split('\n')
                .filter(line => !line.includes(ip))
                .join('\n');
            fs.writeFileSync(logsBlacklist, updatedBlacklistLog);
        }, blacklistDuration * 1000);

        const errorFilePath = path.join(www, 'err', '403.html');
        await serverStatic(res, errorFilePath);
        return;
    }
}

export async function handleRequest(req, res) {
    await autoBlacklist(req, res);
}
