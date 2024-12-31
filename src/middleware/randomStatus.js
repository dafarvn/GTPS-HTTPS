/**
 * DaFaFlare. Random Custom HTTPS Status Code.
 */

const statusCodes = [200, 301, 302, 307];

const randomStatus = () => {
    return statusCodes[Math.floor(Math.random() * statusCodes.length)];
};

export { randomStatus };
