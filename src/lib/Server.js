'use strict';

const bcrypt = require('bcryptjs');
const crypto = require('node:crypto');
const { createServer: createHttpServer } = require('node:http');
const { createServer: createHttpsServer } = require('node:https');
const { readFileSync } = require('node:fs');
const { stat, readFile } = require('node:fs/promises');
const { resolve, sep } = require('node:path');

const expressSession = require('express-session');
const debug = require('debug')('Server');

const {
  createApp,
  createError,
  createRouter,
  defineEventHandler,
  fromNodeMiddleware,
  getRouterParam,
  toNodeListener,
  readBody,
  setHeader,
  serveStatic,
} = require('h3');

const WireGuard = require('../services/WireGuard');

const {
  PORT,
  PROTOCOL,
  CERT_PATH,
  KEY_PATH,
  WEBUI_HOST,
  PASSWORD,
  PASSWORD_HASH,
  USERNAME,
  USERNAME_HASH,
  LANG,
  UI_TRAFFIC_STATS,
  UI_CHART_TYPE,
} = require('../config');

const requiresAuth = !!PASSWORD_HASH && !!USERNAME_HASH;

/**
 * Checks if `password` matches the PASSWORD_HASH.
 *
 * If environment variable is not set, the password is always invalid.
 *
 * @param {string} password String to test
 * @returns {boolean} true if matching environment, otherwise false
 */

const isUsernameValid = (username) => {
  if (typeof username !== 'string') {
    return false;
  }

  if (USERNAME_HASH) {
    return bcrypt.compareSync(username, USERNAME_HASH);
  }

  return false;
};
 
const isPasswordValid = (password) => {
  if (typeof password !== 'string') {
    return false;
  }

  if (PASSWORD_HASH) {
    return bcrypt.compareSync(password, PASSWORD_HASH);
  }

  return false;
};

module.exports = class Server {

  constructor() {
    const app = createApp();
    this.app = app;

    app.use(fromNodeMiddleware(expressSession({
      secret: crypto.randomBytes(256).toString('hex'),
      resave: true,
      saveUninitialized: true,
      cookie: {
        secure: PROTOCOL.toLowerCase() === 'https', // Устанавливаем secure в зависимости от протокола
        sameSite: 'lax', // Дополнительная защита от CSRF
      },
    })));

    const router = createRouter();
    app.use(router);

    router
      .get('/api/lang', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return `"${LANG}"`;
      }))

      .get('/api/ui-traffic-stats', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return `"${UI_TRAFFIC_STATS}"`;
      }))

      .get('/api/ui-chart-type', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return `"${UI_CHART_TYPE}"`;
      }))

      // Authentication
      .get('/api/session', defineEventHandler((event) => {
        const authenticated = requiresAuth
          ? !!(event.node.req.session && event.node.req.session.authenticated)
          : true;

        return {
          requiresAuth,
          authenticated,
        };
      }))
      .post('/api/session', defineEventHandler(async (event) => {
        const { username, password } = await readBody(event);

        if (!requiresAuth) {
        // Если авторизация не требуется, API не должен вызываться.
          throw createError({
            status: 401,
            message: 'Invalid state',
          });
        }

        if (!isUsernameValid(username)) {
          throw createError({
          status: 401,
          message: 'Incorrect Username',
        });
      }

      if (!isPasswordValid(password)) {
        throw createError({
          status: 401,
          message: 'Incorrect Password',
        });
      }

      event.node.req.session.authenticated = true;
      event.node.req.session.save();

      debug(`New Session: ${event.node.req.session.id}`);

      return { success: true };
    }));

    // WireGuard
    app.use(
      fromNodeMiddleware((req, res, next) => {
        if (!requiresAuth || !req.url.startsWith('/api/')) {
          return next();
        }

        if (req.session && req.session.authenticated) {
          return next();
        }

        if (req.url.startsWith('/api/') && req.headers['authorization'] && req.headers['authorization-username']) {
          if (isUsernameValid(req.headers['authorization-username']) && isPasswordValid(req.headers['authorization'])) {
            return next();
          }
          return res.status(401).json({
            error: 'Incorrect Username or Password',
          });
        }

        return res.status(401).json({
          error: 'Not Logged In',
        });
      }),
    );

    const router2 = createRouter();
    app.use(router2);

    router2
      .delete('/api/session', defineEventHandler((event) => {
        const sessionId = event.node.req.session.id;

        event.node.req.session.destroy();

        debug(`Deleted Session: ${sessionId}`);
        return { success: true };
      }))
      .get('/api/wireguard/client/:clientId/traffic/:yearMonth', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        const yearMonth = getRouterParam(event, 'yearMonth');
        const clients = await WireGuard.getClients();
        const client = clients.find(c => c.id === clientId);
        if (!client) {
          throw createError({
            status: 404,
            message: 'Client Not Found',
          });
        }
        const traffic = client.monthlyTraffic[yearMonth] || { totalTransferRx: 0, totalTransferTx: 0 };
        setHeader(event, 'Content-Type', 'application/json');
        return  {
          transferRx: traffic.totalTransferRx || 0, // Накопленный трафик
          transferTx: traffic.totalTransferTx || 0, // Накопленный трафик
        };
      }))
      .get('/api/wireguard/client', defineEventHandler(() => {
        return WireGuard.getClients();
      }))
      .get('/api/wireguard/client/:clientId/qrcode.svg', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        const svg = await WireGuard.getClientQRCodeSVG({ clientId });
        setHeader(event, 'Content-Type', 'image/svg+xml');
        return svg;
      }))
      .get('/api/wireguard/client/:clientId/configuration', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        const client = await WireGuard.getClient({ clientId });
        const config = await WireGuard.getClientConfiguration({ clientId });
        const configName = client.name
          .replace(/[^a-zA-Z0-9_=+.-]/g, '-')
          .replace(/(-{2,}|-$)/g, '-')
          .replace(/-$/, '')
          .substring(0, 64);

        // Формируем тип конфигурации для имени файла
        const configType = client.type === 'wireguard' ? 'WireGuard' : 'AmneziaWG';
        const fileName = `${configName || clientId}-${configType}.conf`;

        setHeader(event, 'Content-Disposition', `attachment; filename="${fileName}"`);
        setHeader(event, 'Content-Type', 'text/plain');
        return config;
       }))
      .post('/api/wireguard/client', defineEventHandler(async (event) => {
        const { name, type, Jc, Jmin, Jmax, expiresAt } = await readBody(event);
        if (!['wireguard', 'amneziawg'].includes(type)) {
          throw createError({
            status: 400,
            message: 'Invalid client type',
          });
        }
        if (type === 'amneziawg' && (Jc < 1 || Jc > 128 || Jmin < 1 || Jmin > Jmax || Jmax < 1 || Jmax > 1280)) {
          throw createError({
            status: 400,
            message: 'Invalid AmneziaWG parameters',
          });
        }
        await WireGuard.createClient({ name, type, Jc, Jmin, Jmax, expiresAt });
        return { success: true };
      }))
      .delete('/api/wireguard/client/:clientId', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        await WireGuard.deleteClient({ clientId });
        return { success: true };
      }))
      .post('/api/wireguard/client/:clientId/enable', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        await WireGuard.enableClient({ clientId });
        return { success: true };
      }))
      .post('/api/wireguard/client/:clientId/disable', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        await WireGuard.disableClient({ clientId });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/name', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        const { name } = await readBody(event);
        await WireGuard.updateClientName({ clientId, name });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/amnezia-params', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        const { Jc, Jmin, Jmax } = await readBody(event);
        await WireGuard.updateClientAmneziaParams({ clientId, Jc: parseInt(Jc), Jmin: parseInt(Jmin), Jmax: parseInt(Jmax) });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/expiration', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        const { expiresAt } = await readBody(event);
        await WireGuard.updateClientExpiration({ clientId, expiresAt });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/type', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        const { type, Jc, Jmin, Jmax } = await readBody(event);
        await WireGuard.updateClientType({ clientId, type, Jc, Jmin, Jmax });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/address', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        const { address } = await readBody(event);
        await WireGuard.updateClientAddress({ clientId, address });
        return { success: true };
      }));

    const safePathJoin = (base, target) => {
      // Manage web root (edge case)
      if (target === '/') {
        return `${base}${sep}`;
      }

      // Prepend './' to prevent absolute paths
      const targetPath = `.${sep}${target}`;

      // Resolve the absolute path
      const resolvedPath = resolve(base, targetPath);

      // Check if resolvedPath is a subpath of base
      if (resolvedPath.startsWith(`${base}${sep}`)) {
        return resolvedPath;
      }

      throw createError({
        status: 400,
        message: 'Bad Request',
      });
    };

    // backup_restore
    const router3 = createRouter();
    app.use(router3);

    router3
      .get('/api/wireguard/backup', defineEventHandler(async (event) => {
        const config = await WireGuard.backupConfiguration();
        setHeader(event, 'Content-Disposition', 'attachment; filename="wg0.json"');
        setHeader(event, 'Content-Type', 'text/json');
        return config;
      }))
      .put('/api/wireguard/restore', defineEventHandler(async (event) => {
        const { file } = await readBody(event);
        await WireGuard.restoreConfiguration(file);
        return { success: true };
      }));

    // Static assets
    const publicDir = '/app/www';
    app.use(
      defineEventHandler((event) => {
        return serveStatic(event, {
          getContents: (id) => {
            return readFile(safePathJoin(publicDir, id));
          },
          getMeta: async (id) => {
            const filePath = safePathJoin(publicDir, id);

            const stats = await stat(filePath).catch(() => {});
            if (!stats || !stats.isFile()) {
              return;
            }

            if (id.endsWith('.html')) setHeader(event, 'Content-Type', 'text/html');
            if (id.endsWith('.js')) setHeader(event, 'Content-Type', 'application/javascript');
            if (id.endsWith('.json')) setHeader(event, 'Content-Type', 'application/json');
            if (id.endsWith('.css')) setHeader(event, 'Content-Type', 'text/css');
            if (id.endsWith('.png')) setHeader(event, 'Content-Type', 'image/png');

            return {
              size: stats.size,
              mtime: stats.mtimeMs,
            };
          },
        });
      }),
    );

    if (PASSWORD || USERNAME) {
      throw new Error('DO NOT USE PASSWORD OR USERNAME ENVIRONMENT VARIABLE. USE PASSWORD_HASH AND USERNAME_HASH INSTEAD.');
    }
    let server;
    if (PROTOCOL.toLowerCase() === 'https') {
      try {
        const cert = readFileSync(CERT_PATH);
        const key = readFileSync(KEY_PATH);
        server = createHttpsServer({ cert, key }, toNodeListener(app));
        debug(`Starting HTTPS server on https://${WEBUI_HOST}:${PORT}`);
      } catch (err) {
        debug(`Failed to start HTTPS server: ${err.message}. Falling back to HTTP.`);
        server = createHttpServer(toNodeListener(app));
        debug(`Starting HTTP server on http://${WEBUI_HOST}:${PORT}`);
      }
    } else {
      server = createHttpServer(toNodeListener(app));
      debug(`Starting HTTP server on http://${WEBUI_HOST}:${PORT}`);
    }

    server.listen(PORT, WEBUI_HOST, () => {
      debug(`Server is listening on ${PROTOCOL.toLowerCase() === 'https' ? 'https' : 'http'}://${WEBUI_HOST}:${PORT}`);
    });
  }
};
