#!/usr/bin/env node
/**
 * Secure Password Generator API with QRNG pooling.
 * - OS CSPRNG always used (crypto.randomBytes)
 * - Optional /dev/hwrng mixing (Linux)
 * - Optional QRNG (Outshift) pooled in background (POST, 10-bit blocks)
 * - HKDF-SHA256 mixing, rejection sampling (no modulo bias)
 * - Endpoint: POST /v1/passwords
 *
 * Body example:
 * {
 *   "length": 24,
 *   "count": 2,
 *   "includeLower": true, "includeUpper": true, "includeDigits": true,
 *   "includeSymbols": true, "symbols": "!@#$%^&*()-_=+[]{}:;<>,.?",
 *   "excludeAmbiguous": true,
 *   "requireEachClass": true
 * }
 */

const http = require('http');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const dotenv = require('dotenv');
dotenv.config();
const { routes, availableEndpoints, routeDefinitions, setAuthMiddleware } = require('./routes');
// dotenv already configured above

// --------------------- Config ---------------------
const PORT = parseInt(process.env.PORT || '8080', 10);
const ENABLE_CORS = String(process.env.ENABLE_CORS || 'false') === 'true';

const RATE_WINDOW_MS = parseInt(process.env.RATE_WINDOW_MS || '60000', 10);
const RATE_MAX = parseInt(process.env.RATE_MAX || '60', 10);
const MAX_BODY_BYTES = '16kb';

// API Key authentication
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || '';
const API_KEY_HEADER = 'x-api-key';

// ------------------- Authentication Middleware -------------------
function requireApiKey(req, res, next) {
    const providedKey = req.headers[API_KEY_HEADER];
    
    if (!ADMIN_API_KEY) {
        return res.status(500).json({ 
            error: 'Admin API key not configured',
            message: 'ADMIN_API_KEY environment variable must be set'
        });
    }
    
    if (!providedKey) {
        return res.status(401).json({ 
            error: 'API key required',
            message: `Please provide API key in ${API_KEY_HEADER} header`
        });
    }
    
    if (providedKey !== ADMIN_API_KEY) {
        return res.status(403).json({ 
            error: 'Invalid API key',
            message: 'The provided API key is incorrect'
        });
    }
    
    next();
}

// ------------------- Express app -------------------
async function main() {
    // Set up authentication middleware
    setAuthMiddleware(requireApiKey);

    const app = express();
    // Trust proxy for Docker/reverse proxy environments - but be specific about which proxies to trust
    // In Docker, we typically trust the first proxy (Docker's internal network)
    app.set('trust proxy', 1);
    app.disable('x-powered-by');
    app.use(helmet({ contentSecurityPolicy: false, hsts: true }));
    app.use(express.json({ limit: MAX_BODY_BYTES }));

    if (ENABLE_CORS) {
        app.use((req, res, next) => {
            res.setHeader('Access-Control-Allow-Origin', '*'); // tighten in prod
            res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
            if (req.method === 'OPTIONS') return res.sendStatus(204);
            next();
        });
    }

    // no-store responses
    app.use((req, res, next) => {
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        next();
    });

    app.use(rateLimit({ 
        windowMs: RATE_WINDOW_MS, 
        max: RATE_MAX, 
        standardHeaders: true, 
        legacyHeaders: false
        // Using default keyGenerator which properly handles IPv6 and proxy headers
        // with our trust proxy: 1 configuration
    }));

    // Generic router using the routes table (catch-all without pattern)
    app.use((req, res, next) => {
        const endpoint = req.path;
        const method = req.method;
        
        // Try exact match first
        let handler = routes[endpoint] && routes[endpoint][method];
        
        // If no exact match, try parameterized routes
        if (!handler) {
            for (const route of routeDefinitions) {
                if (route.method === method && route.endpoint.includes(':')) {
                    // Convert route pattern to regex
                    const pattern = route.endpoint.replace(/:\w+/g, '([^/]+)');
                    const regex = new RegExp(`^${pattern}$`);
                    
                    if (regex.test(endpoint)) {
                        // Extract parameters
                        const matches = endpoint.match(regex);
                        if (matches) {
                            const paramNames = route.endpoint.match(/:(\w+)/g);
                            if (paramNames) {
                                paramNames.forEach((param, index) => {
                                    const paramName = param.substring(1); // Remove the ':'
                                    req.params = req.params || {};
                                    req.params[paramName] = matches[index + 1];
                                });
                            }
                            handler = route.handler;
                            // Check if this route requires authentication
                            if (route.requiresAuth && requireApiKey) {
                                return requireApiKey(req, res, () => handler(req, res, next));
                            }
                            break;
                        }
                    }
                }
            }
        }
        
        // Check if exact match route requires authentication
        if (handler) {
            const route = routeDefinitions.find(r => r.endpoint === endpoint && r.method === method);
            if (route && route.requiresAuth && requireApiKey) {
                return requireApiKey(req, res, () => handler(req, res, next));
            }
        }
        
        if (!handler) {
            res.status(404).json({ error: 'Endpoint not found', availableEndpoints });
            return;
        }
        return handler(req, res, next);
    });

    http.createServer(app).listen(PORT, () => {
        console.log(`Password API listening on :${PORT}`);
    });
}

main().catch(err => {
    console.error('Fatal startup error:', err);
    process.exit(1);
});
