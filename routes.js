const { passwordController, healthController, adminController, diceController, entropyController } = require('./controllers');

// Import authentication middleware (will be passed from server.js)
let requireApiKey = null;
function setAuthMiddleware(authMiddleware) {
    requireApiKey = authMiddleware;
}

// Route definitions
const routeDefinitions = [
    { endpoint: '/v1/passwords', method: 'POST', handler: passwordController.generatePasswords },
    { endpoint: '/healthz', method: 'GET', handler: healthController.healthz },
    { endpoint: '/v1/admin/reseed', method: 'POST', handler: adminController.reseedNow, requiresAuth: true },
    { endpoint: '/v1/roll', method: 'POST', handler: diceController.rollDice },
    { endpoint: '/v1/roll/:expression', method: 'GET', handler: diceController.rollDice },
    { endpoint: '/v1/entropy/uint32', method: 'GET', handler: entropyController.getEntropyUint32 }
];

// Build routes map
const routes = {};
for (const route of routeDefinitions) {
    if (!routes[route.endpoint]) routes[route.endpoint] = {};
    routes[route.endpoint][route.method] = route.handler;
}

const availableEndpoints = routeDefinitions.map(r => `${r.method} ${r.endpoint}`);

module.exports = {
    routes,
    routeDefinitions,
    availableEndpoints,
    setAuthMiddleware
};


