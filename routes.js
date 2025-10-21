const { passwordController, healthController, adminController } = require('./controllers');

// Route definitions
const routeDefinitions = [
    { endpoint: '/v1/passwords', method: 'POST', handler: passwordController.generatePasswords },
    { endpoint: '/healthz', method: 'GET', handler: healthController.healthz },
    { endpoint: '/admin/reseed', method: 'POST', handler: adminController.reseedNow }
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
    availableEndpoints
};


