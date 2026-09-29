/* global SwaggerUIBundle */
SwaggerUIBundle({
  url: '/openapi.json',
  dom_id: '#swagger-ui',
  deepLinking: true,
  displayRequestDuration: true,
  persistAuthorization: false,
  validatorUrl: null,
  queryConfigEnabled: false,
  tryItOutEnabled: false,
  docExpansion: 'list',
  defaultModelsExpandDepth: -1,
});
