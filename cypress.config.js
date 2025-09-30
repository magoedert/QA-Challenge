const { defineConfig } = require("cypress");

module.exports = defineConfig({
  e2e: {
    baseUrl: 'http://localhost:3001/',
    setupNodeEvents(on, config) {
      // implement node event listeners here

      // Configurar relatórios
      on('task', {
        log(message) {
          console.log(message);
          return null;
        },

        generateTimestamp() {
          return new Date().toISOString();
        }
      });

      // Event listeners para capturar dados de teste
      on('before:spec', (spec) => {
        console.log(`🧪 Iniciando spec: ${spec.name}`);
      });

      on('after:spec', (spec, results) => {
        console.log(`✅ Spec finalizado: ${spec.name}`);
        console.log(`📊 Resultados: ${results.stats.passes} passou(ram), ${results.stats.failures} falhou(ram)`);
      });
    },

    // Configurações de gravação e screenshots
    video: true,
    videosFolder: 'cypress/videos',
    screenshotOnRunFailure: true,
    screenshotsFolder: 'cypress/screenshots',

    // Configurações de timeout
    defaultCommandTimeout: 10000,
    requestTimeout: 15000,
    responseTimeout: 15000,
    pageLoadTimeout: 30000,

    // Configurações de retry
    retries: {
      runMode: 2,
      openMode: 0
    },

    // Configurações de suporte
    supportFile: 'cypress/support/e2e.js',
    fixturesFolder: 'cypress/fixtures',

    // Configurações de spec patterns
    specPattern: 'cypress/e2e/**/*.cy.{js,jsx,ts,tsx}',

    // Configurações de exclusão
    excludeSpecPattern: [
      '**/__snapshots__/*',
      '**/__image_snapshots__/*'
    ],

    // Configurações experimentais
    experimentalStudio: true,
    experimentalWebKitSupport: true
  },

  // Configurações globais
  viewportWidth: 1280,
  viewportHeight: 720,

  // Configurações de componente (se necessário no futuro)
  component: {
    devServer: {
      framework: 'create-react-app',
      bundler: 'webpack',
    },
  },

  // Configurações de ambiente
  env: {
    coverage: false,
    codeCoverage: {
      exclude: 'cypress/**/*.*'
    }
  },

  // Configurações de reporter
  reporter: 'mochawesome',
  reporterOptions: {
    reportDir: 'cypress/reports',
    overwrite: false,
    html: true,
    json: true,
    timestamp: 'mmddyyyy_HHMMss',
    reportTitle: 'Mini E-commerce - Cypress Test Report',
    reportPageTitle: 'Cypress Test Results',
    embeddedScreenshots: true,
    inlineAssets: true,
    saveAllAttempts: false,
    charts: true,
    enableCharts: true,
    code: false
  }
});
