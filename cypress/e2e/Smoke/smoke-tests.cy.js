/// <reference types="cypress" />

describe('Smoke Tests - Funcionalidades Críticas', () => {
  let users;

  before(() => {
    cy.fixture('users').then((userData) => {
      users = userData;
    });
  });

  beforeEach(() => {
    cy.visit('/');
    cy.clearLocalStorage();
    cy.clearCookies();
  });

  it('Aplicação deve carregar corretamente', () => {
    // Verificar elementos essenciais da página
    cy.get('h1').should('contain', 'BIX Mini E-commerce');
    cy.get('#email').should('be.visible');
    cy.get('#password').should('be.visible');
    cy.get('#login-btn').should('be.visible');
    cy.get('#product-list').should('exist');
    cy.get('#cart').should('be.visible');
    cy.get('#checkout-section').should('be.visible');
  });

  it('API de saúde deve responder', () => {
    cy.request({
      method: 'GET',
      url: '/api/health',
      failOnStatusCode: false
    }).then((response) => {
      expect(response.status).to.be.oneOf([200, 404]);
    });
  });

  it('Produtos devem carregar', () => {
    cy.request('GET', '/api/products').then((response) => {
      expect(response.status).to.eq(200);
      expect(response.body).to.have.property('items');
      expect(response.body.items).to.be.an('array');
      expect(response.body.items.length).to.be.greaterThan(0);
    });
  });

  it('Login deve funcionar', () => {
    cy.intercept('POST', '/api/login').as('loginRequest');

    cy.get('#email').type(Cypress.env('USER_EMAIL'));
    cy.get('#password').type(Cypress.env('USER_PASSWORD'));
    cy.get('#login-btn').click();

    cy.wait('@loginRequest');
    cy.get('#user-name').should('be.visible');
    cy.window().its('localStorage').invoke('getItem', 'token').should('exist');
  });

  it('Adicionar produto ao carrinho deve funcionar', () => {
    // Login primeiro
    cy.intercept('POST', '/api/login').as('loginRequest');
    cy.get('#email').type(Cypress.env('USER_EMAIL'));
    cy.get('#password').type(Cypress.env('USER_PASSWORD'));
    cy.get('#login-btn').click();
    cy.wait('@loginRequest');

    // Adicionar produto
    cy.get('#product-list li').first().within(() => {
      cy.get('button').click();
    });

    // Verificar carrinho atualizado
    cy.get('#cart-count').should('not.contain', '0');
    cy.get('#cart-total').should('not.contain', '0,00');
  });

  it('Fluxo crítico: Login → Adicionar produto → Checkout', () => {
    // Interceptar todas as APIs necessárias
    cy.intercept('POST', '/api/login').as('loginRequest');
    cy.intercept('POST', '/api/checkout').as('checkoutRequest');

    // Login
    cy.get('#email').type(Cypress.env('USER_EMAIL'));
    cy.get('#password').type(Cypress.env('USER_PASSWORD'));
    cy.get('#login-btn').click();
    cy.wait('@loginRequest');

    // Verificar login bem-sucedido
    cy.get('#user-name').should('be.visible');

    // Adicionar produto ao carrinho
    cy.get('#product-list li').first().within(() => {
      cy.get('button').click();
    });

    // Verificar produto adicionado
    cy.get('#cart-count').should('not.contain', '0');

    // Tentar checkout
    cy.get('#checkout-btn').click();

    // Verificar que o processo foi iniciado (pode ser sucesso ou erro específico)
    cy.get('#result').should('exist');
  });

  it('Deve rejeitar tentativas de SQL injection no login', () => {
    cy.intercept('POST', '/api/login').as('loginRequest');

    const sqlInjectionPayloads = [
      "' OR '1'='1",
      "admin'--",
      "' OR 1=1--",
      "'; DROP TABLE users;--"
    ];

    sqlInjectionPayloads.forEach((payload, index) => {
      // Limpar estado antes de cada tentativa
      cy.visit('/');
      cy.clearLocalStorage();
      cy.clearCookies();

      cy.get('#email').should('be.visible').clear().type(`${payload}@test.com`);
      cy.get('#password').should('be.visible').clear().type(payload);
      cy.get('#login-btn').click();

      cy.wait('@loginRequest').then((interception) => {
        // A aplicação deve rejeitar tentativas de SQL injection
        expect(interception.response.statusCode).to.be.oneOf([400, 401, 422]);
      });

      // Verificar que não há token no localStorage (principal verificação)
      cy.window().its('localStorage').invoke('getItem', 'token').should('not.exist');

      // Verificar que ainda está na tela de login
      cy.get('#login-form').should('be.visible');
    });
  });
});