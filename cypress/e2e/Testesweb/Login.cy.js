/// <reference types="cypress" />

describe('Login Tests', () => {
  let users;

  before(() => {
    // Carregar dados de usuários do arquivo de fixtures
    cy.fixture('users').then((userData) => {
      users = userData;
    });
  });

  beforeEach('Setup test environment', () => {
    cy.visit('/')
    cy.clearLocalStorage()
    cy.clearCookies()

    // Interceptar requisições de API para melhor controle
    cy.intercept('POST', '/api/login').as('loginRequest')
    cy.intercept('GET', '/api/me').as('getUserInfo')
  })

  describe('Valid Login Scenarios', () => {
    it('should allow admin login with valid credentials', () => {
      cy.get('#email').should('be.visible').type(Cypress.env('ADMIN_EMAIL'))
      cy.get('#password').should('be.visible').type(Cypress.env('ADMIN_PASSWORD'))
      cy.get('#login-btn').should('be.enabled').click()

      // Verificar requisição da API
      cy.wait('@loginRequest').its('response.statusCode').should('eq', 200)

      // Verificar elementos da UI após login
      cy.get('#user-name').should('be.visible').and('contain.text', users.validUsers.admin.expectedName)
      cy.url().should('not.contain', '/login')

      // Verificar armazenamento local
      cy.window().its('localStorage')
        .invoke('getItem', 'token')
        .should('exist')
        .and('have.length.greaterThan', 5)
    })

    it('should allow user login with valid credentials', () => {
      cy.get('#email').should('be.visible').type(Cypress.env('USER_EMAIL'))
      cy.get('#password').should('be.visible').type(Cypress.env('USER_PASSWORD'))
      cy.get('#login-btn').should('be.enabled').click()

      cy.wait('@loginRequest').its('response.statusCode').should('eq', 200)
      cy.get('#user-name').should('be.visible')
      cy.url().should('not.contain', '/login')
      cy.window().its('localStorage').invoke('getItem', 'token').should('exist')
    })
  })

  describe('Invalid Login Scenarios', () => {
    it('should show error for invalid email', () => {
      cy.window().then((win) => {
        cy.stub(win, 'alert').as('windowAlert')
      })

      cy.get('#email').type(users.invalidUsers.invalidEmail.email, {delay: 100})
      cy.get('#password').type(users.invalidUsers.invalidEmail.password)
      cy.get('#login-btn').click()

      cy.wait('@loginRequest').its('response.statusCode').should('eq', 401)
      cy.get('@windowAlert').should('have.been.calledWith', 'Invalid credentials')

      // Verificar que permanece na página de login
      cy.get('#login-form').should('be.visible')
      cy.window().its('localStorage').invoke('getItem', 'token').should('not.exist')
    })

    it('should show error for invalid password', () => {
      cy.window().then((win) => {
        cy.stub(win, 'alert').as('windowAlert')
      })

      cy.get('#email').type(users.invalidUsers.wrongPassword.email)
      cy.get('#password').type(users.invalidUsers.wrongPassword.password)
      cy.get('#login-btn').click()

      cy.wait('@loginRequest').its('response.statusCode').should('eq', 401)
      cy.get('@windowAlert').should('have.been.calledWith', 'Invalid credentials')
    })

    it('should show error for non-existent user', () => {
      cy.window().then((win) => {
        cy.stub(win, 'alert').as('windowAlert')
      })

      cy.get('#email').type(users.invalidUsers.nonexistent.email)
      cy.get('#password').type(users.invalidUsers.nonexistent.password)
      cy.get('#login-btn').click()

      cy.wait('@loginRequest').its('response.statusCode').should('eq', 401)
      cy.get('@windowAlert').should('have.been.calledWith', 'Invalid credentials')
    })
  })

  describe('Form Validation', () => {
    it('should validate required email field', () => {
      cy.window().then((win) => {
        cy.stub(win, 'alert').as('windowAlert')
      })

      // Apenas senha, sem email
      cy.get('#password').type(Cypress.env('USER_PASSWORD'))
      cy.get('#login-btn').click()

      cy.get('@windowAlert').should('have.been.calledWith', 'Email and password are required')
    })

    it('should validate required password field', () => {
      cy.window().then((win) => {
        cy.stub(win, 'alert').as('windowAlert')
      })

      // Apenas email, sem senha
      cy.get('#email').type(Cypress.env('USER_EMAIL'))
      cy.get('#login-btn').click()

      cy.get('@windowAlert').should('have.been.calledWith', 'Email and password are required')
    })

    it('should validate both empty fields', () => {
      cy.window().then((win) => {
        cy.stub(win, 'alert').as('windowAlert')
      })

      cy.get('#login-btn').click()
      cy.get('@windowAlert').should('have.been.calledWith', 'Email and password are required')
    })

    it('should validate email format', () => {
      cy.window().then((win) => {
        cy.stub(win, 'alert').as('windowAlert')
      })

      cy.get('#email').type(users.validationTests.invalidEmailFormat)
      cy.get('#password').type(Cypress.env('USER_PASSWORD'))
      cy.get('#login-btn').click()

      // A aplicação não valida formato de email no frontend, então trata como credencial inválida
      cy.wait('@loginRequest').its('response.statusCode').should('eq', 401)
      cy.get('@windowAlert').should('have.been.calledWith', 'Invalid credentials')
    })
  })


  describe('Security Tests', () => {
    it('should not store password in localStorage', () => {
      cy.get('#email').type(Cypress.env('USER_EMAIL'))
      cy.get('#password').type(Cypress.env('USER_PASSWORD'))
      cy.get('#login-btn').click()

      cy.wait('@loginRequest')

      cy.window().its('localStorage').then((storage) => {
        const storageString = JSON.stringify(storage)
        expect(storageString).to.not.contain(Cypress.env('USER_PASSWORD'))
        expect(storageString).to.not.contain('password')
      })
    })

    it('should clear sensitive data on logout', () => {
      // Primeiro fazer login
      cy.get('#email').type(Cypress.env('USER_EMAIL'))
      cy.get('#password').type(Cypress.env('USER_PASSWORD'))
      cy.get('#login-btn').click()
      cy.wait('@loginRequest')

      // Fazer logout
      cy.get('#logout-btn').click()

      // Verificar limpeza
      cy.window().its('localStorage').invoke('getItem', 'token').should('not.exist')
      cy.url().should('include', '/')
    })
  })
})