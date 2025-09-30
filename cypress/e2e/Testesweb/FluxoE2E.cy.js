/// <reference types="cypress" />

describe('Fluxos Completos de Compra', () => {
  let users;

  before(() => {
    // Carregar dados de usuários do arquivo de fixtures
    cy.fixture('users').then((userData) => {
      users = userData;
    });
  });

  beforeEach(() => {
    cy.visit('/')
    cy.clearLocalStorage()
    cy.clearCookies()

    // Interceptar requisições comuns
    cy.intercept('POST', '/api/login').as('loginRequest')
    cy.intercept('GET', '/api/products').as('getProducts')
    cy.intercept('POST', '/api/validate-coupon').as('validateCoupon')
    cy.intercept('POST', '/api/checkout').as('checkout')
  })

  it('Fluxo 1: Guest → Adicionar produtos → Aplicar cupom → Login → Finalizar compra', () => {
    // === FASE 1: Como Guest - Adicionar produtos ===
    cy.get('#product-list li').should('have.length.greaterThan', 1)

    // Adicionar primeiro produto
    cy.get('#product-list li').eq(0).within(() => {
      cy.get('button').click()
    })

    // Adicionar segundo produto com quantidade 2
    cy.get('#product-list li').eq(1).within(() => {
      cy.get('input[type="number"]').clear().type('2')
      cy.get('button').click()
    })

    // Verificar carrinho atualizado
    cy.get('#cart-count').should('contain', '3')
    cy.get('#cart-total').should('not.contain', '0,00')

    // === FASE 2: Aplicar cupom como Guest ===
    // Simular cupom válido
    cy.intercept('POST', '/api/validate-coupon', {
      statusCode: 200,
      body: {
        valid: true,
        coupon: {
          code: 'DESCONTO15',
          type: 'percentage',
          discount: 15
        }
      }
    }).as('validateValidCoupon')

    cy.get('#coupon-code').type('DESCONTO15')
    cy.get('#apply-coupon-btn').click()
    cy.wait('@validateValidCoupon')

    // Verificar cupom aplicado
    cy.get('#coupon-message').should('contain', 'Cupom aplicado: DESCONTO15')
    cy.get('#discount-line').should('be.visible')
    cy.get('#discount').should('not.contain', '0,00')

    // === FASE 3: Tentar checkout como Guest (deve falhar) ===
    cy.window().then((win) => {
      cy.stub(win, 'alert').as('windowAlert')
    })

    cy.get('#checkout-btn').click()
    cy.get('@windowAlert').should('have.been.calledWith', 'Faça login para finalizar a compra')

    // === FASE 4: Fazer login ===
    cy.get('#email').type(Cypress.env('USER_EMAIL'))
    cy.get('#password').type(Cypress.env('USER_PASSWORD'))
    cy.get('#login-btn').click()
    cy.wait('@loginRequest')

    // Verificar que carrinho e cupom foram mantidos
    cy.get('#cart-count').should('contain', '3')
    cy.get('#coupon-message').should('contain', 'Cupom aplicado: DESCONTO15')

    // === FASE 5: Finalizar compra como usuário logado ===
    cy.intercept('POST', '/api/checkout', {
      statusCode: 200,
      body: {
        success: true,
        orderId: 'ORD-12345',
        total: 254.15,
        discount: 44.85
      }
    }).as('successCheckout')

    cy.get('#checkout-btn').click()
    cy.wait('@successCheckout')

    // Verificar resultado da compra
    cy.get('#result').should('be.visible')
      .and('contain', 'success')
      .and('contain', 'ORD-12345')

    // Verificar que carrinho foi limpo
    cy.get('#cart-count').should('contain', '0')
    cy.get('#coupon-code').should('have.value', '')
  })

  it('Fluxo 2: User sem cupom - Login → Adicionar produtos → Finalizar compra', () => {
    // === FASE 1: Login ===
    cy.get('#email').type(Cypress.env('USER_EMAIL'))
    cy.get('#password').type(Cypress.env('USER_PASSWORD'))
    cy.get('#login-btn').click()
    cy.wait('@loginRequest')

    // === FASE 2: Adicionar produtos ===
    cy.get('#product-list li').eq(0).within(() => {
      cy.get('button').click()
    })

    cy.get('#product-list li').eq(2).within(() => {
      cy.get('input[type="number"]').clear().type('1')
      cy.get('button').click()
    })

    // Verificar carrinho
    cy.get('#cart-count').should('contain', '2')

    // === FASE 3: Finalizar compra sem cupom ===
    cy.intercept('POST', '/api/checkout', {
      statusCode: 200,
      body: {
        success: true,
        orderId: 'ORD-67890',
        total: 498.90,
        discount: 0
      }
    }).as('checkoutNoCoupon')

    cy.get('#checkout-btn').click()
    cy.wait('@checkoutNoCoupon')

    // Verificar resultado
    cy.get('#result').should('contain', 'success')
      .and('contain', 'ORD-67890')

    // Verificar que não houve desconto
    cy.get('#discount').should('contain', '0,00')
  })

  it('Fluxo 3: User com cupom - Login → Adicionar produtos → Aplicar cupom → Finalizar compra', () => {
    // === FASE 1: Login ===
    cy.get('#email').type(Cypress.env('USER_EMAIL'))
    cy.get('#password').type(Cypress.env('USER_PASSWORD'))
    cy.get('#login-btn').click()
    cy.wait('@loginRequest')

    // === FASE 2: Adicionar produtos ===
    cy.get('#product-list li').eq(1).within(() => {
      cy.get('input[type="number"]').clear().type('3')
      cy.get('button').click()
    })

    // === FASE 3: Aplicar cupom ===
    cy.intercept('POST', '/api/validate-coupon', {
      statusCode: 200,
      body: {
        valid: true,
        coupon: {
          code: 'DESCONTO25',
          type: 'fixed',
          discount: 50.00
        }
      }
    }).as('validateFixedCoupon')

    cy.get('#coupon-code').type('DESCONTO25')
    cy.get('#apply-coupon-btn').click()
    cy.wait('@validateFixedCoupon')

    // Verificar cupom aplicado
    cy.get('#coupon-message').should('contain', 'Cupom aplicado: DESCONTO25')
    cy.get('#discount').should('contain', '50,00')

    // === FASE 4: Finalizar compra ===
    cy.intercept('POST', '/api/checkout', {
      statusCode: 200,
      body: {
        success: true,
        orderId: 'ORD-11111',
        total: 248.50,
        discount: 50.00
      }
    }).as('checkoutWithCoupon')

    cy.get('#checkout-btn').click()
    cy.wait('@checkoutWithCoupon')

    // Verificar resultado
    cy.get('#result').should('contain', 'success')
      .and('contain', 'ORD-11111')
  })

  it('Fluxo 4: Admin - Login como admin → Adicionar produtos → Finalizar compra', () => {
    // === FASE 1: Login como admin ===
    cy.get('#email').type(Cypress.env('ADMIN_EMAIL'))
    cy.get('#password').type(Cypress.env('ADMIN_PASSWORD'))
    cy.get('#login-btn').click()
    cy.wait('@loginRequest')

    // Verificar que o login foi bem-sucedido
    cy.get('#user-name').should('be.visible').and('not.be.empty')

    // === FASE 2: Adicionar produtos como admin ===
    cy.get('#product-list li').eq(0).within(() => {
      cy.get('input[type="number"]').clear().type('1')
      cy.get('button').click()
    })

    cy.get('#product-list li').eq(1).within(() => {
      cy.get('input[type="number"]').clear().type('1')
      cy.get('button').click()
    })

    cy.get('#product-list li').eq(2).within(() => {
      cy.get('input[type="number"]').clear().type('1')
      cy.get('button').click()
    })

    // Verificar carrinho com todos os produtos
    cy.get('#cart-count').should('contain', '3')

    // === FASE 3: Aplicar cupom administrativo ===
    cy.intercept('POST', '/api/validate-coupon', {
      statusCode: 200,
      body: {
        valid: true,
        coupon: {
          code: 'ADMIN20',
          type: 'percentage',
          discount: 20
        }
      }
    }).as('validateAdminCoupon')

    cy.get('#coupon-code').type('ADMIN20')
    cy.get('#apply-coupon-btn').click()
    cy.wait('@validateAdminCoupon')

    // === FASE 4: Finalizar compra como admin ===
    cy.intercept('POST', '/api/checkout', {
      statusCode: 200,
      body: {
        success: true,
        orderId: 'ADM-99999',
        total: 478.72,
        discount: 119.68,
        adminOrder: true
      }
    }).as('adminCheckout')

    cy.get('#checkout-btn').click()
    cy.wait('@adminCheckout')

    // Verificar resultado do pedido admin
    cy.get('#result').should('contain', 'success')
      .and('contain', 'ADM-99999')

    // === FASE 5: Verificar limpeza pós-compra ===
    cy.get('#cart-count').should('contain', '0')
    cy.get('#coupon-code').should('have.value', '')
    cy.get('#coupon-message').should('have.text', '')
    cy.get('#discount-line').should('not.be.visible')
  })
})