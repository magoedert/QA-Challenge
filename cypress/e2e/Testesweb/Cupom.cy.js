/// <reference types="cypress" />

describe('Cupons de Desconto', () => {
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

    // Interceptar requisições de API
    cy.intercept('POST', '/api/login').as('loginRequest')
    cy.intercept('GET', '/api/products').as('getProducts')
    cy.intercept('POST', '/api/cart/add').as('addToCart')
    cy.intercept('POST', '/api/validate-coupon').as('validateCoupon')

    // Fazer login para acessar produtos
    cy.get('#email').type(Cypress.env('USER_EMAIL'))
    cy.get('#password').type(Cypress.env('USER_PASSWORD'))
    cy.get('#login-btn').click()
    cy.wait('@loginRequest')

    // Adicionar produto para aplicar cupom
    cy.get('#product-list li').first().within(() => {
      cy.get('button').click()
    })
  })

  it('deve aplicar cupom valido e calcular desconto', () => {
    // Simular resposta de cupom valido
    cy.intercept('POST', '/api/validate-coupon', {
      statusCode: 200,
      body: {
        valid: true,
        coupon: {
          code: 'DESCONTO10',
          type: 'percentage',
          discount: 10
        }
      }
    }).as('validateValidCoupon')

    // Aplicar cupom
    cy.get('#coupon-code').type('DESCONTO10')
    cy.get('#apply-coupon-btn').click()
    cy.wait('@validateValidCoupon')

    // Verificar mensagem de sucesso
    cy.get('#coupon-message').should('be.visible')
      .and('contain', 'Cupom aplicado: DESCONTO10')
      .and('have.css', 'color', 'rgb(0, 128, 0)') // verde

    // Verificar que o desconto foi aplicado
    cy.get('#discount-line').should('be.visible')
    cy.get('#discount').should('not.contain', '0,00')

    // Verificar que o total final � menor que o subtotal
    cy.get('#subtotal').invoke('text').then((subtotal) => {
      cy.get('#final-total').invoke('text').then((finalTotal) => {
        const subtotalValue = parseFloat(subtotal.replace('R$', '').replace(',', '.'))
        const finalTotalValue = parseFloat(finalTotal.replace('R$', '').replace(',', '.'))
        expect(finalTotalValue).to.be.lessThan(subtotalValue)
      })
    })
  })

  it('deve exibir erro para cupom inv�lido', () => {
    // Simular resposta de cupom inv�lido
    cy.intercept('POST', '/api/validate-coupon', {
      statusCode: 200,
      body: {
        valid: false,
        message: 'Cupom inv�lido ou expirado'
      }
    }).as('validateInvalidCoupon')

    // Tentar aplicar cupom inv�lido
    cy.get('#coupon-code').type('CUPOMINVALIDO')
    cy.get('#apply-coupon-btn').click()
    cy.wait('@validateInvalidCoupon')

    // Verificar mensagem de erro
    cy.get('#coupon-message').should('be.visible')
      .and('contain', 'Cupom inv�lido ou expirado')
      .and('have.css', 'color', 'rgb(255, 0, 0)') // vermelho

    // Verificar que nenhum desconto foi aplicado
    cy.get('#discount-line').should('not.be.visible')
    cy.get('#discount').should('contain', '0,00')
  })

})