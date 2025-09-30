/// <reference types="cypress" />

describe('Carrinho de Compras - Novos Testes', () => {
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
  })

  it('deve adicionar um item ao carrinho com usuário logado', () => {
    // Interceptar requisições
    cy.intercept('POST', '/api/login').as('loginRequest')
    cy.intercept('GET', '/api/products').as('getProducts')

    // Fazer login
    cy.get('#email').type(Cypress.env('USER_EMAIL'))
    cy.get('#password').type(Cypress.env('USER_PASSWORD'))
    cy.get('#login-btn').click()
    cy.wait('@loginRequest')

    // Verificar que produtos carregaram
    cy.get('#product-list li').should('have.length.greaterThan', 0)

    // Adicionar um item ao carrinho
    cy.get('#product-list li').first().within(() => {
      // Capturar informações do produto
      cy.get('.product-info').invoke('text').as('productInfo')
      cy.get('button').click()
    })

    // Verificar contador do carrinho
    cy.get('#cart-count').should('contain', '1')

    // Verificar que o total foi atualizado
    cy.get('#cart-total').should('not.contain', '0,00')

    // Verificar subtotal
    cy.get('#subtotal').should('not.contain', '0,00')

    // Verificar que o produto foi adicionado corretamente
    cy.get('@productInfo').then((productInfo) => {
      const priceMatch = productInfo.match(/R\$ ([\d,]+)/)
      if (priceMatch) {
        const expectedPrice = priceMatch[1]
        cy.get('#cart-total').should('contain', expectedPrice)
      }
    })
  })

  it('deve permitir adicionar itens ao carrinho como visitante mas exigir login no checkout', () => {
    // Não fazer login - permanecer como guest
    cy.get('#product-list li').should('have.length.greaterThan', 0)

    // Adicionar produto como guest
    cy.get('#product-list li').first().within(() => {
      cy.get('button').click()
    })

    // Verificar que o produto foi adicionado ao carrinho
    cy.get('#cart-count').should('contain', '1')
    cy.get('#cart-total').should('not.contain', '0,00')

    // Tentar finalizar compra
    cy.get('#checkout-btn').click()

    // Verificar que aparece mensagem pedindo login ou alerta
    cy.on('window:alert', (text) => {
      expect(text).to.include('login')
    })

    // Verificar que a compra não foi processada
    cy.get('#result').should('be.empty')
  })

  it('deve adicionar múltiplos itens (2 ou mais) ao carrinho', () => {
    // Interceptar requisições
    cy.intercept('POST', '/api/login').as('loginRequest')
    cy.intercept('GET', '/api/products').as('getProducts')

    // Fazer login
    cy.get('#email').type(Cypress.env('USER_EMAIL'))
    cy.get('#password').type(Cypress.env('USER_PASSWORD'))
    cy.get('#login-btn').click()
    cy.wait('@loginRequest')

    // Verificar que produtos carregaram
    cy.get('#product-list li').should('have.length.greaterThan', 1)

    let totalEsperado = 0

    // Adicionar primeiro produto
    cy.get('#product-list li').eq(0).within(() => {
      cy.get('.product-info').invoke('text').then((productInfo) => {
        const priceMatch = productInfo.match(/R\$ ([\d,]+)/)
        if (priceMatch) {
          totalEsperado += parseFloat(priceMatch[1].replace(',', '.'))
        }
      })
      cy.get('button').click()
    })

    // Adicionar segundo produto com quantidade 2
    cy.get('#product-list li').eq(1).within(() => {
      cy.get('.product-info').invoke('text').then((productInfo) => {
        const priceMatch = productInfo.match(/R\$ ([\d,]+)/)
        if (priceMatch) {
          totalEsperado += parseFloat(priceMatch[1].replace(',', '.')) * 2
        }
      })
      cy.get('input[type="number"]').clear().type('2')
      cy.get('button').click()
    })

    // Adicionar terceiro produto
    cy.get('#product-list li').eq(2).within(() => {
      cy.get('.product-info').invoke('text').then((productInfo) => {
        const priceMatch = productInfo.match(/R\$ ([\d,]+)/)
        if (priceMatch) {
          totalEsperado += parseFloat(priceMatch[1].replace(',', '.'))
        }
      })
      cy.get('button').click()
    })

    // Verificar contador total (1 + 2 + 1 = 4 itens)
    cy.get('#cart-count').should('contain', '4')

    // Verificar que todos os produtos foram adicionados
    cy.get('#cart-total').should('not.contain', '0,00')
    cy.get('#subtotal').should('not.contain', '0,00')

    // Verificar que o total calculado está correto
    cy.then(() => {
      cy.get('#cart-total').invoke('text').then((cartTotal) => {
        const total = parseFloat(cartTotal.replace(',', '.'))
        expect(total).to.be.greaterThan(0)
        // Verificar que o total é razoável baseado nos produtos adicionados
        expect(total).to.be.closeTo(totalEsperado, 0.01)
      })
    })

    // Verificar que subtotal e total são iguais (sem desconto)
    cy.get('#subtotal').invoke('text').then((subtotal) => {
      cy.get('#cart-total').invoke('text').then((total) => {
        expect(subtotal).to.equal(total)
      })
    })
  })

  it('não deve aceitar valores negativos na quantidade de produtos', () => {
    // Interceptar requisições
    cy.intercept('POST', '/api/login').as('loginRequest')
    cy.intercept('GET', '/api/products').as('getProducts')

    // Fazer login
    cy.get('#email').type(Cypress.env('USER_EMAIL'))
    cy.get('#password').type(Cypress.env('USER_PASSWORD'))
    cy.get('#login-btn').click()
    cy.wait('@loginRequest')

    // Verificar que produtos carregaram
    cy.get('#product-list li').should('have.length.greaterThan', 0)

    // Tentar inserir valor negativo no campo de quantidade
    cy.get('#product-list li').first().within(() => {
      cy.get('input[type="number"]').clear().type('-5')
      cy.get('button').click()
    })

    // Verificar que o carrinho permanece vazio ou não aceita o valor negativo
    cy.get('#cart-count').should('contain', '0')
    cy.get('#cart-total').should('contain', '0,00')
  })

  it('não deve aceitar valores decimais na quantidade de produtos', () => {
    // Interceptar requisições
    cy.intercept('POST', '/api/login').as('loginRequest')
    cy.intercept('GET', '/api/products').as('getProducts')

    // Fazer login
    cy.get('#email').type(Cypress.env('USER_EMAIL'))
    cy.get('#password').type(Cypress.env('USER_PASSWORD'))
    cy.get('#login-btn').click()
    cy.wait('@loginRequest')

    // Verificar que produtos carregaram
    cy.get('#product-list li').should('have.length.greaterThan', 0)

    // Tentar inserir valor decimal no campo de quantidade (exemplo: 1.5)
    cy.get('#product-list li').first().within(() => {
      cy.get('input[type="number"]').clear().type('1.5')
      cy.get('button').click()
    })

    // Verificar que o carrinho deve arredondar para inteiro ou rejeitar
    // Espera-se que apenas valores inteiros sejam aceitos
    cy.get('#cart-count').then(($count) => {
      const count = $count.text()
      // O contador deve ser um número inteiro (0, 1 ou 2, mas não 1.5)
      expect(parseInt(count)).to.equal(parseFloat(count))
    })

    // Tentar com outro valor decimal (exemplo: 1.74)
    cy.get('#product-list li').eq(1).within(() => {
      cy.get('input[type="number"]').clear().type('1.74')
      cy.get('button').click()
    })

    // Verificar que não aceita valores quebrados
    cy.get('#cart-count').then(($count) => {
      const count = $count.text()
      expect(parseInt(count)).to.equal(parseFloat(count))
    })
  })
})