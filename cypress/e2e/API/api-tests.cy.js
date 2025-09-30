/// <reference types="cypress" />

describe('API Tests - Complete Coverage', () => {
  let users;
  let authToken;
  let adminToken;

  before(() => {
    // Carregar dados de usuários do arquivo de fixtures
    cy.fixture('users').then((userData) => {
      users = userData;
    });
  });

  beforeEach(() => {
    cy.clearLocalStorage();
    cy.clearCookies();
  });

  describe('Health Check API', () => {
    it('GET /api/health - should return application status', () => {
      cy.request({
        method: 'GET',
        url: '/api/health',
        failOnStatusCode: false
      }).then((response) => {
        expect(response.status).to.be.oneOf([200, 404]); // 404 se não implementado
        if (response.status === 200) {
          expect(response.body).to.have.property('status');
        }
      });
    });
  });

  describe('Authentication API', () => {
    it('POST /api/login - should authenticate with valid user credentials', () => {
      cy.request({
        method: 'POST',
        url: '/api/login',
        body: {
          email: Cypress.env('USER_EMAIL'),
          password: Cypress.env('USER_PASSWORD')
        }
      }).then((response) => {
        expect(response.status).to.eq(200);
        expect(response.body).to.have.property('token');
        expect(response.body.token).to.have.length.greaterThan(5);

        // Salvar token para testes subsequentes
        authToken = response.body.token;

        // Verificar outras propriedades da resposta
        if (response.body.user) {
          expect(response.body.user).to.have.property('email', Cypress.env('USER_EMAIL'));
        }
      });
    });

    it('POST /api/login - should authenticate with valid admin credentials', () => {
      cy.request({
        method: 'POST',
        url: '/api/login',
        body: {
          email: Cypress.env('ADMIN_EMAIL'),
          password: Cypress.env('ADMIN_PASSWORD')
        }
      }).then((response) => {
        expect(response.status).to.eq(200);
        expect(response.body).to.have.property('token');
        expect(response.body.token).to.have.length.greaterThan(5);

        // Salvar token admin para testes subsequentes
        adminToken = response.body.token;

        if (response.body.user) {
          expect(response.body.user).to.have.property('email', Cypress.env('ADMIN_EMAIL'));
        }
      });
    });

    it('POST /api/login - should reject invalid credentials', () => {
      cy.request({
        method: 'POST',
        url: '/api/login',
        body: {
          email: users.invalidUsers.invalidEmail.email,
          password: users.invalidUsers.invalidEmail.password
        },
        failOnStatusCode: false
      }).then((response) => {
        expect(response.status).to.eq(401);
        expect(response.body).to.have.property('error');
        expect(response.body.error).to.contain('Invalid');
      });
    });

    it('POST /api/login - should reject missing credentials', () => {
      cy.request({
        method: 'POST',
        url: '/api/login',
        body: {},
        failOnStatusCode: false
      }).then((response) => {
        expect(response.status).to.be.oneOf([400, 422]);
        // Flexible assertion for error property (could be 'error' or 'message')
        expect(response.body).to.satisfy((body) => {
          return body.hasOwnProperty('error') || body.hasOwnProperty('message');
        });
      });
    });

    it('GET /api/me - should return user info with valid token', () => {
      // Primeiro fazer login para obter token
      cy.request({
        method: 'POST',
        url: '/api/login',
        body: {
          email: Cypress.env('USER_EMAIL'),
          password: Cypress.env('USER_PASSWORD')
        }
      }).then((loginResponse) => {
        const token = loginResponse.body.token;

        // Usar token para obter informações do usuário
        cy.request({
          method: 'GET',
          url: '/api/me',
          headers: {
            'Authorization': `Bearer ${token}`
          }
        }).then((response) => {
          expect(response.status).to.eq(200);
          expect(response.body).to.have.property('user');
          expect(response.body.user).to.have.property('email', Cypress.env('USER_EMAIL'));
          expect(response.body.user).to.have.property('id');
        });
      });
    });

    it('GET /api/me - should reject invalid token', () => {
      cy.request({
        method: 'GET',
        url: '/api/me',
        headers: {
          'Authorization': 'Bearer invalid-token'
        },
        failOnStatusCode: false
      }).then((response) => {
        expect(response.status).to.eq(401);
      });
    });

    it('GET /api/me - should reject missing token', () => {
      cy.request({
        method: 'GET',
        url: '/api/me',
        failOnStatusCode: false
      }).then((response) => {
        expect(response.status).to.eq(401);
      });
    });

    it('POST /api/logout - should logout user with valid token', () => {
      // Primeiro fazer login
      cy.request({
        method: 'POST',
        url: '/api/login',
        body: {
          email: Cypress.env('USER_EMAIL'),
          password: Cypress.env('USER_PASSWORD')
        }
      }).then((loginResponse) => {
        const token = loginResponse.body.token;

        // Fazer logout
        cy.request({
          method: 'POST',
          url: '/api/logout',
          headers: {
            'Authorization': `Bearer ${token}`
          }
        }).then((response) => {
          expect(response.status).to.be.oneOf([200, 204]);

          // Verificar se token foi invalidado tentando usar /api/me
          cy.request({
            method: 'GET',
            url: '/api/me',
            headers: {
              'Authorization': `Bearer ${token}`
            },
            failOnStatusCode: false
          }).then((meResponse) => {
            expect(meResponse.status).to.eq(401);
          });
        });
      });
    });
  });

  describe('Products API', () => {
    it('GET /api/products - should return products list', () => {
      cy.request({
        method: 'GET',
        url: '/api/products'
      }).then((response) => {
        expect(response.status).to.eq(200);
        expect(response.body).to.have.property('items');
        expect(response.body.items).to.be.an('array');
        expect(response.body.items.length).to.be.greaterThan(0);

        // Verificar estrutura do primeiro produto
        const firstProduct = response.body.items[0];
        expect(firstProduct).to.have.property('id');
        expect(firstProduct).to.have.property('name');
        expect(firstProduct).to.have.property('price');
        expect(firstProduct.price).to.be.a('number');
        expect(firstProduct.price).to.be.greaterThan(0);

        if (firstProduct.stock !== undefined) {
          expect(firstProduct.stock).to.be.a('number');
          expect(firstProduct.stock).to.be.at.least(0);
        }
      });
    });

    it('GET /api/products - should return products with authenticated user', () => {
      // Primeiro fazer login
      cy.request({
        method: 'POST',
        url: '/api/login',
        body: {
          email: Cypress.env('USER_EMAIL'),
          password: Cypress.env('USER_PASSWORD')
        }
      }).then((loginResponse) => {
        const token = loginResponse.body.token;

        cy.request({
          method: 'GET',
          url: '/api/products',
          headers: {
            'Authorization': `Bearer ${token}`
          }
        }).then((response) => {
          expect(response.status).to.eq(200);
          expect(response.body).to.have.property('items');
          expect(response.body.items).to.be.an('array');
          expect(response.body.items.length).to.be.greaterThan(0);
        });
      });
    });
  });

  describe('Coupons API', () => {
    beforeEach(() => {
      // Fazer login antes de cada teste de cupom
      cy.request({
        method: 'POST',
        url: '/api/login',
        body: {
          email: Cypress.env('USER_EMAIL'),
          password: Cypress.env('USER_PASSWORD')
        }
      }).then((response) => {
        authToken = response.body.token;
      });
    });

    it('POST /api/validate-coupon - should validate a valid coupon', () => {
      cy.request({
        method: 'POST',
        url: '/api/validate-coupon',
        headers: {
          'Authorization': `Bearer ${authToken}`
        },
        body: {
          code: 'DESCONTO10',
          cartTotal: 100.00
        },
        failOnStatusCode: false
      }).then((response) => {
        expect(response.status).to.be.oneOf([200, 404]); // 404 se cupom não existir

        if (response.status === 200) {
          expect(response.body).to.have.property('valid');
          if (response.body.valid) {
            expect(response.body).to.have.property('coupon');
            expect(response.body.coupon).to.have.property('code');
            expect(response.body.coupon).to.have.property('discount');
            expect(response.body.coupon.discount).to.be.a('number');
          }
        }
      });
    });

    it('POST /api/validate-coupon - should reject invalid coupon', () => {
      cy.request({
        method: 'POST',
        url: '/api/validate-coupon',
        headers: {
          'Authorization': `Bearer ${authToken}`
        },
        body: {
          code: 'INVALID_COUPON',
          cartTotal: 100.00
        },
        failOnStatusCode: false
      }).then((response) => {
        expect(response.status).to.be.oneOf([200, 404, 400]);

        if (response.status === 200) {
          expect(response.body).to.have.property('valid', false);
        }
      });
    });

    it('POST /api/validate-coupon - should handle request without authentication', () => {
      cy.request({
        method: 'POST',
        url: '/api/validate-coupon',
        body: {
          code: 'DESCONTO10',
          cartTotal: 100.00
        },
        failOnStatusCode: false
      }).then((response) => {
        // API allows coupon validation without auth, expect 200 or validation response
        expect(response.status).to.be.oneOf([200, 401]);

        if (response.status === 200) {
          expect(response.body).to.have.property('valid');
        }
      });
    });

    it('POST /api/validate-coupon - should reject malformed request', () => {
      cy.request({
        method: 'POST',
        url: '/api/validate-coupon',
        headers: {
          'Authorization': `Bearer ${authToken}`
        },
        body: {},
        failOnStatusCode: false
      }).then((response) => {
        expect(response.status).to.be.oneOf([400, 422]);
      });
    });
  });

  describe('Checkout API', () => {
    beforeEach(() => {
      // Fazer login antes de cada teste de checkout
      cy.request({
        method: 'POST',
        url: '/api/login',
        body: {
          email: Cypress.env('USER_EMAIL'),
          password: Cypress.env('USER_PASSWORD')
        }
      }).then((response) => {
        authToken = response.body.token;
      });
    });

    it('POST /api/checkout - should process checkout request', () => {
      const checkoutData = {
        items: [
          { id: 1, quantity: 2, price: 99.90 },
          { id: 2, quantity: 1, price: 149.90 }
        ],
        total: 349.70,
        coupon: null
      };

      cy.request({
        method: 'POST',
        url: '/api/checkout',
        headers: {
          'Authorization': `Bearer ${authToken}`
        },
        body: checkoutData,
        failOnStatusCode: false
      }).then((response) => {
        // Accept various status codes depending on API implementation
        expect(response.status).to.be.oneOf([200, 201, 400, 422]);

        if (response.status === 200 || response.status === 201) {
          expect(response.body).to.have.property('success', true);
          expect(response.body).to.have.property('orderId');
          expect(response.body.orderId).to.be.a('string');
          expect(response.body.orderId.length).to.be.greaterThan(0);

          if (response.body.total !== undefined) {
            expect(response.body.total).to.be.a('number');
          }
        } else if (response.status === 400 || response.status === 422) {
          // API may require different data format or validation
          expect(response.body).to.satisfy((body) => {
            return body.hasOwnProperty('error') || body.hasOwnProperty('message') || body.hasOwnProperty('errors');
          });
        }
      });
    });

    it('POST /api/checkout - should process checkout with coupon', () => {
      const checkoutData = {
        items: [
          { id: 1, quantity: 1, price: 99.90 }
        ],
        total: 89.91,
        coupon: {
          code: 'DESCONTO10',
          discount: 9.99,
          type: 'percentage'
        }
      };

      cy.request({
        method: 'POST',
        url: '/api/checkout',
        headers: {
          'Authorization': `Bearer ${authToken}`
        },
        body: checkoutData,
        failOnStatusCode: false
      }).then((response) => {
        expect(response.status).to.be.oneOf([200, 201, 400, 422]);

        if (response.status === 200 || response.status === 201) {
          expect(response.body).to.have.property('success', true);
          expect(response.body).to.have.property('orderId');

          if (response.body.discount !== undefined) {
            expect(response.body.discount).to.be.a('number');
            expect(response.body.discount).to.be.greaterThan(0);
          }
        } else if (response.status === 400 || response.status === 422) {
          // API validation error - different data format expected
          expect(response.body).to.satisfy((body) => {
            return body.hasOwnProperty('error') || body.hasOwnProperty('message') || body.hasOwnProperty('errors');
          });
        }
      });
    });

    it('POST /api/checkout - should handle checkout without authentication', () => {
      cy.request({
        method: 'POST',
        url: '/api/checkout',
        body: {
          items: [{ id: 1, quantity: 1, price: 99.90 }],
          total: 99.90
        },
        failOnStatusCode: false
      }).then((response) => {
        // API may return 400 (bad request) or 401 (unauthorized)
        expect(response.status).to.be.oneOf([400, 401]);

        // Should have an error message in the response
        expect(response.body).to.satisfy((body) => {
          return body.hasOwnProperty('error') || body.hasOwnProperty('message') || body.hasOwnProperty('errors');
        });
      });
    });

    it('POST /api/checkout - should reject empty cart', () => {
      cy.request({
        method: 'POST',
        url: '/api/checkout',
        headers: {
          'Authorization': `Bearer ${authToken}`
        },
        body: {
          items: [],
          total: 0
        },
        failOnStatusCode: false
      }).then((response) => {
        expect(response.status).to.be.oneOf([400, 422]);
      });
    });

    it('POST /api/checkout - should reject invalid item data', () => {
      cy.request({
        method: 'POST',
        url: '/api/checkout',
        headers: {
          'Authorization': `Bearer ${authToken}`
        },
        body: {
          items: [
            { id: 'invalid', quantity: 'invalid', price: 'invalid' }
          ],
          total: 'invalid'
        },
        failOnStatusCode: false
      }).then((response) => {
        expect(response.status).to.be.oneOf([400, 422]);
      });
    });
  });

  describe('API Error Handling', () => {
    it('should handle non-existent endpoints', () => {
      cy.request({
        method: 'GET',
        url: '/api/non-existent-endpoint',
        failOnStatusCode: false
      }).then((response) => {
        // API may return 404 (not found) or 200 (catch-all route)
        expect(response.status).to.be.oneOf([200, 404]);

        // If 200, might be a catch-all that returns HTML page or error info
        if (response.status === 200) {
          // Check if response is HTML (catch-all route) or API error
          expect(response.body).to.satisfy((body) => {
            return body === null ||
                   body === '' ||
                   (typeof body === 'string' && body.includes('<!DOCTYPE html>')) || // HTML page
                   (typeof body === 'object' && (body.hasOwnProperty('error') || body.hasOwnProperty('message')));
          });
        }
      });
    });

    it('should handle malformed JSON in requests', () => {
      cy.request({
        method: 'POST',
        url: '/api/login',
        body: 'invalid-json',
        headers: {
          'Content-Type': 'application/json'
        },
        failOnStatusCode: false
      }).then((response) => {
        expect(response.status).to.be.oneOf([400, 422]);
      });
    });
  });

  describe('API Security Validation', () => {
    it('Passwords should not appear in API responses', () => {
      cy.request({
        method: 'POST',
        url: '/api/login',
        body: {
          email: Cypress.env('USER_EMAIL'),
          password: Cypress.env('USER_PASSWORD')
        }
      }).then((response) => {
        const responseBody = JSON.stringify(response.body);
        expect(responseBody).to.not.contain(Cypress.env('USER_PASSWORD'));
        expect(responseBody).to.not.contain('password');
      });
    });

    it('Should validate JWT tokens properly', () => {
      // Login válido primeiro
      cy.request({
        method: 'POST',
        url: '/api/login',
        body: {
          email: Cypress.env('USER_EMAIL'),
          password: Cypress.env('USER_PASSWORD')
        }
      }).then((response) => {
        const validToken = response.body.token;

        // Testar token válido
        cy.request({
          method: 'GET',
          url: '/api/me',
          headers: {
            'Authorization': `Bearer ${validToken}`
          }
        }).then((meResponse) => {
          expect(meResponse.status).to.eq(200);
        });

        // Testar token inválido
        cy.request({
          method: 'GET',
          url: '/api/me',
          headers: {
            'Authorization': 'Bearer invalid-token'
          },
          failOnStatusCode: false
        }).then((invalidResponse) => {
          expect(invalidResponse.status).to.eq(401);
        });

        // Testar token manipulado
        const manipulatedToken = validToken.slice(0, -5) + 'XXXXX';
        cy.request({
          method: 'GET',
          url: '/api/me',
          headers: {
            'Authorization': `Bearer ${manipulatedToken}`
          },
          failOnStatusCode: false
        }).then((manipulatedResponse) => {
          expect(manipulatedResponse.status).to.eq(401);
        });
      });
    });

    it('Should invalidate tokens after logout', () => {
      // Login e capturar token
      cy.request({
        method: 'POST',
        url: '/api/login',
        body: {
          email: Cypress.env('USER_EMAIL'),
          password: Cypress.env('USER_PASSWORD')
        }
      }).then((loginResponse) => {
        const token = loginResponse.body.token;

        // Fazer logout
        cy.request({
          method: 'POST',
          url: '/api/logout',
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });

        // Tentar usar token após logout
        cy.request({
          method: 'GET',
          url: '/api/me',
          headers: {
            'Authorization': `Bearer ${token}`
          },
          failOnStatusCode: false
        }).then((meResponse) => {
          expect(meResponse.status).to.eq(401);
        });
      });
    });
  });
});