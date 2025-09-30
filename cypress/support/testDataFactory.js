/**
 * Test Data Factory - Gerenciamento centralizado de dados de teste
 */

class TestDataFactory {
  constructor() {
    this.sequences = new Map();
  }

  // Gerador de sequências únicas
  getSequence(key) {
    if (!this.sequences.has(key)) {
      this.sequences.set(key, 1);
    }
    const current = this.sequences.get(key);
    this.sequences.set(key, current + 1);
    return current;
  }

  // Dados de usuários
  getUserData(type = 'valid', options = {}) {
    const timestamp = Date.now();
    const sequence = this.getSequence('user');

    const templates = {
      valid: {
        email: options.email || Cypress.env('USER_EMAIL'),
        password: options.password || Cypress.env('USER_PASSWORD'),
        name: options.name || 'Usuário Teste',
        role: 'user'
      },

      admin: {
        email: options.email || Cypress.env('ADMIN_EMAIL'),
        password: options.password || Cypress.env('ADMIN_PASSWORD'),
        name: options.name || 'Admin Teste',
        role: 'admin'
      },

      invalid: {
        email: options.email || 'invalid@test.com',
        password: options.password || 'wrongpassword',
        name: 'Usuário Inválido',
        role: 'user'
      },

      random: {
        email: `user${sequence}${timestamp}@test.com`,
        password: `pass${sequence}${timestamp}`,
        name: `User ${sequence}`,
        role: 'user'
      },

      malformed: {
        email: options.email || 'invalid-email-format',
        password: options.password || '',
        name: '',
        role: 'user'
      }
    };

    return { ...templates[type], ...options };
  }

  // Dados de produtos
  getProductData(type = 'default', options = {}) {
    const sequence = this.getSequence('product');

    const templates = {
      default: {
        id: sequence,
        name: `Produto Teste ${sequence}`,
        price: 99.90,
        stock: 10,
        category: 'Categoria Teste',
        description: 'Descrição do produto teste'
      },

      expensive: {
        id: sequence,
        name: `Produto Premium ${sequence}`,
        price: 999.90,
        stock: 5,
        category: 'Premium',
        description: 'Produto de alto valor'
      },

      cheap: {
        id: sequence,
        name: `Produto Barato ${sequence}`,
        price: 9.90,
        stock: 100,
        category: 'Econômico',
        description: 'Produto econômico'
      },

      outOfStock: {
        id: sequence,
        name: `Produto Esgotado ${sequence}`,
        price: 49.90,
        stock: 0,
        category: 'Indisponível',
        description: 'Produto fora de estoque'
      }
    };

    return { ...templates[type], ...options };
  }

  // Dados de cupons
  getCouponData(type = 'percentage', options = {}) {
    const sequence = this.getSequence('coupon');

    const templates = {
      percentage: {
        code: options.code || `DESCONTO${sequence}`,
        type: 'percentage',
        discount: options.discount || 10,
        minValue: options.minValue || 50,
        maxUses: options.maxUses || 100,
        expiresAt: options.expiresAt || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 dias
        active: true
      },

      fixed: {
        code: options.code || `FIXO${sequence}`,
        type: 'fixed',
        discount: options.discount || 25.00,
        minValue: options.minValue || 100,
        maxUses: options.maxUses || 50,
        expiresAt: options.expiresAt || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        active: true
      },

      expired: {
        code: options.code || `EXPIRADO${sequence}`,
        type: 'percentage',
        discount: 15,
        minValue: 0,
        maxUses: 100,
        expiresAt: new Date(Date.now() - 24 * 60 * 60 * 1000), // Ontem
        active: true
      },

      inactive: {
        code: options.code || `INATIVO${sequence}`,
        type: 'percentage',
        discount: 20,
        minValue: 0,
        maxUses: 100,
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        active: false
      },

      maxUsesReached: {
        code: options.code || `ESGOTADO${sequence}`,
        type: 'fixed',
        discount: 30.00,
        minValue: 0,
        maxUses: 0, // Máximo de usos atingido
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        active: true
      }
    };

    return { ...templates[type], ...options };
  }

  // Dados de carrinho
  getCartData(type = 'single', options = {}) {
    const templates = {
      single: {
        items: [
          {
            productId: 1,
            quantity: 1,
            price: 99.90
          }
        ]
      },

      multiple: {
        items: [
          {
            productId: 1,
            quantity: 2,
            price: 99.90
          },
          {
            productId: 2,
            quantity: 1,
            price: 149.90
          },
          {
            productId: 3,
            quantity: 3,
            price: 29.90
          }
        ]
      },

      highValue: {
        items: [
          {
            productId: 1,
            quantity: 1,
            price: 999.90
          },
          {
            productId: 2,
            quantity: 2,
            price: 799.90
          }
        ]
      },

      empty: {
        items: []
      }
    };

    const cart = { ...templates[type], ...options };

    // Calcular totais automaticamente
    cart.subtotal = cart.items.reduce((total, item) => total + (item.price * item.quantity), 0);
    cart.itemCount = cart.items.reduce((count, item) => count + item.quantity, 0);

    return cart;
  }

  // Dados de API para mocking
  getApiMockData(endpoint, scenario = 'success', options = {}) {
    const scenarios = {
      login: {
        success: {
          statusCode: 200,
          body: {
            token: `mock-token-${Date.now()}`,
            user: this.getUserData('valid'),
            expiresIn: 3600
          }
        },
        failure: {
          statusCode: 401,
          body: {
            error: 'Invalid credentials'
          }
        },
        serverError: {
          statusCode: 500,
          body: {
            error: 'Internal server error'
          }
        }
      },

      products: {
        success: {
          statusCode: 200,
          body: {
            items: [
              this.getProductData('default'),
              this.getProductData('expensive'),
              this.getProductData('cheap')
            ]
          }
        },
        empty: {
          statusCode: 200,
          body: {
            items: []
          }
        },
        error: {
          statusCode: 500,
          body: {
            error: 'Failed to load products'
          }
        }
      },

      validateCoupon: {
        valid: {
          statusCode: 200,
          body: {
            valid: true,
            coupon: this.getCouponData('percentage')
          }
        },
        invalid: {
          statusCode: 200,
          body: {
            valid: false,
            message: 'Cupom inválido ou expirado'
          }
        },
        expired: {
          statusCode: 200,
          body: {
            valid: false,
            message: 'Cupom expirado'
          }
        }
      },

      checkout: {
        success: {
          statusCode: 200,
          body: {
            success: true,
            orderId: `ORD-${Date.now()}`,
            total: 299.70,
            discount: 29.97
          }
        },
        failure: {
          statusCode: 400,
          body: {
            error: 'Checkout failed',
            details: 'Insufficient stock'
          }
        },
        paymentError: {
          statusCode: 402,
          body: {
            error: 'Payment processing failed'
          }
        }
      }
    };

    return { ...scenarios[endpoint]?.[scenario], ...options };
  }

  // Dados para validações básicas
  getValidationTestData(type = 'sql_injection') {
    const data = {
      sql_injection: [
        "' OR '1'='1",
        "admin'--",
        "'; DROP TABLE users;--",
        "' UNION SELECT * FROM users--",
        "1' OR 1=1#"
      ],

      invalid_emails: [
        'invalid-email',
        '@domain.com',
        'user@',
        'user@domain',
        'user..name@domain.com',
        'user@domain..com'
      ]
    };

    return data[type] || [];
  }


  // Resetar sequências (útil para testes isolados)
  resetSequences() {
    this.sequences.clear();
  }

  // Gerar dados aleatórios
  generateRandomString(length = 10) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  generateRandomEmail() {
    return `${this.generateRandomString(8)}@test${this.getSequence('email')}.com`;
  }

  generateRandomPrice(min = 10, max = 1000) {
    return Math.round((Math.random() * (max - min) + min) * 100) / 100;
  }
}

// Instância singleton
const testDataFactory = new TestDataFactory();

// Comandos Cypress personalizados
Cypress.Commands.add('getTestUser', (type = 'valid', options = {}) => {
  return cy.wrap(testDataFactory.getUserData(type, options));
});

Cypress.Commands.add('getTestProduct', (type = 'default', options = {}) => {
  return cy.wrap(testDataFactory.getProductData(type, options));
});

Cypress.Commands.add('getTestCoupon', (type = 'percentage', options = {}) => {
  return cy.wrap(testDataFactory.getCouponData(type, options));
});

Cypress.Commands.add('getTestCart', (type = 'single', options = {}) => {
  return cy.wrap(testDataFactory.getCartData(type, options));
});

Cypress.Commands.add('mockApiResponse', (endpoint, scenario = 'success', options = {}) => {
  const mockData = testDataFactory.getApiMockData(endpoint, scenario, options);
  return cy.intercept('**/api/**', mockData);
});

export default testDataFactory;