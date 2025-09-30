// Custom commands for testing paths and user journeys

// Login command with different user types
Cypress.Commands.add('loginUser', (email, password) => {
  cy.request({
    method: 'POST',
    url: '/api/login',
    body: {
      email,
      password
    },
    failOnStatusCode: false
  }).then((response) => {
    if (response.status === 200) {
      window.localStorage.setItem('user', JSON.stringify(response.body.user));
      window.localStorage.setItem('token', response.body.token);

      // Redirect based on user role
      if (response.body.user.role === 'admin') {
        cy.visit('/admin/dashboard');
      } else {
        cy.visit('/products');
      }
    }
  });
});

// Tab navigation command for accessibility testing
Cypress.Commands.add('tab', { prevSubject: 'optional' }, (subject, options = {}) => {
  const direction = options.shift ? 'shift+tab' : 'tab';

  if (subject) {
    cy.wrap(subject).focus().trigger('keydown', { key: 'Tab', shiftKey: options.shift });
  } else {
    cy.get('body').trigger('keydown', { key: 'Tab', shiftKey: options.shift });
  }

  return cy.focused();
});

// Wait for page load with performance tracking
Cypress.Commands.add('waitForPageLoad', (timeout = 5000) => {
  cy.window().then((win) => {
    return new Cypress.Promise((resolve) => {
      if (win.document.readyState === 'complete') {
        resolve();
      } else {
        win.addEventListener('load', resolve);
      }
    });
  });
});

// Add product to cart with stock validation
Cypress.Commands.add('addProductToCart', (productIndex = 0, quantity = 1) => {
  cy.get('[data-cy=product-card]').eq(productIndex).within(() => {
    // Check stock availability first
    cy.get('[data-cy=product-stock]').then(($stock) => {
      const stockText = $stock.text();
      const availableStock = parseInt(stockText.match(/\d+/)[0]);

      if (availableStock >= quantity) {
        if (quantity > 1) {
          cy.get('[data-cy=quantity-selector]').clear().type(quantity.toString());
        }
        cy.get('[data-cy=add-to-cart-btn]').click();
      } else {
        throw new Error(`Insufficient stock. Available: ${availableStock}, Requested: ${quantity}`);
      }
    });
  });
});

// Complete checkout flow
Cypress.Commands.add('completeCheckout', (shippingInfo = {}) => {
  const defaultShipping = {
    address: '123 Test Street',
    city: 'Test City',
    zipcode: '12345-678',
    paymentMethod: 'credit-card'
  };

  const shipping = { ...defaultShipping, ...shippingInfo };

  cy.get('#address').type(shipping.address);
  cy.get('#city').type(shipping.city);
  cy.get('#zipcode').type(shipping.zipcode);

  if (shipping.paymentMethod) {
    cy.get('#payment-method').select(shipping.paymentMethod);
  }

  cy.get('[data-cy=place-order-btn]').click();
});

// Apply coupon with validation
Cypress.Commands.add('applyCoupon', (couponCode) => {
  cy.get('[data-cy=coupon-input]').clear().type(couponCode);
  cy.get('[data-cy=apply-coupon-btn]').click();

  // Wait for either success or error response
  cy.get('[data-cy=discount-applied], [data-cy=coupon-error]', { timeout: 5000 })
    .should('be.visible');
});

// Simulate network conditions
Cypress.Commands.add('simulateSlowNetwork', (delay = 2000) => {
  cy.intercept('**/*', (req) => {
    req.reply((res) => {
      res.delay(delay);
    });
  });
});

// Check accessibility compliance
Cypress.Commands.add('checkA11y', (context = null, options = {}) => {
  const defaultOptions = {
    includedImpacts: ['critical', 'serious']
  };

  cy.get(context || 'body').within(() => {
    // Check for basic accessibility requirements
    cy.get('[role="main"]').should('exist');
    cy.get('h1').should('exist');

    // Check for ARIA labels on interactive elements
    cy.get('button, [role="button"]').each(($button) => {
      cy.wrap($button).should('satisfy', ($el) => {
        return $el.attr('aria-label') || $el.text().trim().length > 0;
      });
    });

    // Check for alt text on images
    cy.get('img').each(($img) => {
      cy.wrap($img).should('have.attr', 'alt');
    });
  });
});

// Monitor console errors
Cypress.Commands.add('monitorConsoleErrors', () => {
  cy.window().then((win) => {
    cy.stub(win.console, 'error').as('consoleError');
  });
});

// Assert no console errors
Cypress.Commands.add('assertNoConsoleErrors', () => {
  cy.get('@consoleError').should('not.have.been.called');
});

// Custom command to handle loading states
Cypress.Commands.add('waitForNoLoading', (timeout = 10000) => {
  cy.get('[data-cy*="loading"], [data-cy*="spinner"]', { timeout })
    .should('not.exist');
});

// Simulate user typing with realistic delays
Cypress.Commands.add('typeRealistic', { prevSubject: 'element' }, (subject, text, options = {}) => {
  const defaultOptions = { delay: 100 };
  const typingOptions = { ...defaultOptions, ...options };

  cy.wrap(subject).type(text, typingOptions);
});

// Clear all data and reset state
Cypress.Commands.add('resetAppState', () => {
  cy.clearLocalStorage();
  cy.clearCookies();
  cy.window().then((win) => {
    win.sessionStorage.clear();
  });
});