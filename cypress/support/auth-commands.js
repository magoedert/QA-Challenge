// Custom Cypress commands for authentication testing

// Override alert to capture alert messages for testing
Cypress.Commands.add('setupAlertSpy', () => {
  cy.window().then((win) => {
    cy.stub(win, 'alert').callsFake((message) => {
      win.alertCalled = message;
    });
  });
});

// Setup authentication state directly
Cypress.Commands.add('setupAuthState', (user = null, token = null) => {
  cy.window().then((win) => {
    win.state.user = user;
    win.state.token = token;
    if (token) {
      win.localStorage.setItem('token', token);
    } else {
      win.localStorage.removeItem('token');
    }
    win.updateAuthUI();
  });
});

// Test login function directly
Cypress.Commands.add('testLogin', (email, password, shouldSucceed = true, responseBody = null) => {
  if (shouldSucceed) {
    const defaultResponse = {
      user: { id: 1, email: email, name: 'Test User' },
      token: 'test-token'
    };
    cy.intercept('POST', '/api/login', {
      statusCode: 200,
      body: responseBody || defaultResponse
    }).as('loginRequest');
  } else {
    cy.intercept('POST', '/api/login', {
      statusCode: 401,
      body: responseBody || { error: 'Invalid credentials' }
    }).as('loginRequest');
  }

  cy.setupAlertSpy();

  cy.get('#email').clear().type(email);
  cy.get('#password').clear().type(password);
  cy.get('form').submit();

  cy.wait('@loginRequest');
});

// Test logout function directly
Cypress.Commands.add('testLogout', (shouldSucceed = true) => {
  if (shouldSucceed) {
    cy.intercept('POST', '/api/logout', {
      statusCode: 200,
      body: {}
    }).as('logoutRequest');
  } else {
    cy.intercept('POST', '/api/logout', { forceNetworkError: true }).as('logoutRequest');
  }

  cy.window().then((win) => {
    win.logout();
  });

  cy.wait('@logoutRequest');
});

// Test checkAuth function directly
Cypress.Commands.add('testCheckAuth', (hasValidToken = true, user = null) => {
  if (hasValidToken) {
    const defaultUser = { id: 1, email: 'test@test.com', name: 'Test User' };
    cy.intercept('GET', '/api/me', {
      statusCode: 200,
      body: { user: user || defaultUser }
    }).as('authRequest');
  } else {
    cy.intercept('GET', '/api/me', {
      statusCode: 401,
      body: { error: 'Invalid token' }
    }).as('authRequest');
  }

  cy.window().then((win) => {
    win.checkAuth();
  });

  if (hasValidToken || cy.window().then(win => win.state.token)) {
    cy.wait('@authRequest');
  }
});

// Verify authentication state
Cypress.Commands.add('verifyAuthState', (expectedUser, expectedToken, expectedUIState = null) => {
  cy.window().then((win) => {
    if (expectedUser === null) {
      expect(win.state.user).to.be.null;
    } else {
      expect(win.state.user).to.deep.equal(expectedUser);
    }

    if (expectedToken === null) {
      expect(win.state.token).to.be.null;
    } else {
      expect(win.state.token).to.equal(expectedToken);
    }
  });

  // Verify localStorage
  if (expectedToken === null) {
    cy.window().its('localStorage').invoke('getItem', 'token').should('be.null');
  } else {
    cy.window().its('localStorage').invoke('getItem', 'token').should('equal', expectedToken);
  }

  // Verify UI state if specified
  if (expectedUIState !== null) {
    if (expectedUIState === 'authenticated') {
      cy.get('#login-form').should('have.css', 'display', 'none');
      cy.get('#user-info').should('have.css', 'display', 'block');
    } else if (expectedUIState === 'unauthenticated') {
      cy.get('#login-form').should('have.css', 'display', 'block');
      cy.get('#user-info').should('have.css', 'display', 'none');
    }
  }
});

// Verify API call was made with correct parameters
Cypress.Commands.add('verifyAPICall', (alias, expectedMethod, expectedHeaders = {}, expectedBody = null) => {
  cy.get(alias).then((interception) => {
    expect(interception.request.method).to.equal(expectedMethod);

    Object.keys(expectedHeaders).forEach(header => {
      expect(interception.request.headers).to.have.property(header.toLowerCase(), expectedHeaders[header]);
    });

    if (expectedBody !== null) {
      expect(interception.request.body).to.deep.equal(expectedBody);
    }
  });
});

// Test form field clearing
Cypress.Commands.add('verifyFormCleared', () => {
  cy.get('#email').should('have.value', '');
  cy.get('#password').should('have.value', '');
});

// Test error handling
Cypress.Commands.add('verifyErrorHandling', (expectedErrorMessage) => {
  cy.window().then((win) => {
    expect(win.alertCalled).to.equal(expectedErrorMessage);
  });
});

// Setup network error intercept
Cypress.Commands.add('interceptNetworkError', (method, url, alias) => {
  cy.intercept(method, url, { forceNetworkError: true }).as(alias);
});

// Setup server error intercept
Cypress.Commands.add('interceptServerError', (method, url, statusCode, alias, errorMessage = null) => {
  cy.intercept(method, url, {
    statusCode: statusCode,
    body: { error: errorMessage || `Server error ${statusCode}` }
  }).as(alias);
});

// Test UI updates
Cypress.Commands.add('testUIUpdate', (isAuthenticated) => {
  cy.window().then((win) => {
    win.updateAuthUI();
  });

  if (isAuthenticated) {
    cy.get('#login-form').should('have.css', 'display', 'none');
    cy.get('#user-info').should('have.css', 'display', 'block');
  } else {
    cy.get('#login-form').should('have.css', 'display', 'block');
    cy.get('#user-info').should('have.css', 'display', 'none');
  }
});

// Performance testing helper
Cypress.Commands.add('measureAuthPerformance', (authFunction) => {
  cy.window().then((win) => {
    const startTime = performance.now();

    return cy.wrap(authFunction(win)).then(() => {
      const endTime = performance.now();
      const duration = endTime - startTime;

      cy.wrap(duration).as('authDuration');

      // Assert reasonable performance (adjust threshold as needed)
      expect(duration).to.be.lessThan(1000); // 1 second max
    });
  });
});

// Test data factory
Cypress.Commands.add('createTestUser', (overrides = {}) => {
  const defaultUser = {
    id: 1,
    email: 'test@example.com',
    name: 'Test User',
    role: 'user'
  };

  cy.wrap({ ...defaultUser, ...overrides }).as('testUser');
});

// Bulk authentication testing
Cypress.Commands.add('testMultipleLogins', (credentials) => {
  credentials.forEach((cred, index) => {
    cy.testLogin(cred.email, cred.password, cred.shouldSucceed, cred.response);

    if (cred.shouldSucceed) {
      cy.verifyAuthState(cred.response.user, cred.response.token, 'authenticated');
      cy.testLogout();
    } else {
      cy.verifyAuthState(null, null, 'unauthenticated');
    }
  });
});

// Test concurrent requests
Cypress.Commands.add('testConcurrentAuth', (requestCount = 3) => {
  cy.intercept('GET', '/api/me', {
    statusCode: 200,
    body: { user: { id: 1, email: 'test@test.com' } },
    delay: 500
  }).as('concurrentAuth');

  cy.window().then((win) => {
    win.state.token = 'test-token';

    // Make multiple concurrent requests
    for (let i = 0; i < requestCount; i++) {
      win.checkAuth();
    }
  });

  // Should handle gracefully
  cy.get('@concurrentAuth').should('have.been.called');
});