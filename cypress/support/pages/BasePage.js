class BasePage {
  constructor() {
    this.baseUrl = Cypress.config('baseUrl') || 'http://localhost:3001';
  }

  // Métodos comuns para todas as páginas
  visit(path = '/') {
    cy.visit(path);
    return this;
  }

  clearStorage() {
    cy.clearLocalStorage();
    cy.clearCookies();
    return this;
  }

  getElement(selector) {
    return cy.get(selector);
  }

  clickElement(selector) {
    this.getElement(selector).click();
    return this;
  }

  typeInElement(selector, text) {
    this.getElement(selector).type(text);
    return this;
  }

  verifyElementVisible(selector) {
    this.getElement(selector).should('be.visible');
    return this;
  }

  verifyElementNotVisible(selector) {
    this.getElement(selector).should('not.be.visible');
    return this;
  }

  verifyElementContainsText(selector, text) {
    this.getElement(selector).should('contain.text', text);
    return this;
  }

  verifyUrl(expectedUrl) {
    cy.url().should('eq', expectedUrl);
    return this;
  }

  verifyUrlContains(text) {
    cy.url().should('contain', text);
    return this;
  }

  verifyUrlNotContains(text) {
    cy.url().should('not.contain', text);
    return this;
  }

  // Métodos para interceptar APIs
  setupApiInterceptors(endpoints = []) {
    endpoints.forEach(endpoint => {
      cy.intercept(endpoint.method, endpoint.url).as(endpoint.alias);
    });
    return this;
  }

  waitForApiCall(alias) {
    cy.wait(`@${alias}`);
    return this;
  }

  verifyApiResponse(alias, statusCode = 200) {
    cy.wait(`@${alias}`).its('response.statusCode').should('eq', statusCode);
    return this;
  }

  // Métodos para window alerts
  setupWindowAlert() {
    cy.window().then((win) => {
      cy.stub(win, 'alert').as('windowAlert');
    });
    return this;
  }

  verifyAlert(expectedMessage) {
    cy.get('@windowAlert').should('have.been.calledWith', expectedMessage);
    return this;
  }

  // Métodos para localStorage
  verifyLocalStorageItem(key, expectedValue = null) {
    if (expectedValue) {
      cy.window().its('localStorage').invoke('getItem', key).should('eq', expectedValue);
    } else {
      cy.window().its('localStorage').invoke('getItem', key).should('exist');
    }
    return this;
  }

  verifyLocalStorageItemNotExists(key) {
    cy.window().its('localStorage').invoke('getItem', key).should('not.exist');
    return this;
  }

  // Métodos utilitários
  wait(milliseconds) {
    cy.wait(milliseconds);
    return this;
  }

  reload() {
    cy.reload();
    return this;
  }

  takeScreenshot(name) {
    cy.screenshot(name);
    return this;
  }
}

export default BasePage;