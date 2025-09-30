# 🧪 Mini E-commerce - Pipeline de Testes

## 📋 Visão Geral

Este projeto implementa uma pipeline de testes robusta para o Mini E-commerce usando **Cypress** e **Docker**, cobrindo todas as funcionalidades críticas da aplicação.

## 🎯 Funcionalidades Testadas

### ✅ **Funcionalidades Essenciais**
- **Autenticação**: Login/Logout com validação de tokens
- **Catálogo de Produtos**: Listagem e exibição de produtos
- **Carrinho de Compras**: Adicionar/remover produtos
- **Sistema de Cupons**: Validação e aplicação de descontos
- **Checkout**: Finalização de compras
- **APIs Completas**: Todos os endpoints REST
- **Segurança**: Testes contra SQL injection, XSS, etc.

### 🏗️ **Tipos de Testes**
1. **Smoke Tests** - Testes básicos de funcionalidade (inclui SQL injection)
2. **E2E Tests** - Fluxos completos de usuário
3. **API Tests** - Validação de APIs (inclui validação de segurança)

## 🐳 **Executando com Docker**

### Pré-requisitos
- Docker
- Docker Compose

### Comandos Básicos

```bash
# Executar todos os testes com Docker
npm run test:docker

# Executar em modo desenvolvimento (com interface)
npm run test:docker:dev

# Limpar containers e volumes
npm run docker:cleanup
```

### Execução Manual
```bash
# Build e execução completa
docker-compose up --build --abort-on-container-exit

# Apenas testes (app já rodando)
docker-compose run cypress

# Modo interativo para desenvolvimento
docker-compose --profile dev up
```

## 🚀 **Executando Localmente**

### Instalação
```bash
npm install
```

### Configuração de Ambiente
```bash
# Copiar arquivo de exemplo
cp cypress.env.example.json cypress.env.json

# Editar credenciais se necessário
# O arquivo já vem com dados de teste padrão
```

### Execução dos Testes

```bash
# Interface gráfica do Cypress
npm run cy:open

# Executar todos os testes (headless)
npm run cy:run

# Executar em navegadores específicos
npm run cy:run:chrome
npm run cy:run:firefox

# Executar com a aplicação
npm run test
```

### Executar Suites Específicas

```bash
# Smoke tests
npx cypress run --spec "cypress/e2e/Smoke/**/*"

# Testes de API
npx cypress run --spec "cypress/e2e/API/**/*"
```

## 📊 **Relatórios e Evidências**

### Geração Automática
Os testes geram automaticamente:
- 🎥 **Vídeos** de execução
- 📸 **Screenshots** de falhas
- 📊 **Relatórios HTML** detalhados
- 📄 **Logs JSON** estruturados

### Localização dos Arquivos
```
cypress/
├── videos/           # Vídeos dos testes
├── screenshots/      # Screenshots de falhas
└── reports/          # Relatórios JSON
```

### Gerar Relatório Consolidado
```bash
# Executar script de relatórios
node scripts/generate-reports.js
```

Isso criará:
- `test-reports/consolidated-report.html` - Relatório visual completo
- `test-reports/test-summary-{timestamp}.md` - Resumo em Markdown
- Cópias organizadas de vídeos e screenshots

## 🔄 **CI/CD Pipeline**

### GitHub Actions
O projeto inclui workflows completos:

1. **cypress-tests.yml** - Pipeline principal
   - Smoke tests rápidos
   - Testes E2E completos
   - Execução em múltiplos navegadores
   - Testes com Docker
   - Geração de relatórios

2. **nightly-tests.yml** - Testes abrangentes noturnos
   - Testes de stress
   - Múltiplas resoluções
   - Benchmarks de performance
   - Scans de segurança

### Execução Automática
- ✅ **Push/PR** para main/develop
- ⏰ **Agendado** diariamente
- 🔧 **Manual** via GitHub interface

### Artefatos Gerados
- Screenshots de falhas
- Vídeos completos
- Relatórios consolidados
- Logs de performance
- Análises de segurança

## 🛡️ **Validações de Segurança**

### Cobertura Integrada
- **SQL Injection** - Testado nos Smoke Tests
- **API Security** - Validação de tokens e responses nos testes de API
- **Authentication** - Validação completa de autenticação
- **Data Protection** - Verificação de dados sensíveis nas APIs

### Exemplos de Validações
```javascript
// SQL Injection (Smoke Tests)
"' OR '1'='1"
"admin'--"
"'; DROP TABLE users;--"

// API Security (API Tests)
- Passwords não aparecem em responses
- Tokens são validados corretamente
- Logout invalida tokens
```


## 📁 **Estrutura do Projeto**

```
cypress/
├── e2e/
│   ├── Smoke/              # Testes básicos + SQL injection
│   ├── Testesweb/          # Testes web (E2E)
│   └── API/                # Testes de APIs + validações de segurança
├── fixtures/
│   └── users.json          # Dados de teste estruturados
├── support/
│   ├── pages/              # Page Objects (se necessário)
│   ├── testDataFactory.js  # Factory de dados de teste
│   └── e2e.js              # Configurações globais
├── videos/                 # Vídeos dos testes
├── screenshots/            # Screenshots de falhas
└── reports/                # Relatórios gerados

.github/
└── workflows/
    ├── cypress-tests.yml   # Pipeline principal
    └── nightly-tests.yml   # Testes noturnos

scripts/
└── generate-reports.js    # Gerador de relatórios

├── Dockerfile.cypress      # Container para testes
└── docker-compose.yml      # Orquestração completa
```

## 🔧 **Configurações Avançadas**

### Cypress Config
```javascript
// cypress.config.js
{
  retries: { runMode: 2, openMode: 0 },
  video: true,
  screenshotOnRunFailure: true,
  defaultCommandTimeout: 10000,
  requestTimeout: 15000,
  viewportWidth: 1280,
  viewportHeight: 720
}
```

### Docker Compose
- **Healthchecks** para garantir app disponível
- **Networks** isoladas para testes
- **Volumes** para persistir artefatos
- **Profiles** para diferentes ambientes

### Environment Variables
```json
{
  "ADMIN_EMAIL": "admin@test.com",
  "ADMIN_PASSWORD": "admin123",
  "USER_EMAIL": "user@test.com",
  "USER_PASSWORD": "user123"
}
```

## 🎭 **Test Data Factory**

### Uso do Factory
```javascript
// Obter dados de usuário
cy.getTestUser('valid');
cy.getTestUser('admin');
cy.getTestUser('invalid');

// Obter dados de produto
cy.getTestProduct('default');
cy.getTestProduct('expensive');
cy.getTestProduct('outOfStock');

// Mock de APIs
cy.mockApiResponse('login', 'success');
cy.mockApiResponse('products', 'empty');
```

### Tipos de Dados Disponíveis
- **Usuários**: válidos, inválidos, admin, aleatórios
- **Produtos**: default, caros, baratos, sem estoque
- **Cupons**: porcentagem, valor fixo, expirados
- **Carrinho**: único item, múltiplos, alto valor
- **APIs**: responses de sucesso/erro para mock

## 📈 **Monitoramento e Alertas**

### Métricas Coletadas
- Taxa de sucesso dos testes
- Tempo de execução
- Número de falhas
- Performance da aplicação
- Cobertura de testes

### Notificações
- **GitHub** - Comentários automáticos em PRs
- **Artifacts** - Download de evidências
- **Reports** - Relatórios visuais

## 🔍 **Debugging e Troubleshooting**

### Logs Disponíveis
```bash
# Logs do container da aplicação
docker-compose logs app

# Logs dos testes Cypress
docker-compose logs cypress

# Logs específicos
docker-compose logs --follow cypress
```

### Screenshots e Vídeos
- **Automáticos** em todas as falhas
- **Manuais** com `cy.screenshot()`
- **Vídeos** de toda execução
- **Disponíveis** nos artefatos do CI

### Debug Mode
```bash
# Executar com debug
DEBUG=cypress:* npx cypress run

# Modo headed para ver execução
npx cypress run --headed

# Browser específico
npx cypress run --browser chrome --headed
```

## 🚀 **Próximos Passos**

### Melhorias Futuras
1. **Page Object Model** - Se necessário mais organização
2. **Component Testing** - Testes de componentes React
3. **Visual Testing** - Comparação de screenshots
4. **Load Testing** - Testes de carga com múltiplos usuários
5. **Mobile Testing** - Responsividade e PWA

### Integração com Ferramentas
- **Jira** - Rastreamento de bugs
- **Slack** - Notificações de falhas
- **Dashboard** - Métricas em tempo real
- **Monitoring** - APM para produção

## 📞 **Suporte**

### Comandos Úteis
```bash
# Verificar saúde dos containers
docker-compose ps

# Rebuild completo
docker-compose down -v && docker-compose up --build

# Executar teste específico
npx cypress run --spec "cypress/e2e/Login/Login1.cy.js"

# Gerar relatório
node scripts/generate-reports.js
```

### Resolução de Problemas
1. **Porta ocupada**: Verificar se localhost:3001 está livre
2. **Timeout**: Aumentar wait-on-timeout no docker-compose
3. **Falhas intermitentes**: Configurar retries no cypress.config.js
4. **Memória**: Ajustar recursos do Docker se necessário

---

**🎯 Esta pipeline garante qualidade, segurança e performance através de testes automatizados abrangentes com evidências completas para auditoria e análise.**
