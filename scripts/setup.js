#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

/**
 * Script de setup para pipeline de testes
 */

// Cores para output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function checkDocker() {
  log('\n🐳 Verificando Docker...', 'cyan');

  try {
    execSync('docker --version', { stdio: 'ignore' });
    execSync('docker-compose --version', { stdio: 'ignore' });
    log('✅ Docker e Docker Compose encontrados', 'green');
    return true;
  } catch (error) {
    log('❌ Docker não encontrado. Instale Docker Desktop:', 'red');
    log('   https://www.docker.com/products/docker-desktop', 'yellow');
    return false;
  }
}

function checkNode() {
  log('\n📦 Verificando Node.js...', 'cyan');

  try {
    const nodeVersion = execSync('node --version', { encoding: 'utf8' }).trim();
    const majorVersion = parseInt(nodeVersion.substring(1).split('.')[0]);

    if (majorVersion >= 16) {
      log(`✅ Node.js ${nodeVersion} (OK)`, 'green');
      return true;
    } else {
      log(`❌ Node.js ${nodeVersion} é muito antigo. Necessário >= 16.x`, 'red');
      return false;
    }
  } catch (error) {
    log('❌ Node.js não encontrado. Instale Node.js >= 16.x', 'red');
    return false;
  }
}

function createDirectories() {
  log('\n📁 Criando diretórios necessários...', 'cyan');

  const directories = [
    'cypress/videos',
    'cypress/screenshots',
    'cypress/reports',
    'test-reports',
    'scripts'
  ];

  directories.forEach(dir => {
    const fullPath = path.join(process.cwd(), dir);
    if (!fs.existsSync(fullPath)) {
      fs.mkdirSync(fullPath, { recursive: true });
      log(`📂 Criado: ${dir}`, 'green');
    } else {
      log(`📂 Existe: ${dir}`, 'yellow');
    }
  });
}

function setupEnvironment() {
  log('\n🔧 Configurando arquivos de ambiente...', 'cyan');

  const envFile = path.join(process.cwd(), 'cypress.env.json');
  const exampleFile = path.join(process.cwd(), 'cypress.env.example.json');

  if (!fs.existsSync(envFile)) {
    if (fs.existsSync(exampleFile)) {
      fs.copyFileSync(exampleFile, envFile);
      log('✅ cypress.env.json criado a partir do exemplo', 'green');
    } else {
      // Criar arquivo padrão
      const defaultEnv = {
        "ADMIN_EMAIL": "admin@test.com",
        "ADMIN_PASSWORD": "admin123",
        "USER_EMAIL": "user@test.com",
        "USER_PASSWORD": "user123",
        "INVALID_EMAIL": "invalid@test.com",
        "NONEXISTENT_EMAIL": "nonexistent@test.com"
      };

      fs.writeFileSync(envFile, JSON.stringify(defaultEnv, null, 2));
      log('✅ cypress.env.json criado com valores padrão', 'green');
    }
  } else {
    log('✅ cypress.env.json já existe', 'yellow');
  }
}

function installDependencies() {
  log('\n📥 Instalando dependências...', 'cyan');

  try {
    log('🔄 Executando npm install...', 'blue');
    execSync('npm install', { stdio: 'inherit' });
    log('✅ Dependências instaladas com sucesso', 'green');
    return true;
  } catch (error) {
    log('❌ Erro ao instalar dependências', 'red');
    return false;
  }
}

function verifyInstallation() {
  log('\n🔍 Verificando instalação do Cypress...', 'cyan');

  try {
    execSync('npx cypress verify', { stdio: 'inherit' });
    log('✅ Cypress verificado com sucesso', 'green');
    return true;
  } catch (error) {
    log('⚠️  Cypress não verificado. Tentando instalar...', 'yellow');

    try {
      execSync('npx cypress install', { stdio: 'inherit' });
      log('✅ Cypress instalado com sucesso', 'green');
      return true;
    } catch (installError) {
      log('❌ Erro ao instalar Cypress', 'red');
      return false;
    }
  }
}

function createGitignore() {
  log('\n📝 Configurando .gitignore...', 'cyan');

  const gitignoreFile = path.join(process.cwd(), '.gitignore');
  const cypressEntries = [
    '# Cypress',
    'cypress.env.json',
    'cypress/videos/',
    'cypress/screenshots/',
    'cypress/reports/',
    'test-reports/',
    '',
    '# Dependencies',
    'node_modules/',
    '',
    '# OS',
    '.DS_Store',
    'Thumbs.db'
  ];

  if (fs.existsSync(gitignoreFile)) {
    const content = fs.readFileSync(gitignoreFile, 'utf8');

    // Verificar se entradas do Cypress já existem
    if (!content.includes('cypress.env.json')) {
      fs.appendFileSync(gitignoreFile, '\n' + cypressEntries.join('\n') + '\n');
      log('✅ Entradas do Cypress adicionadas ao .gitignore', 'green');
    } else {
      log('✅ .gitignore já contém entradas do Cypress', 'yellow');
    }
  } else {
    fs.writeFileSync(gitignoreFile, cypressEntries.join('\n') + '\n');
    log('✅ .gitignore criado com entradas do Cypress', 'green');
  }
}

function displayCommands() {
  log('\n🚀 Setup concluído! Comandos disponíveis:', 'bright');
  log('', 'reset');

  const commands = [
    { cmd: 'npm run cy:open', desc: 'Abrir interface do Cypress' },
    { cmd: 'npm run cy:run', desc: 'Executar todos os testes (headless)' },
    { cmd: 'npm run test', desc: 'Executar testes com aplicação' },
    { cmd: 'npm run test:docker', desc: 'Executar com Docker' },
    { cmd: 'node scripts/generate-reports.js', desc: 'Gerar relatórios' }
  ];

  commands.forEach(({ cmd, desc }) => {
    log(`  ${cmd}`, 'cyan');
    log(`    ${desc}`, 'reset');
    log('', 'reset');
  });

  log('📚 Para mais informações, consulte README-TESTING.md', 'blue');
}

function runHealthCheck() {
  log('\n🏥 Executando health check...', 'cyan');

  try {
    // Verificar se pode executar um teste simples
    log('🧪 Testando execução básica do Cypress...', 'blue');

    // Criar um teste temporário simples
    const tempTest = path.join(process.cwd(), 'cypress', 'e2e', 'health-check.cy.js');
    const testContent = `
describe('Health Check', () => {
  it('should verify Cypress is working', () => {
    cy.log('✅ Cypress is working correctly');
    expect(true).to.be.true;
  });
});
`;

    fs.writeFileSync(tempTest, testContent);

    // Executar teste temporário
    execSync(`npx cypress run --spec "${tempTest}" --reporter min`, { stdio: 'inherit' });

    // Remover teste temporário
    fs.unlinkSync(tempTest);

    log('✅ Health check passou - tudo funcionando!', 'green');
    return true;
  } catch (error) {
    log('⚠️  Health check falhou - pode haver problemas de configuração', 'yellow');
    return false;
  }
}

function main() {
  log('🎯 Configurando Pipeline de Testes do Mini E-commerce', 'bright');
  log('=' .repeat(60), 'blue');

  let allGood = true;

  // Verificações de pré-requisitos
  if (!checkNode()) allGood = false;
  if (!checkDocker()) {
    log('⚠️  Docker não está disponível. Testes locais ainda funcionarão.', 'yellow');
  }

  if (!allGood) {
    log('\n❌ Pré-requisitos não atendidos. Corrija os problemas acima.', 'red');
    process.exit(1);
  }

  // Setup
  createDirectories();
  setupEnvironment();
  createGitignore();

  if (!installDependencies()) {
    log('\n❌ Falha na instalação. Verifique os logs acima.', 'red');
    process.exit(1);
  }

  if (!verifyInstallation()) {
    log('\n❌ Cypress não foi configurado corretamente.', 'red');
    process.exit(1);
  }

  // Health check opcional
  log('\n🔍 Deseja executar um health check? (pode demorar alguns segundos)', 'cyan');
  // Por simplicidade, vamos pular o health check automático
  // runHealthCheck();

  // Sucesso!
  log('\n🎉 Setup concluído com sucesso!', 'bright');
  displayCommands();
}

// Executar se chamado diretamente
if (require.main === module) {
  try {
    main();
  } catch (error) {
    log(`❌ Erro durante setup: ${error.message}`, 'red');
    process.exit(1);
  }
}