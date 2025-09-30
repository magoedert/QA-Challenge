#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

/**
 * Script para gerar relatórios consolidados dos testes Cypress
 */

const REPORTS_DIR = path.join(__dirname, '..', 'cypress', 'reports');
const OUTPUT_DIR = path.join(__dirname, '..', 'test-reports');
const VIDEOS_DIR = path.join(__dirname, '..', 'cypress', 'videos');
const SCREENSHOTS_DIR = path.join(__dirname, '..', 'cypress', 'screenshots');

// Cores para output no console
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function createDirectory(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    log(`📁 Diretório criado: ${dir}`, 'green');
  }
}

function generateTimestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
}

function mergeJsonReports() {
  log('\n🔄 Mergeando relatórios JSON...', 'cyan');

  if (!fs.existsSync(REPORTS_DIR)) {
    log('❌ Diretório de relatórios não encontrado', 'red');
    return false;
  }

  const jsonFiles = fs.readdirSync(REPORTS_DIR)
    .filter(file => file.endsWith('.json'))
    .map(file => path.join(REPORTS_DIR, file));

  if (jsonFiles.length === 0) {
    log('⚠️  Nenhum arquivo JSON encontrado', 'yellow');
    return false;
  }

  log(`📄 Encontrados ${jsonFiles.length} arquivos JSON`, 'blue');

  try {
    // Usar mochawesome-merge
    const mergedFile = path.join(OUTPUT_DIR, `merged-report-${generateTimestamp()}.json`);
    execSync(`npx mochawesome-merge "${jsonFiles.join('" "')}" > "${mergedFile}"`, { stdio: 'inherit' });

    log(`✅ Relatórios merged com sucesso: ${mergedFile}`, 'green');
    return mergedFile;
  } catch (error) {
    log(`❌ Erro ao fazer merge dos relatórios: ${error.message}`, 'red');
    return false;
  }
}

function generateHtmlReport(mergedJsonFile) {
  if (!mergedJsonFile) return false;

  log('\n🎨 Gerando relatório HTML...', 'cyan');

  try {
    const htmlOutput = path.join(OUTPUT_DIR, 'consolidated-report.html');
    execSync(`npx marge "${mergedJsonFile}" --reportDir "${OUTPUT_DIR}" --reportFilename "consolidated-report" --inline`, { stdio: 'inherit' });

    log(`✅ Relatório HTML gerado: ${htmlOutput}`, 'green');
    return htmlOutput;
  } catch (error) {
    log(`❌ Erro ao gerar HTML: ${error.message}`, 'red');
    return false;
  }
}

function generateSummaryReport() {
  log('\n📊 Gerando relatório resumo...', 'cyan');

  const summaryFile = path.join(OUTPUT_DIR, `test-summary-${generateTimestamp()}.md`);
  const timestamp = new Date().toLocaleString();

  let summary = `# 🧪 Relatório de Testes - Mini E-commerce\n\n`;
  summary += `**Data/Hora:** ${timestamp}\n\n`;

  // Estatísticas de arquivos
  const videoCount = fs.existsSync(VIDEOS_DIR) ? fs.readdirSync(VIDEOS_DIR).length : 0;
  const screenshotCount = fs.existsSync(SCREENSHOTS_DIR) ? fs.readdirSync(SCREENSHOTS_DIR).length : 0;
  const reportCount = fs.existsSync(REPORTS_DIR) ? fs.readdirSync(REPORTS_DIR).filter(f => f.endsWith('.json')).length : 0;

  summary += `## 📈 Estatísticas\n\n`;
  summary += `- 🎥 **Vídeos gerados:** ${videoCount}\n`;
  summary += `- 📸 **Screenshots capturados:** ${screenshotCount}\n`;
  summary += `- 📄 **Relatórios JSON:** ${reportCount}\n\n`;

  // Analisar relatórios JSON para estatísticas
  if (fs.existsSync(REPORTS_DIR)) {
    const jsonFiles = fs.readdirSync(REPORTS_DIR).filter(f => f.endsWith('.json'));
    let totalTests = 0;
    let totalPasses = 0;
    let totalFailures = 0;
    let totalPending = 0;
    let totalDuration = 0;

    jsonFiles.forEach(file => {
      try {
        const reportData = JSON.parse(fs.readFileSync(path.join(REPORTS_DIR, file), 'utf8'));
        if (reportData.stats) {
          totalTests += reportData.stats.tests || 0;
          totalPasses += reportData.stats.passes || 0;
          totalFailures += reportData.stats.failures || 0;
          totalPending += reportData.stats.pending || 0;
          totalDuration += reportData.stats.duration || 0;
        }
      } catch (error) {
        log(`⚠️  Erro ao processar ${file}: ${error.message}`, 'yellow');
      }
    });

    summary += `## 🎯 Resultados dos Testes\n\n`;
    summary += `- ✅ **Testes Aprovados:** ${totalPasses}\n`;
    summary += `- ❌ **Testes Falharam:** ${totalFailures}\n`;
    summary += `- ⏸️ **Testes Pendentes:** ${totalPending}\n`;
    summary += `- 📊 **Total de Testes:** ${totalTests}\n`;
    summary += `- ⏱️ **Duração Total:** ${Math.round(totalDuration / 1000)}s\n\n`;

    // Taxa de sucesso
    const successRate = totalTests > 0 ? ((totalPasses / totalTests) * 100).toFixed(2) : 0;
    summary += `### 🎯 Taxa de Sucesso: ${successRate}%\n\n`;

    if (totalFailures > 0) {
      summary += `### ⚠️ Atenção: ${totalFailures} teste(s) falharam\n\n`;
    }
  }

  summary += `## 📁 Arquivos Gerados\n\n`;
  summary += `- 📈 Relatório consolidado HTML\n`;
  summary += `- 📄 Relatórios JSON individuais\n`;
  summary += `- 🎥 Vídeos dos testes (se habilitado)\n`;
  summary += `- 📸 Screenshots de falhas\n\n`;

  summary += `## 🔍 Como Visualizar\n\n`;
  summary += `1. Abra o arquivo \`consolidated-report.html\` em um navegador\n`;
  summary += `2. Navegue pelos resultados detalhados\n`;
  summary += `3. Verifique vídeos e screenshots para falhas\n\n`;

  summary += `---\n`;
  summary += `*Relatório gerado automaticamente pelo script de relatórios Cypress*\n`;

  fs.writeFileSync(summaryFile, summary);
  log(`✅ Relatório resumo gerado: ${summaryFile}`, 'green');
  return summaryFile;
}

function copyArtifacts() {
  log('\n📦 Copiando artefatos...', 'cyan');

  // Copiar vídeos
  if (fs.existsSync(VIDEOS_DIR)) {
    const videosOutput = path.join(OUTPUT_DIR, 'videos');
    createDirectory(videosOutput);
    execSync(`cp -r "${VIDEOS_DIR}"/* "${videosOutput}/" 2>/dev/null || true`);
    log('🎥 Vídeos copiados', 'green');
  }

  // Copiar screenshots
  if (fs.existsSync(SCREENSHOTS_DIR)) {
    const screenshotsOutput = path.join(OUTPUT_DIR, 'screenshots');
    createDirectory(screenshotsOutput);
    execSync(`cp -r "${SCREENSHOTS_DIR}"/* "${screenshotsOutput}/" 2>/dev/null || true`);
    log('📸 Screenshots copiados', 'green');
  }
}

function cleanOldReports() {
  log('\n🧹 Limpando relatórios antigos...', 'cyan');

  if (fs.existsSync(OUTPUT_DIR)) {
    const files = fs.readdirSync(OUTPUT_DIR);
    const oldFiles = files.filter(file => {
      const filePath = path.join(OUTPUT_DIR, file);
      const stats = fs.statSync(filePath);
      const ageInDays = (Date.now() - stats.mtime.getTime()) / (1000 * 60 * 60 * 24);
      return ageInDays > 7; // Manter apenas últimos 7 dias
    });

    oldFiles.forEach(file => {
      fs.unlinkSync(path.join(OUTPUT_DIR, file));
      log(`🗑️  Removido: ${file}`, 'yellow');
    });

    if (oldFiles.length === 0) {
      log('✨ Nenhum arquivo antigo para limpar', 'green');
    }
  }
}

function main() {
  log('🚀 Iniciando geração de relatórios...', 'bright');

  // Criar diretório de output
  createDirectory(OUTPUT_DIR);

  // Limpar relatórios antigos
  cleanOldReports();

  // Gerar relatórios
  const mergedFile = mergeJsonReports();
  const htmlFile = generateHtmlReport(mergedFile);
  const summaryFile = generateSummaryReport();

  // Copiar artefatos
  copyArtifacts();

  // Sumário final
  log('\n✨ Relatórios gerados com sucesso!', 'bright');
  log('\n📋 Resumo:', 'cyan');

  if (htmlFile) {
    log(`📊 Relatório HTML: ${htmlFile}`, 'green');
  }
  if (summaryFile) {
    log(`📄 Resumo Markdown: ${summaryFile}`, 'green');
  }
  if (mergedFile) {
    log(`🔗 JSON Consolidado: ${mergedFile}`, 'green');
  }

  log(`\n🎯 Para visualizar: abra o arquivo HTML em um navegador`, 'bright');
}

// Executar apenas se chamado diretamente
if (require.main === module) {
  try {
    main();
  } catch (error) {
    log(`❌ Erro fatal: ${error.message}`, 'red');
    process.exit(1);
  }
}

module.exports = {
  generateTimestamp,
  mergeJsonReports,
  generateHtmlReport,
  generateSummaryReport,
  createDirectory
};