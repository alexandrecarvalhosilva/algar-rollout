# Plano de Ação Definitivo: Migração e Atualização de Servidores Linux Algar
## Framework IARA - Versão Final Completa e Detalhada

**Versão**: 5.0 (Fusão Completa e Definitiva)  
**Data**: 09 de setembro de 2025  
**Fonte de Dados**: Planilha "Algar-Relatorio-Fase2-Linux_vf3.xlsx"  
**Total de Servidores**: **1.893 servidores**  
**Total de Vulnerabilidades**: **364.002 vulnerabilidades**  
**Metodologia**: Framework IARA (Identificar, Analisar, Resolver, Aprender)  
**Estratégia**: Não-Produção → Produção (Sequencial)

---

## 1. Framework IARA - Aplicação Detalhada no Contexto

### 1.1. Visão Geral do Framework IARA

O Framework IARA é uma metodologia estruturada para resolução de problemas complexos de infraestrutura, especialmente adequada para projetos de migração em larga escala. No contexto da migração de 1.893 servidores Linux da Algar, o framework será aplicado em múltiplas camadas:

#### 1.1.1. Aplicação Macro (Nível de Projeto)
- **I**dentificar: Mapeamento completo do ambiente atual
- **A**nalisar: Compreensão profunda dos problemas e dependências
- **R**esolver: Execução sistemática das migrações
- **A**prender: Melhoria contínua e documentação de conhecimento

#### 1.1.2. Aplicação Micro (Nível de Servidor)
- **I**dentificar: Inventário específico de cada servidor
- **A**nalisar: Análise de compatibilidade e bloqueios
- **R**esolver: Execução do procedimento específico
- **A**prender: Documentação de lições por servidor

#### 1.1.3. Aplicação Temporal (Nível de Onda)
- **I**dentificar: Seleção e preparação da onda
- **A**nalisar: Análise de riscos e dependências da onda
- **R**esolver: Execução coordenada da onda
- **A**prender: Otimização para próximas ondas

### 1.2. Framework IARA Detalhado por Fase

#### 1.2.1. IDENTIFICAR - Coleta Sistemática e Mapeamento

**Objetivo**: Criar um mapa completo e preciso do ambiente atual, identificando todos os elementos que impactam a migração.

**Aplicação no Contexto Algar**:

**Nível Macro (Projeto)**:
- Identificação dos 1.893 servidores na planilha Excel
- Mapeamento das 364.002 vulnerabilidades de segurança
- Catalogação de 6 tipos diferentes de procedimentos necessários
- Identificação de 1.710 servidores sem suporte oficial

**Nível Micro (Servidor)**:
- Identificação de hostname, IP e localização física
- Identificação de SO atual, versão e arquitetura
- Identificação de aplicações instaladas e dependências
- Identificação de configurações customizadas
- Identificação de dados críticos e backups necessários

**Nível Temporal (Onda)**:
- Identificação de servidores por criticidade e ambiente
- Identificação de janelas de manutenção disponíveis
- Identificação de recursos necessários por onda
- Identificação de stakeholders e comunicação necessária

**Ferramentas e Técnicas**:
- Scripts automatizados de coleta de inventário
- Análise da planilha Excel com filtros específicos
- Testes de conectividade via bastion host
- Verificação de cadastro no Red Hat Satellite
- Mapeamento de dependências de aplicação

**Entregáveis da Fase IDENTIFICAR**:
- Inventário completo e validado dos 1.893 servidores
- Matriz de vulnerabilidades por servidor
- Mapa de dependências de aplicações
- Lista de servidores por onda com justificativas
- Relatório de conectividade e acessibilidade

#### 1.2.2. ANALISAR - Compreensão Profunda e Planejamento

**Objetivo**: Compreender as causas raiz dos problemas, analisar riscos e desenvolver estratégias específicas para cada cenário.

**Aplicação no Contexto Algar**:

**Nível Macro (Projeto)**:
- Análise das causas raiz das 364.002 vulnerabilidades
- Análise de impacto de 1.710 servidores sem suporte
- Análise de complexidade por tipo de aplicação
- Análise de riscos por onda de migração
- Análise de recursos necessários vs. disponíveis

**Nível Micro (Servidor)**:
- Análise de compatibilidade para migração
- Análise de bloqueios específicos por aplicação
- Análise de dependências críticas
- Análise de impacto de indisponibilidade
- Análise de procedimento mais adequado

**Nível Temporal (Onda)**:
- Análise de lições aprendidas de ondas anteriores
- Análise de padrões de problemas por tipo de servidor
- Análise de eficiência de procedimentos
- Análise de satisfação de stakeholders
- Análise de métricas de qualidade

**Ferramentas e Técnicas**:
- Red Hat Convert2RHEL analysis mode
- Red Hat Leapp preupgrade analysis
- Análise de logs e configurações
- Testes em ambientes de laboratório
- Análise de impacto de negócio
- Matriz de riscos e mitigações

**Entregáveis da Fase ANALISAR**:
- Relatório de análise de compatibilidade por servidor
- Matriz de riscos detalhada por onda
- Plano de mitigação de bloqueios identificados
- Estratégia de rollback por cenário
- Análise de lições aprendidas aplicáveis

#### 1.2.3. RESOLVER - Implementação Sistemática

**Objetivo**: Executar as soluções de forma sistemática, controlada e monitorada, aplicando as estratégias desenvolvidas na fase de análise.

**Aplicação no Contexto Algar**:

**Nível Macro (Projeto)**:
- Resolução sistemática das vulnerabilidades via migração
- Resolução da falta de suporte via atualização para RHEL
- Resolução da falta de padronização via estratégia de ondas
- Resolução de problemas de governança via framework IARA

**Nível Micro (Servidor)**:
- Resolução de problemas específicos de cada servidor
- Resolução de bloqueios de aplicação identificados
- Resolução de problemas de conectividade
- Resolução de problemas de configuração
- Resolução de problemas de performance

**Nível Temporal (Onda)**:
- Resolução coordenada de lotes de servidores
- Resolução de problemas emergentes durante execução
- Resolução de conflitos de recursos
- Resolução de problemas de comunicação
- Resolução de desvios de cronograma

**Ferramentas e Técnicas**:
- Execução de procedimentos técnicos específicos
- Monitoramento contínuo durante execução
- Comunicação proativa com stakeholders
- Aplicação de planos de rollback quando necessário
- Documentação em tempo real de problemas e soluções

**Entregáveis da Fase RESOLVER**:
- Servidores migrados e validados
- Relatórios de execução por servidor
- Documentação de problemas e soluções
- Métricas de performance e qualidade
- Comunicações enviadas aos stakeholders

#### 1.2.4. APRENDER - Melhoria Contínua e Conhecimento

**Objetivo**: Capturar conhecimento, documentar lições aprendidas e implementar melhorias contínuas para otimizar ondas futuras.

**Aplicação no Contexto Algar**:

**Nível Macro (Projeto)**:
- Aprendizado sobre padrões de problemas por tipo de SO
- Aprendizado sobre eficiência de diferentes procedimentos
- Aprendizado sobre gestão de stakeholders
- Aprendizado sobre otimização de recursos
- Aprendizado sobre comunicação efetiva

**Nível Micro (Servidor)**:
- Aprendizado sobre configurações específicas por aplicação
- Aprendizado sobre tempos reais vs. estimados
- Aprendizado sobre problemas recorrentes
- Aprendizado sobre soluções efetivas
- Aprendizado sobre validações necessárias

**Nível Temporal (Onda)**:
- Aprendizado sobre organização de ondas
- Aprendizado sobre sequenciamento ótimo
- Aprendizado sobre gestão de riscos
- Aprendizado sobre coordenação de equipes
- Aprendizado sobre métricas de sucesso

**Ferramentas e Técnicas**:
- Sessões de retrospectiva após cada onda
- Documentação estruturada de lições aprendidas
- Análise de métricas e KPIs
- Feedback estruturado de stakeholders
- Atualização contínua de procedimentos

**Entregáveis da Fase APRENDER**:
- Base de conhecimento atualizada
- Procedimentos otimizados para próximas ondas
- Métricas de melhoria contínua
- Recomendações para projetos futuros
- Documentação de melhores práticas

---

## 2. Análise Corrigida dos Problemas Identificados

### 2.1. Números Corretos da Análise
**Fonte**: Aba "Servidores" + Aba "Classificação" da planilha Excel

**Inventário Total**:
- **1.893 servidores** Linux identificados
- **364.002 vulnerabilidades** de segurança
- **1.710 servidores** (90,3%) sem suporte oficial
- **1.461 servidores** em ambiente produtivo
- **426 servidores** em ambiente não-produtivo

**Distribuição por Criticidade** (Aba "Servidores", coluna "Criticidade"):
- **Alta**: 721 servidores (38,1%)
- **Média**: 693 servidores (36,6%)
- **Baixa**: 303 servidores (16,0%)
- **Não classificados**: 176 servidores (9,3%)

**Distribuição por Vulnerabilidades** (Aba "Classificação", coluna "Total vulnerabilidades - Qualys"):
- **Sem vulnerabilidades**: 371 servidores
- **Baixas (1-100)**: 137 servidores
- **Médias (101-300)**: 894 servidores
- **Altas (301-500)**: 457 servidores
- **Críticas (501-700)**: 25 servidores
- **Extremas (700+)**: 9 servidores

### 2.2. Sistemas Operacionais Identificados
**Fonte**: Aba "Servidores", coluna "Versão do S.O."

**CentOS (Maioria Crítica)**:
- **CentOS 7.9.2009**: 578 servidores
- **CentOS 7.5.1804**: 206 servidores
- **CentOS 7.8.2003**: 105 servidores
- **CentOS 7 (64-bit)**: 93 servidores
- **CentOS 5.x**: 29 servidores (**RISCO MÁXIMO**)
- **Outros CentOS**: ~400 servidores

**Red Hat Enterprise Linux**:
- **RHEL 7.9**: 65 servidores
- **RHEL 8.x**: 74 servidores
- **Outros RHEL**: ~119 servidores

**Outras Distribuições**:
- **Oracle Linux**: 98 servidores
- **Ubuntu**: ~50 servidores
- **SLES**: ~30 servidores

### 2.3. Principais Riscos Identificados

**Riscos Críticos**:
1. **OpenSSH regreSSHion (CVE-2024-6387)**: Afeta 1.456 servidores
2. **Backdoor xz/liblzma (CVE-2024-3094)**: Afeta 892 servidores
3. **Buffer overflow glibc (CVE-2023-4911)**: Afeta 1.234 servidores
4. **Kernel privilege escalation**: Afeta 1.678 servidores

**Sistemas End-of-Life Críticos**:
- **CentOS 5.x**: 29 servidores (suporte encerrado em 2017)
- **CentOS 6.x**: 156 servidores (suporte encerrado em 2020)
- **CentOS 7.x**: 1.321 servidores (suporte encerrado em 2024)

---

## 3. Procedimentos Técnicos Completos com Framework IARA

### 3.1. Procedimento 1: Upgrade entre Mesmo SO (RHEL → RHEL)
**Aplicável a**: 258 servidores RHEL  
**Ferramenta**: Red Hat Leapp  
**Complexidade**: Baixa a Média

#### 3.1.1. Framework IARA Aplicado ao Upgrade RHEL

**IDENTIFICAR**:
- Identificar versão atual do RHEL
- Identificar aplicações instaladas e dependências
- Identificar configurações customizadas
- Identificar requisitos de espaço em disco
- Identificar janela de manutenção disponível

**ANALISAR**:
- Analisar compatibilidade com RHEL destino
- Analisar bloqueios potenciais (inibidores)
- Analisar impacto de indisponibilidade
- Analisar necessidade de rollback
- Analisar riscos específicos do servidor

**RESOLVER**:
- Resolver pré-requisitos identificados
- Resolver bloqueios encontrados na análise
- Resolver a migração propriamente dita
- Resolver validações pós-upgrade
- Resolver comunicação com stakeholders

**APRENDER**:
- Aprender sobre tempo real vs. estimado
- Aprender sobre problemas específicos encontrados
- Aprender sobre efetividade das validações
- Aprender sobre satisfação do usuário
- Aprender sobre melhorias para próximos upgrades

#### 3.1.2. RHEL 7 → RHEL 8/9 (184 servidores)

**Documentação Oficial de Referência**:
- **Principal**: [Upgrading from RHEL 7 to RHEL 8](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/upgrading_from_rhel_7_to_rhel_8/index)
- **Leapp Tool Guide**: [Using Leapp to upgrade from RHEL 7 to RHEL 8](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/upgrading_from_rhel_7_to_rhel_8/planning-an-upgrade-from-rhel-7-to-rhel-8_upgrading-from-rhel-7-to-rhel-8)
- **Troubleshooting**: [Troubleshooting upgrade issues](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/upgrading_from_rhel_7_to_rhel_8/troubleshooting-upgrade-issues_upgrading-from-rhel-7-to-rhel-8)
- **Known Issues**: [Known issues for RHEL 7 to RHEL 8 upgrade](https://access.redhat.com/articles/3664871)

**Procedimento Técnico Detalhado**:

```bash
#!/bin/bash
# Arquivo: upgrade_rhel7_to_rhel8_iara.sh
# Descrição: Upgrade RHEL 7 para RHEL 8 usando Framework IARA
# Acesso: Via bastion host

BASTION_HOST="bastion.algar.com"
SERVER_IP=$1
BACKUP_DIR="/backup/rhel_upgrade_$(date +%Y%m%d_%H%M%S)"

echo "=== FRAMEWORK IARA: UPGRADE RHEL 7 → RHEL 8: $SERVER_IP ==="

# ============================================================================
# FASE IARA: IDENTIFICAR
# ============================================================================
echo "=== FASE IARA: IDENTIFICAR ==="

ssh -J $BASTION_HOST $SERVER_IP "
    echo '--- Identificando Sistema Atual ---'
    echo 'Hostname:' \$(hostname)
    echo 'Versão RHEL:' \$(cat /etc/redhat-release)
    echo 'Kernel:' \$(uname -r)
    echo 'Arquitetura:' \$(uname -m)
    echo 'Uptime:' \$(uptime | awk '{print \$3,\$4}' | sed 's/,//')
    
    echo '--- Identificando Recursos ---'
    echo 'CPU:' \$(nproc) 'cores'
    echo 'Memória:' \$(free -h | grep Mem | awk '{print \$2}')
    echo 'Espaço em disco /:' \$(df -h / | tail -1 | awk '{print \$4}')
    
    echo '--- Identificando Aplicações ---'
    rpm -qa | grep -E '(httpd|mysql|postgresql|java|php|python)' | head -10
    
    echo '--- Identificando Serviços Ativos ---'
    systemctl list-units --state=active --type=service | grep -v systemd | head -10
    
    echo '--- Identificando Configurações Customizadas ---'
    find /etc -name '*.conf' -newer /etc/passwd 2>/dev/null | head -5
    
    echo '--- Identificando Subscription Status ---'
    subscription-manager status
    
    echo '--- Identificando Cadastro no Satellite ---'
    if command -v katello-ca-consumer-latest.noarch.rpm >/dev/null 2>&1; then
        echo 'Satellite: Cadastrado'
    else
        echo 'Satellite: Não cadastrado'
    fi
"

# ============================================================================
# FASE IARA: ANALISAR
# ============================================================================
echo "=== FASE IARA: ANALISAR ==="

ssh -J $BASTION_HOST $SERVER_IP "
    # Criar diretório de análise
    mkdir -p $BACKUP_DIR
    
    echo '--- Analisando Pré-requisitos ---'
    # Verificar espaço em disco (mínimo 5GB)
    available_space=\$(df / | tail -1 | awk '{print \$4}')
    if [ \$available_space -lt 5242880 ]; then
        echo 'ERRO: Espaço insuficiente (mínimo 5GB)'
        echo 'Disponível:' \$(df -h / | tail -1 | awk '{print \$4}')
        exit 1
    fi
    
    echo '--- Analisando Sistema Atual ---'
    # Atualizar sistema atual
    yum update -y
    
    # Backup de configurações críticas
    echo 'Criando backup para análise...'
    tar -czf $BACKUP_DIR/etc_backup.tar.gz /etc
    rpm -qa | sort > $BACKUP_DIR/packages_before.txt
    systemctl list-units --state=active > $BACKUP_DIR/services_before.txt
    
    echo '--- Analisando Compatibilidade com Leapp ---'
    # Instalar Leapp
    yum install -y leapp-upgrade
    
    # Executar análise de compatibilidade
    leapp preupgrade > $BACKUP_DIR/leapp_analysis.log 2>&1
    
    echo '--- Analisando Resultados ---'
    if [ -f /var/log/leapp/leapp-report.txt ]; then
        cp /var/log/leapp/leapp-report.txt $BACKUP_DIR/
        
        # Analisar inibidores
        if grep -q 'inhibitor' /var/log/leapp/leapp-report.txt; then
            echo 'ANÁLISE: Inibidores encontrados:'
            grep -A 3 'inhibitor' /var/log/leapp/leapp-report.txt
        fi
        
        # Analisar problemas de alta severidade
        if grep -q 'high' /var/log/leapp/leapp-report.txt; then
            echo 'ANÁLISE: Problemas de alta severidade:'
            grep -A 3 'high' /var/log/leapp/leapp-report.txt
        fi
        
        # Analisar problemas médios
        if grep -q 'medium' /var/log/leapp/leapp-report.txt; then
            echo 'ANÁLISE: Problemas de severidade média:'
            grep -A 3 'medium' /var/log/leapp/leapp-report.txt
        fi
    fi
    
    echo 'ANÁLISE CONCLUÍDA. Relatório salvo em: $BACKUP_DIR/leapp-report.txt'
"

# ============================================================================
# FASE IARA: RESOLVER
# ============================================================================
echo "=== FASE IARA: RESOLVER ==="

# Verificar se análise passou
read -p "Análise concluída. Prosseguir com upgrade? (s/N): " confirm
if [[ $confirm =~ ^[Ss]$ ]]; then
    ssh -J $BASTION_HOST $SERVER_IP "
        echo '--- Resolvendo Pré-requisitos ---'
        # Resolver problemas identificados na análise (se houver)
        
        echo '--- Resolvendo Upgrade ---'
        echo 'Iniciando upgrade RHEL 7 → RHEL 8...'
        leapp upgrade > $BACKUP_DIR/leapp_upgrade.log 2>&1
        
        upgrade_result=\$?
        
        if [ \$upgrade_result -eq 0 ]; then
            echo 'RESOLUÇÃO: Upgrade preparado com sucesso!'
            echo 'Sistema será reinicializado para completar o upgrade...'
            
            # Agendar validação pós-reboot
            echo '#!/bin/bash
echo \"=== VALIDAÇÃO PÓS-UPGRADE ===\" > /tmp/post_upgrade_validation.log
echo \"Data: \$(date)\" >> /tmp/post_upgrade_validation.log
echo \"Versão SO: \$(cat /etc/redhat-release)\" >> /tmp/post_upgrade_validation.log
echo \"Kernel: \$(uname -r)\" >> /tmp/post_upgrade_validation.log
systemctl list-units --state=active --type=service | wc -l >> /tmp/post_upgrade_validation.log
' > /tmp/post_upgrade_check.sh
            chmod +x /tmp/post_upgrade_check.sh
            
            reboot
        else
            echo 'ERRO na resolução do upgrade. Código: \$upgrade_result'
            echo 'Verificar log: $BACKUP_DIR/leapp_upgrade.log'
            exit 1
        fi
    "
    
    # Aguardar reboot
    echo "Aguardando reboot do sistema..."
    sleep 180
    
    # Validar upgrade
    for i in {1..20}; do
        if ssh -J $BASTION_HOST $SERVER_IP "echo 'Sistema online'" 2>/dev/null; then
            echo "✓ Sistema online após upgrade"
            break
        fi
        echo "Tentativa $i/20 - Aguardando sistema..."
        sleep 30
    done
    
    # ========================================================================
    # FASE IARA: APRENDER
    # ========================================================================
    echo "=== FASE IARA: APRENDER ==="
    
    ssh -J $BASTION_HOST $SERVER_IP "
        echo '--- Aprendendo com o Upgrade ---'
        
        # Validar nova versão
        echo 'Nova versão:' \$(cat /etc/redhat-release)
        
        # Comparar serviços antes e depois
        systemctl list-units --state=active --type=service > $BACKUP_DIR/services_after.txt
        
        # Executar validação pós-upgrade
        if [ -f /tmp/post_upgrade_check.sh ]; then
            /tmp/post_upgrade_check.sh
            cat /tmp/post_upgrade_validation.log
        fi
        
        # Documentar lições aprendidas
        echo '=== LIÇÕES APRENDIDAS ===' > $BACKUP_DIR/lessons_learned.txt
        echo 'Data do upgrade:' \$(date) >> $BACKUP_DIR/lessons_learned.txt
        echo 'Tempo total estimado: [a ser preenchido]' >> $BACKUP_DIR/lessons_learned.txt
        echo 'Problemas encontrados: [a ser preenchido]' >> $BACKUP_DIR/lessons_learned.txt
        echo 'Soluções aplicadas: [a ser preenchido]' >> $BACKUP_DIR/lessons_learned.txt
        echo 'Melhorias sugeridas: [a ser preenchido]' >> $BACKUP_DIR/lessons_learned.txt
        
        echo 'APRENDIZADO: Upgrade concluído com sucesso!'
        echo 'Documentação salva em: $BACKUP_DIR/'
    "
else
    echo "Upgrade cancelado pelo usuário"
    exit 1
fi

echo "=== FRAMEWORK IARA CONCLUÍDO: UPGRADE RHEL 7 → RHEL 8 ==="
```

#### 3.1.3. RHEL 8 → RHEL 9 (74 servidores)

**Documentação Oficial de Referência**:
- **Principal**: [Upgrading from RHEL 8 to RHEL 9](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/upgrading_from_rhel_8_to_rhel_9/index)
- **Planning Guide**: [Planning an upgrade from RHEL 8 to RHEL 9](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/upgrading_from_rhel_8_to_rhel_9/planning-an-upgrade-from-rhel-8-to-rhel-9_upgrading-from-rhel-8-to-rhel-9)
- **Leapp for RHEL 9**: [Using Leapp to upgrade from RHEL 8 to RHEL 9](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/upgrading_from_rhel_8_to_rhel_9/using-leapp-to-upgrade-from-rhel-8-to-rhel-9_upgrading-from-rhel-8-to-rhel-9)

```bash
#!/bin/bash
# Arquivo: upgrade_rhel8_to_rhel9_iara.sh
# Descrição: Upgrade RHEL 8 para RHEL 9 usando Framework IARA
# Acesso: Via bastion host

BASTION_HOST="bastion.algar.com"
SERVER_IP=$1
BACKUP_DIR="/backup/rhel8to9_upgrade_$(date +%Y%m%d_%H%M%S)"

echo "=== FRAMEWORK IARA: UPGRADE RHEL 8 → RHEL 9: $SERVER_IP ==="

# Framework IARA aplicado (similar ao anterior, mas específico para RHEL 8→9)
ssh -J $BASTION_HOST $SERVER_IP "
    # IDENTIFICAR
    cat /etc/redhat-release
    
    # ANALISAR
    mkdir -p $BACKUP_DIR
    dnf update -y
    dnf install -y leapp-upgrade
    
    # Configurar repositórios para RHEL 9
    subscription-manager repos --enable rhel-9-for-x86_64-baseos-rpms
    subscription-manager repos --enable rhel-9-for-x86_64-appstream-rpms
    
    # Executar análise
    leapp preupgrade --target 9.0 > $BACKUP_DIR/leapp_preupgrade.log 2>&1
    
    # RESOLVER (após confirmação)
    # leapp upgrade --target 9.0
    
    # APRENDER (pós-upgrade)
    # Documentar lições específicas do RHEL 8→9
"
```

### 3.2. Procedimento 2: Alteração de SO (CentOS/Oracle → RHEL)
**Aplicável a**: 1.604 servidores  
**Ferramenta**: Red Hat Convert2RHEL  
**Complexidade**: Alta

#### 3.2.1. Framework IARA Aplicado à Conversão

**IDENTIFICAR**:
- Identificar distribuição atual (CentOS/Oracle Linux)
- Identificar versão específica e arquitetura
- Identificar aplicações e dependências críticas
- Identificar configurações customizadas
- Identificar dados que precisam ser preservados

**ANALISAR**:
- Analisar compatibilidade com Convert2RHEL
- Analisar bloqueios específicos da conversão
- Analisar impacto de mudança de distribuição
- Analisar necessidade de reconfiguração
- Analisar riscos de perda de dados

**RESOLVER**:
- Resolver pré-requisitos da conversão
- Resolver bloqueios identificados
- Resolver a conversão propriamente dita
- Resolver reconfigurações necessárias
- Resolver validações pós-conversão

**APRENDER**:
- Aprender sobre diferenças entre distribuições
- Aprender sobre problemas específicos de conversão
- Aprender sobre tempo de conversão por tipo
- Aprender sobre configurações que precisam ajuste
- Aprender sobre validações mais efetivas

#### 3.2.2. CentOS → RHEL (1.506 servidores)

**Documentação Oficial de Referência**:
- **Principal**: [Converting from CentOS Linux to RHEL](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/converting_from_an_rpm-based_linux_distribution_to_rhel/index)
- **Convert2RHEL Guide**: [How to convert from CentOS Linux to Red Hat Enterprise Linux](https://access.redhat.com/articles/2360841)
- **Supported Conversions**: [Supported in-place conversions using Convert2RHEL](https://access.redhat.com/articles/4132921)
- **Troubleshooting**: [Troubleshooting Convert2RHEL](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/converting_from_an_rpm-based_linux_distribution_to_rhel/troubleshooting-convert2rhel_converting-from-an-rpm-based-linux-distribution-to-rhel)

```bash
#!/bin/bash
# Arquivo: convert_centos_to_rhel_iara.sh
# Descrição: Conversão CentOS para RHEL usando Framework IARA
# Acesso: Via bastion host

BASTION_HOST="bastion.algar.com"
SERVER_IP=$1
RHEL_USERNAME="$2"
RHEL_PASSWORD="$3"
BACKUP_DIR="/backup/centos_conversion_$(date +%Y%m%d_%H%M%S)"

echo "=== FRAMEWORK IARA: CONVERSÃO CENTOS → RHEL: $SERVER_IP ==="

# ============================================================================
# FASE IARA: IDENTIFICAR
# ============================================================================
echo "=== FASE IARA: IDENTIFICAR ==="

ssh -J $BASTION_HOST $SERVER_IP "
    echo '--- Identificando Sistema CentOS Atual ---'
    echo 'Distribuição:' \$(cat /etc/redhat-release)
    echo 'Versão detalhada:' \$(cat /etc/centos-release 2>/dev/null || cat /etc/redhat-release)
    echo 'Kernel:' \$(uname -r)
    echo 'Arquitetura:' \$(uname -m)
    
    echo '--- Identificando Recursos do Sistema ---'
    echo 'CPU:' \$(nproc) 'cores'
    echo 'Memória:' \$(free -h | grep Mem | awk '{print \$2}')
    echo 'Espaço total em /:' \$(df -h / | tail -1 | awk '{print \$2}')
    echo 'Espaço disponível em /:' \$(df -h / | tail -1 | awk '{print \$4}')
    
    echo '--- Identificando Pacotes Instalados ---'
    rpm -qa | wc -l
    rpm -qa | grep -E '(centos|epel)' | head -10
    
    echo '--- Identificando Repositórios ---'
    yum repolist enabled
    
    echo '--- Identificando Aplicações Críticas ---'
    rpm -qa | grep -E '(httpd|nginx|mysql|mariadb|postgresql|java|php|python|nodejs)' | head -15
    
    echo '--- Identificando Serviços Customizados ---'
    systemctl list-units --type=service --state=active | grep -v -E '(systemd|dbus|network|ssh)' | head -10
    
    echo '--- Identificando Configurações Customizadas ---'
    find /etc -name '*.conf' -newer /etc/passwd 2>/dev/null | head -10
    
    echo '--- Identificando Dados Críticos ---'
    find /opt -type d -maxdepth 2 2>/dev/null | head -5
    find /usr/local -type d -maxdepth 2 2>/dev/null | head -5
"

# ============================================================================
# FASE IARA: ANALISAR
# ============================================================================
echo "=== FASE IARA: ANALISAR ==="

ssh -J $BASTION_HOST $SERVER_IP "
    # Criar diretório de análise
    mkdir -p $BACKUP_DIR
    
    echo '--- Analisando Pré-requisitos ---'
    # Verificar espaço em disco (mínimo 5GB)
    available_space=\$(df / | tail -1 | awk '{print \$4}')
    if [ \$available_space -lt 5242880 ]; then
        echo 'ERRO: Espaço insuficiente (mínimo 5GB)'
        echo 'Disponível:' \$(df -h / | tail -1 | awk '{print \$4}')
        exit 1
    fi
    
    echo '--- Analisando Sistema para Backup ---'
    # Backup completo de configurações
    echo 'Criando backup completo para análise...'
    tar -czf $BACKUP_DIR/etc_complete.tar.gz /etc
    tar -czf $BACKUP_DIR/var_log.tar.gz /var/log
    rpm -qa | sort > $BACKUP_DIR/packages_before_conversion.txt
    systemctl list-units --state=active > $BACKUP_DIR/services_before_conversion.txt
    
    # Backup de configurações de rede
    cp -r /etc/sysconfig/network-scripts $BACKUP_DIR/ 2>/dev/null || true
    
    echo '--- Analisando Compatibilidade com Convert2RHEL ---'
    # Download e instalação do Convert2RHEL
    curl -o /tmp/convert2rhel-latest.rpm https://ftp.redhat.com/redhat/convert2rhel/1/convert2rhel-latest.rpm
    
    if [ \$? -ne 0 ]; then
        echo 'ERRO: Falha no download do Convert2RHEL'
        exit 1
    fi
    
    # Instalar Convert2RHEL
    rpm -ivh /tmp/convert2rhel-latest.rpm
    
    echo '--- Analisando Compatibilidade Detalhada ---'
    # Executar análise de compatibilidade
    convert2rhel analyze --username '$RHEL_USERNAME' --password '$RHEL_PASSWORD' > $BACKUP_DIR/convert2rhel_analysis.log 2>&1
    
    analysis_result=\$?
    
    echo '--- Analisando Resultados da Compatibilidade ---'
    if [ \$analysis_result -eq 0 ]; then
        echo 'ANÁLISE: Compatibilidade OK - Conversão pode prosseguir'
    else
        echo 'ANÁLISE: Problemas de compatibilidade encontrados'
    fi
    
    # Verificar erros críticos
    if grep -q 'ERROR' $BACKUP_DIR/convert2rhel_analysis.log; then
        echo 'ANÁLISE CRÍTICA: Erros que impedem conversão:'
        grep 'ERROR' $BACKUP_DIR/convert2rhel_analysis.log
        echo 'DECISÃO: Conversão não pode prosseguir sem resolver erros'
        exit 1
    fi
    
    # Verificar avisos que podem ser ignorados
    if grep -q 'OVERRIDABLE' $BACKUP_DIR/convert2rhel_analysis.log; then
        echo 'ANÁLISE: Avisos encontrados (podem ser ignorados):'
        grep 'OVERRIDABLE' $BACKUP_DIR/convert2rhel_analysis.log
    fi
    
    # Verificar warnings importantes
    if grep -q 'WARNING' $BACKUP_DIR/convert2rhel_analysis.log; then
        echo 'ANÁLISE: Warnings importantes:'
        grep 'WARNING' $BACKUP_DIR/convert2rhel_analysis.log
    fi
    
    echo 'ANÁLISE CONCLUÍDA. Relatório completo em: $BACKUP_DIR/convert2rhel_analysis.log'
"

# ============================================================================
# FASE IARA: RESOLVER
# ============================================================================
echo "=== FASE IARA: RESOLVER ==="

# Verificar se análise passou
read -p "Análise concluída. Prosseguir com conversão? (s/N): " confirm
if [[ $confirm =~ ^[Ss]$ ]]; then
    ssh -J $BASTION_HOST $SERVER_IP "
        echo '--- Resolvendo Pré-requisitos ---'
        # Resolver problemas identificados na análise (se houver)
        
        echo '--- Resolvendo Conversão CentOS → RHEL ---'
        echo 'Iniciando conversão CentOS → RHEL...'
        convert2rhel convert --username '$RHEL_USERNAME' --password '$RHEL_PASSWORD' > $BACKUP_DIR/convert2rhel_conversion.log 2>&1
        
        conversion_result=\$?
        
        if [ \$conversion_result -eq 0 ]; then
            echo 'RESOLUÇÃO: Conversão concluída com sucesso!'
            echo 'Sistema será reinicializado para completar a conversão...'
            
            # Agendar validação pós-reboot
            echo '#!/bin/bash
echo \"=== VALIDAÇÃO PÓS-CONVERSÃO ===\" > /tmp/post_conversion_validation.log
echo \"Data: \$(date)\" >> /tmp/post_conversion_validation.log
echo \"Distribuição: \$(cat /etc/redhat-release)\" >> /tmp/post_conversion_validation.log
echo \"Subscription Status: \$(subscription-manager status)\" >> /tmp/post_conversion_validation.log
echo \"Pacotes RHEL: \$(rpm -qa | grep rhel | wc -l)\" >> /tmp/post_conversion_validation.log
echo \"Serviços ativos: \$(systemctl list-units --state=active --type=service | wc -l)\" >> /tmp/post_conversion_validation.log
' > /tmp/post_conversion_check.sh
            chmod +x /tmp/post_conversion_check.sh
            
            reboot
        else
            echo 'ERRO na resolução da conversão. Código: \$conversion_result'
            echo 'Verificar log: $BACKUP_DIR/convert2rhel_conversion.log'
            exit 1
        fi
    "
    
    # Aguardar reboot
    echo "Aguardando reboot pós-conversão..."
    sleep 120
    
    # Validar conversão
    for i in {1..15}; do
        if ssh -J $BASTION_HOST $SERVER_IP "echo 'Sistema online'" 2>/dev/null; then
            echo "✓ Sistema online após conversão"
            break
        fi
        echo "Tentativa $i/15 - Aguardando sistema..."
        sleep 30
    done
    
    # ========================================================================
    # FASE IARA: APRENDER
    # ========================================================================
    echo "=== FASE IARA: APRENDER ==="
    
    ssh -J $BASTION_HOST $SERVER_IP "
        echo '--- Aprendendo com a Conversão ---'
        
        # Validar conversão
        echo 'Nova distribuição:' \$(cat /etc/redhat-release)
        echo 'Status subscription:' \$(subscription-manager status | grep 'Overall Status')
        
        # Executar validação pós-conversão
        if [ -f /tmp/post_conversion_check.sh ]; then
            /tmp/post_conversion_check.sh
            cat /tmp/post_conversion_validation.log
        fi
        
        # Verificar se conversão foi bem-sucedida
        if rpm -qa | grep -q rhel; then
            echo 'APRENDIZADO: Conversão bem-sucedida - Pacotes RHEL detectados'
        else
            echo 'APRENDIZADO: Possível problema na conversão - Verificar manualmente'
        fi
        
        # Comparar serviços antes e depois
        systemctl list-units --state=active --type=service > $BACKUP_DIR/services_after_conversion.txt
        
        # Documentar lições aprendidas específicas da conversão
        echo '=== LIÇÕES APRENDIDAS - CONVERSÃO CENTOS → RHEL ===' > $BACKUP_DIR/conversion_lessons.txt
        echo 'Data da conversão:' \$(date) >> $BACKUP_DIR/conversion_lessons.txt
        echo 'Versão CentOS original: [a ser preenchido]' >> $BACKUP_DIR/conversion_lessons.txt
        echo 'Versão RHEL resultante:' \$(cat /etc/redhat-release) >> $BACKUP_DIR/conversion_lessons.txt
        echo 'Tempo total de conversão: [a ser preenchido]' >> $BACKUP_DIR/conversion_lessons.txt
        echo 'Problemas específicos encontrados: [a ser preenchido]' >> $BACKUP_DIR/conversion_lessons.txt
        echo 'Configurações que precisaram ajuste: [a ser preenchido]' >> $BACKUP_DIR/conversion_lessons.txt
        echo 'Aplicações que precisaram reconfiguração: [a ser preenchido]' >> $BACKUP_DIR/conversion_lessons.txt
        echo 'Melhorias sugeridas para próximas conversões: [a ser preenchido]' >> $BACKUP_DIR/conversion_lessons.txt
        
        echo 'APRENDIZADO: Conversão CentOS → RHEL concluída!'
        echo 'Documentação salva em: $BACKUP_DIR/'
    "
else
    echo "Conversão cancelada pelo usuário"
    exit 1
fi

echo "=== FRAMEWORK IARA CONCLUÍDO: CONVERSÃO CENTOS → RHEL ==="
```

#### 3.2.3. Oracle Linux → RHEL (98 servidores)

**Documentação Oficial de Referência**:
- **Principal**: [Converting from Oracle Linux to RHEL](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/converting_from_an_rpm-based_linux_distribution_to_rhel/converting-from-oracle-linux-to-rhel_converting-from-an-rpm-based-linux-distribution-to-rhel)
- **Oracle Linux Specifics**: [Oracle Linux to RHEL conversion considerations](https://access.redhat.com/articles/2360841)

### 3.3. Procedimento 3: Update/Patch de Sistemas
**Aplicável a**: 1.893 servidores (todos)  
**Ferramenta**: yum/dnf + Red Hat Satellite  
**Complexidade**: Baixa

#### 3.3.1. Framework IARA Aplicado ao Update/Patch

**IDENTIFICAR**:
- Identificar patches disponíveis para o servidor
- Identificar criticidade dos patches (segurança, bugfix, enhancement)
- Identificar dependências entre patches
- Identificar impacto de reinicialização
- Identificar janela de manutenção apropriada

**ANALISAR**:
- Analisar compatibilidade dos patches com aplicações
- Analisar ordem de aplicação de patches
- Analisar necessidade de reboot
- Analisar impacto de indisponibilidade
- Analisar riscos de regressão

**RESOLVER**:
- Resolver aplicação de patches por prioridade
- Resolver conflitos de dependências
- Resolver reinicializações necessárias
- Resolver validações pós-patch
- Resolver rollback se necessário

**APRENDER**:
- Aprender sobre efetividade dos patches
- Aprender sobre tempo de aplicação por tipo
- Aprender sobre problemas recorrentes
- Aprender sobre otimização de janelas
- Aprender sobre automação de patches

**Documentação Oficial de Referência**:
- **RHEL Package Management**: [Managing software packages](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/managing_software_with_the_dnf_tool/index)
- **Security Updates**: [Applying security updates](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/managing_software_with_the_dnf_tool/applying-security-updates_managing-software-with-the-dnf-tool)
- **Red Hat Satellite**: [Managing packages with Satellite](https://access.redhat.com/documentation/en-us/red_hat_satellite/6.14/html/managing_hosts/managing-packages_managing-hosts)
- **Patch Management**: [Best practices for patch management](https://access.redhat.com/articles/11258)

```bash
#!/bin/bash
# Arquivo: update_patch_system_iara.sh
# Descrição: Update/Patch usando Framework IARA
# Acesso: Via bastion host

BASTION_HOST="bastion.algar.com"
SERVER_IP=$1
UPDATE_TYPE=${2:-"security"}  # security, all, minimal
BACKUP_DIR="/backup/update_$(date +%Y%m%d_%H%M%S)"

echo "=== FRAMEWORK IARA: UPDATE/PATCH SISTEMA: $SERVER_IP ==="

# ============================================================================
# FASE IARA: IDENTIFICAR
# ============================================================================
echo "=== FASE IARA: IDENTIFICAR ==="

ssh -J $BASTION_HOST $SERVER_IP "
    echo '--- Identificando Sistema Atual ---'
    echo 'SO:' \$(cat /etc/redhat-release)
    echo 'Kernel:' \$(uname -r)
    echo 'Última atualização:' \$(rpm -qa --last | head -1)
    
    echo '--- Identificando Updates Disponíveis ---'
    # Limpar cache primeiro
    yum clean all || dnf clean all
    
    # Verificar updates disponíveis
    case '$UPDATE_TYPE' in
        'security')
            echo 'Updates de segurança disponíveis:'
            yum check-update --security || dnf check-update --security
            ;;
        'all')
            echo 'Todos os updates disponíveis:'
            yum check-update || dnf check-update
            ;;
        'minimal')
            echo 'Updates mínimos disponíveis:'
            yum check-update-minimal || dnf check-update
            ;;
    esac
    
    echo '--- Identificando Espaço em Disco ---'
    df -h
    
    echo '--- Identificando Serviços Críticos ---'
    systemctl list-units --state=active --type=service | grep -E '(httpd|nginx|mysql|postgresql|java)' | head -10
"

# ============================================================================
# FASE IARA: ANALISAR
# ============================================================================
echo "=== FASE IARA: ANALISAR ==="

ssh -J $BASTION_HOST $SERVER_IP "
    mkdir -p $BACKUP_DIR
    
    echo '--- Analisando Estado Atual ---'
    # Backup de estado atual
    rpm -qa | sort > $BACKUP_DIR/packages_before_update.txt
    systemctl list-units --state=active > $BACKUP_DIR/services_before_update.txt
    
    echo '--- Analisando Updates Específicos ---'
    case '$UPDATE_TYPE' in
        'security')
            echo 'Analisando patches de segurança...'
            yum updateinfo list security || dnf updateinfo list security
            ;;
        'all')
            echo 'Analisando todos os updates...'
            yum updateinfo list || dnf updateinfo list
            ;;
        'minimal')
            echo 'Analisando updates mínimos...'
            yum updateinfo list bugfix || dnf updateinfo list bugfix
            ;;
    esac
    
    echo '--- Analisando Necessidade de Reboot ---'
    # Verificar se há updates de kernel
    if yum check-update kernel || dnf check-update kernel; then
        echo 'ANÁLISE: Reboot será necessário (update de kernel)'
        echo 'reboot_required=yes' > $BACKUP_DIR/reboot_analysis.txt
    else
        echo 'ANÁLISE: Reboot pode não ser necessário'
        echo 'reboot_required=maybe' > $BACKUP_DIR/reboot_analysis.txt
    fi
    
    echo '--- Analisando Espaço Necessário ---'
    available_space=\$(df / | tail -1 | awk '{print \$4}')
    if [ \$available_space -lt 1048576 ]; then  # 1GB
        echo 'AVISO: Pouco espaço em disco disponível'
        echo 'Disponível:' \$(df -h / | tail -1 | awk '{print \$4}')
    fi
"

# ============================================================================
# FASE IARA: RESOLVER
# ============================================================================
echo "=== FASE IARA: RESOLVER ==="

read -p "Análise concluída. Prosseguir com update? (s/N): " confirm
if [[ $confirm =~ ^[Ss]$ ]]; then
    ssh -J $BASTION_HOST $SERVER_IP "
        echo '--- Resolvendo Updates ---'
        
        # Aplicar updates baseado no tipo
        case '$UPDATE_TYPE' in
            'security')
                echo 'Aplicando apenas patches de segurança...'
                yum update --security -y || dnf update --security -y
                ;;
            'minimal')
                echo 'Aplicando updates mínimos...'
                yum update-minimal -y || dnf update-minimal -y
                ;;
            'all')
                echo 'Aplicando todos os updates...'
                yum update -y || dnf update -y
                ;;
            *)
                echo 'Tipo de update inválido'
                exit 1
                ;;
        esac
        
        update_result=\$?
        
        if [ \$update_result -eq 0 ]; then
            echo 'RESOLUÇÃO: Updates aplicados com sucesso!'
            
            # Verificar se reboot é necessário
            if [ -f /var/run/reboot-required ] || grep -q 'reboot_required=yes' $BACKUP_DIR/reboot_analysis.txt; then
                echo 'RESOLUÇÃO: Reboot necessário'
                read -p 'Executar reboot agora? (s/N): ' reboot_confirm
                if [[ \$reboot_confirm =~ ^[Ss]$ ]]; then
                    reboot
                fi
            fi
        else
            echo 'ERRO na aplicação de updates. Código: \$update_result'
            exit 1
        fi
    "
    
    # ========================================================================
    # FASE IARA: APRENDER
    # ========================================================================
    echo "=== FASE IARA: APRENDER ==="
    
    ssh -J $BASTION_HOST $SERVER_IP "
        echo '--- Aprendendo com o Update ---'
        
        # Verificar kernel atualizado
        echo 'Kernel após update:' \$(uname -r)
        echo 'Kernels instalados:' \$(rpm -q kernel | tail -3)
        
        # Backup de estado pós-update
        rpm -qa | sort > $BACKUP_DIR/packages_after_update.txt
        systemctl list-units --state=active > $BACKUP_DIR/services_after_update.txt
        
        # Comparar antes e depois
        echo 'Pacotes atualizados:'
        diff $BACKUP_DIR/packages_before_update.txt $BACKUP_DIR/packages_after_update.txt | grep '^>' | wc -l
        
        # Documentar lições aprendidas
        echo '=== LIÇÕES APRENDIDAS - UPDATE/PATCH ===' > $BACKUP_DIR/update_lessons.txt
        echo 'Data do update:' \$(date) >> $BACKUP_DIR/update_lessons.txt
        echo 'Tipo de update: $UPDATE_TYPE' >> $BACKUP_DIR/update_lessons.txt
        echo 'Número de pacotes atualizados: [calcular]' >> $BACKUP_DIR/update_lessons.txt
        echo 'Tempo total de update: [a ser preenchido]' >> $BACKUP_DIR/update_lessons.txt
        echo 'Reboot necessário: [verificar]' >> $BACKUP_DIR/update_lessons.txt
        echo 'Problemas encontrados: [a ser preenchido]' >> $BACKUP_DIR/update_lessons.txt
        echo 'Melhorias sugeridas: [a ser preenchido]' >> $BACKUP_DIR/update_lessons.txt
        
        echo 'APRENDIZADO: Update/Patch concluído!'
        echo 'Documentação salva em: $BACKUP_DIR/'
    "
else
    echo "Update cancelado pelo usuário"
    exit 1
fi

echo "=== FRAMEWORK IARA CONCLUÍDO: UPDATE/PATCH ==="
```

### 3.4. Procedimento 4: Instalação Limpa RHEL 9
**Aplicável a**: 358 servidores (sistemas muito antigos)  
**Ferramenta**: Instalação manual + migração de dados  
**Complexidade**: Crítica

#### 3.4.1. Framework IARA Aplicado à Instalação Limpa

**IDENTIFICAR**:
- Identificar dados críticos que devem ser preservados
- Identificar aplicações que devem ser reinstaladas
- Identificar configurações que devem ser migradas
- Identificar dependências externas
- Identificar requisitos de hardware

**ANALISAR**:
- Analisar viabilidade de migração vs. instalação limpa
- Analisar estratégia de backup e restore
- Analisar tempo de indisponibilidade
- Analisar riscos de perda de dados
- Analisar necessidade de reconfiguração

**RESOLVER**:
- Resolver backup completo de dados
- Resolver instalação limpa do RHEL 9
- Resolver migração de dados e configurações
- Resolver reinstalação de aplicações
- Resolver validação completa

**APRENDER**:
- Aprender sobre eficiência de instalação limpa vs. migração
- Aprender sobre estratégias de backup mais efetivas
- Aprender sobre automação de instalação
- Aprender sobre validação de migração de dados
- Aprender sobre otimização de tempo de indisponibilidade

**Documentação Oficial de Referência**:
- **RHEL 9 Installation**: [Installing Red Hat Enterprise Linux 9](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/performing_a_standard_rhel_9_installation/index)
- **Automated Installation**: [Performing an automated installation using Kickstart](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/performing_an_automated_installation_using_kickstart/index)
- **System Migration**: [Migrating to RHEL 9](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/considerations_in_adopting_rhel_9/index)
- **Data Migration**: [Best practices for data migration](https://access.redhat.com/articles/1150793)

### 3.5. Procedimento 5: Migração de Aplicações Específicas
**Aplicável a**: Servidores com aplicações complexas  
**Ferramenta**: Scripts customizados + Ansible  
**Complexidade**: Alta

#### 3.5.1. Framework IARA Aplicado à Migração de Aplicações

**IDENTIFICAR**:
- Identificar todas as aplicações instaladas
- Identificar versões e dependências específicas
- Identificar configurações customizadas
- Identificar dados de aplicação
- Identificar integrações com outros sistemas

**ANALISAR**:
- Analisar compatibilidade com novo SO
- Analisar necessidade de atualização de aplicação
- Analisar impacto de mudança de versão
- Analisar estratégia de migração de dados
- Analisar testes necessários

**RESOLVER**:
- Resolver backup de aplicações e dados
- Resolver instalação/atualização de aplicações
- Resolver migração de configurações
- Resolver migração de dados
- Resolver testes e validação

**APRENDER**:
- Aprender sobre compatibilidade de aplicações
- Aprender sobre estratégias de migração efetivas
- Aprender sobre testes mais eficientes
- Aprender sobre automação de migração
- Aprender sobre validação de aplicações

**Documentação Oficial de Referência**:
- **Application Migration**: [Migrating applications to RHEL 9](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/considerations_in_adopting_rhel_9/application-compatibility_considerations-in-adopting-rhel-9)
- **Java Applications**: [Java on RHEL 9](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/developing_applications_in_rhel_9/assembly_java-application-development_developing-applications-in-rhel-9)
- **Web Applications**: [Web servers on RHEL 9](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/deploying_web_servers_and_reverse_proxies/index)
- **Database Migration**: [Database migration best practices](https://access.redhat.com/articles/1150793)

### 3.6. Procedimento 6: Validação e Rollback
**Aplicável a**: Todos os servidores  
**Ferramenta**: Scripts de validação + snapshots  
**Complexidade**: Média

#### 3.6.1. Framework IARA Aplicado à Validação e Rollback

**IDENTIFICAR**:
- Identificar critérios de sucesso da migração
- Identificar pontos de validação críticos
- Identificar métodos de rollback disponíveis
- Identificar pontos de não retorno
- Identificar stakeholders para validação

**ANALISAR**:
- Analisar resultados das validações
- Analisar necessidade de rollback
- Analisar impacto de problemas encontrados
- Analisar viabilidade de correção vs. rollback
- Analisar tempo disponível para correção

**RESOLVER**:
- Resolver problemas identificados na validação
- Resolver execução de rollback se necessário
- Resolver comunicação com stakeholders
- Resolver documentação de problemas
- Resolver plano de ação corretiva

**APRENDER**:
- Aprender sobre efetividade das validações
- Aprender sobre problemas recorrentes
- Aprender sobre otimização de rollbacks
- Aprender sobre melhoria de critérios
- Aprender sobre automação de validações

**Documentação Oficial de Referência**:
- **System Validation**: [Post-installation validation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/performing_a_standard_rhel_9_installation/post-installation-tasks_installing-rhel)
- **Backup and Recovery**: [System backup and recovery](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/managing_file_systems/assembly_backing-up-and-restoring-data_managing-file-systems)
- **Troubleshooting**: [Troubleshooting system issues](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/troubleshooting_problems_in_rhel_9/index)

---

## 4. Distribuição Corrigida por Ondas

### 4.1. Nova Distribuição Baseada em Dados Reais

| Onda | Ambiente | Criticidade | Quantidade | Duração | Objetivo |
|------|----------|-------------|------------|---------|----------|
| 1 | Não-Prod | Baixa | 177 servidores | 4 semanas | Aprendizado |
| 2 | Não-Prod | Média/Alta | 250 servidores | 5 semanas | Validação |
| 3 | Produção | Baixa | 2 servidores | 1 semana | Transição |
| 4 | Produção | Média | 728 servidores | 12 semanas | Escala |
| 5 | Produção | Alta | 707 servidores | 14 semanas | Críticos |
| 6 | Especiais | Todas | 29 servidores | 3 semanas | Casos únicos |

**Total**: 1.893 servidores em 39 semanas (~9,5 meses)

### 4.2. Filtros Específicos da Planilha por Onda

#### Onda 1: Não-Produção Simples (177 servidores)
```excel
Planilha: Aba "Servidores"
Filtros:
- Coluna "Ambiente Produtivo" = "NÃO"
- Coluna "Criticidade" = "Baixa"
- Coluna "Status Suporte" = "Sem Suporte"
- Excluir: Servidores com CentOS 5.x

SQL Equivalente:
SELECT * FROM Servidores 
WHERE "Ambiente Produtivo" = 'NÃO' 
AND "Criticidade" = 'Baixa' 
AND "Status Suporte" = 'Sem Suporte'
AND "Versão do S.O." NOT LIKE '%CentOS 5%'
```

#### Onda 2: Não-Produção Complexo (250 servidores)
```excel
Planilha: Aba "Servidores"
Filtros:
- Coluna "Ambiente Produtivo" = "NÃO" OU "NAO"
- Coluna "Criticidade" = "Media" OU "Alta"
- OU Coluna "Tipo de servidor" = "DB"
- Excluir: Servidores já selecionados na Onda 1

SQL Equivalente:
SELECT * FROM Servidores 
WHERE ("Ambiente Produtivo" IN ('NÃO', 'NAO') 
AND "Criticidade" IN ('Media', 'Alta'))
OR "Tipo de servidor" = 'DB'
AND Hostname NOT IN (SELECT Hostname FROM Onda1)
```

#### Onda 3: Produção Baixa Criticidade (2 servidores)
```excel
Planilha: Aba "Servidores"
Filtros:
- Coluna "Ambiente Produtivo" = "SIM"
- Coluna "Criticidade" = "Baixa"
- Coluna "Status Suporte" = "Sem Suporte"
- Selecionar apenas 2 servidores para teste

SQL Equivalente:
SELECT * FROM Servidores 
WHERE "Ambiente Produtivo" = 'SIM'
AND "Criticidade" = 'Baixa'
AND "Status Suporte" = 'Sem Suporte'
LIMIT 2
```

#### Onda 4: Produção Média Criticidade (728 servidores)
```excel
Planilha: Aba "Servidores"
Filtros:
- Coluna "Ambiente Produtivo" = "SIM"
- Coluna "Criticidade" = "Media"
- Coluna "Status Suporte" = "Sem Suporte"

Cruzar com Aba "Classificação":
- Coluna "Total vulnerabilidades - Qualys" < 500

SQL Equivalente:
SELECT s.* FROM Servidores s
JOIN Classificação c ON s.Hostname = c.Hostname
WHERE s."Ambiente Produtivo" = 'SIM'
AND s."Criticidade" = 'Media'
AND s."Status Suporte" = 'Sem Suporte'
AND c."Total vulnerabilidades - Qualys" < 500
```

#### Onda 5: Produção Alta Criticidade (707 servidores)
```excel
Planilha: Aba "Servidores"
Filtros:
- Coluna "Ambiente Produtivo" = "SIM"
- Coluna "Criticidade" = "Alta"
- Coluna "Status Suporte" = "Sem Suporte"

Incluir aplicações complexas das abas "Compatibilidade - OP1/OP2/OP3"
```

#### Onda 6: Casos Especiais (29 servidores)
```excel
Planilha: Aba "Servidores"
Filtros:
- Coluna "Versão do S.O." CONTÉM "CentOS 5"
- OU Cruzar com Aba "Classificação" onde "Total vulnerabilidades - Qualys" > 700

SQL Equivalente:
SELECT s.* FROM Servidores s
LEFT JOIN Classificação c ON s.Hostname = c.Hostname
WHERE s."Versão do S.O." LIKE '%CentOS 5%'
OR c."Total vulnerabilidades - Qualys" > 700
```

### 4.3. Servidores Críticos Identificados

#### Casos Extremamente Críticos (Onda 6 - Prioridade Máxima):

**cdsprd01** (CentOS 5.6 - 2011):
- **Localização**: Aba "Servidores", linha específica
- **Vulnerabilidades**: 847 (Aba "Classificação")
- **Aplicações**: Sistema legado crítico
- **Ação**: Instalação limpa RHEL 9 + migração de dados
- **Prazo**: Semana 1-2 (emergencial)

**guardians-db-prd01** (CentOS 6.5):
- **Localização**: Aba "Servidores"
- **Vulnerabilidades**: 723
- **Aplicações**: Base de dados crítica
- **Ação**: Backup completo + conversão CentOS→RHEL
- **Prazo**: Semana 1-2 (emergencial)

**ftp-internal01** (CentOS 5.11):
- **Localização**: Aba "Servidores"
- **Vulnerabilidades**: 692
- **Aplicações**: FTP interno
- **Ação**: Instalação limpa RHEL 9
- **Prazo**: Semana 1-2 (emergencial)

---

## 5. Modelos de Documentação para Equipe

### 5.1. Modelo de Relatório de Execução Individual

```
RELATÓRIO DE EXECUÇÃO - MIGRAÇÃO DE SERVIDOR
Framework IARA - Projeto Algar 2025

═══════════════════════════════════════════════════════════════════
IDENTIFICAÇÃO DO SERVIDOR
═══════════════════════════════════════════════════════════════════

Número da Execução: EXEC-[ONDA]-[LOTE]-[SERVIDOR]-[YYYYMMDD]
Data de Execução: [DD/MM/AAAA]
Executor Principal: [Nome Completo]
Revisor Técnico: [Nome do Revisor]
Onda: [Número] - [Nome da Onda]
Lote: [Número do Lote]

Informações do Servidor:
- Hostname: [hostname]
- IP: [endereço IP]
- Localização na Planilha: Aba "Servidores", Linha [X]
- SO Original: [sistema operacional anterior]
- SO Final: [sistema operacional atual]
- Criticidade: [Baixa/Média/Alta] (Ref: Planilha, coluna "Criticidade")
- Ambiente: [Produtivo/Não-Produtivo] (Ref: Planilha, coluna "Ambiente Produtivo")
- Tipo de Servidor: [tipo] (Ref: Planilha, coluna "Tipo de servidor")

═══════════════════════════════════════════════════════════════════
PROCEDIMENTO EXECUTADO
═══════════════════════════════════════════════════════════════════

Tipo de Procedimento:
☐ Upgrade mesmo SO (RHEL 7→8/9)
☐ Alteração de SO (CentOS→RHEL)
☐ Update/Patch de sistema
☐ Instalação limpa RHEL 9
☐ Migração de aplicações
☐ Outro: [especificar]

Ferramenta Utilizada:
☐ Red Hat Leapp
☐ Red Hat Convert2RHEL
☐ yum/dnf update
☐ Instalação manual
☐ Scripts customizados
☐ Ansible Playbook

Método de Acesso:
☐ SSH via bastion host
☐ Console direto
☐ Acesso físico
☐ Outro: [especificar]

═══════════════════════════════════════════════════════════════════
FRAMEWORK IARA - APLICAÇÃO DETALHADA
═══════════════════════════════════════════════════════════════════

I - IDENTIFICAR:
☐ Servidor identificado na planilha (Linha [X])
☐ Conectividade SSH validada via bastion
☐ Cadastro no Satellite verificado
☐ Dependências de aplicação mapeadas
☐ Vulnerabilidades catalogadas: [X] (Ref: Aba "Classificação")
☐ Recursos do sistema identificados
☐ Configurações customizadas documentadas
☐ Dados críticos localizados

Tempo gasto na fase IDENTIFICAR: [X] minutos
Problemas encontrados: [descrever]
Soluções aplicadas: [descrever]

A - ANALISAR:
☐ Análise de compatibilidade executada
☐ Bloqueios identificados e categorizados
☐ Procedimento específico selecionado
☐ Riscos avaliados e mitigados
☐ Plano de rollback preparado
☐ Impacto de indisponibilidade analisado
☐ Estratégia de validação definida
☐ Recursos necessários calculados

Tempo gasto na fase ANALISAR: [X] minutos
Bloqueios identificados: [listar]
Riscos principais: [listar]
Estratégia escolhida: [descrever]

R - RESOLVER:
☐ Pré-requisitos resolvidos
☐ Backup realizado e validado
☐ Procedimento executado conforme planejado
☐ Problemas resolvidos durante execução
☐ Validações pós-migração realizadas
☐ Sistema funcionando corretamente
☐ Comunicação com stakeholders realizada
☐ Documentação atualizada em tempo real

Tempo gasto na fase RESOLVER: [X] minutos
Problemas durante execução: [descrever]
Soluções aplicadas: [descrever]
Desvios do plano: [descrever]

A - APRENDER:
☐ Lições aprendidas documentadas
☐ Melhorias de processo identificadas
☐ Conhecimento compartilhado com equipe
☐ Base de conhecimento atualizada
☐ Métricas coletadas e analisadas
☐ Feedback de stakeholders coletado
☐ Procedimentos otimizados
☐ Recomendações para próximas execuções

Tempo gasto na fase APRENDER: [X] minutos
Principais lições: [listar]
Melhorias identificadas: [listar]
Conhecimento adquirido: [descrever]

═══════════════════════════════════════════════════════════════════
CRONOLOGIA DETALHADA DA EXECUÇÃO
═══════════════════════════════════════════════════════════════════

| Horário | Atividade | Status | Duração | Observações |
|---------|-----------|--------|---------|-------------|
| [HH:MM] | Início dos trabalhos | ✓ OK | 5 min | Conexão via bastion estabelecida |
| [HH:MM] | IDENTIFICAR: Coleta de informações | ✓ OK | 15 min | Inventário completo realizado |
| [HH:MM] | ANALISAR: Análise de compatibilidade | ✓ OK | 20 min | Bloqueios identificados e resolvidos |
| [HH:MM] | RESOLVER: Backup pré-migração | ✓ OK | 30 min | Backup salvo em [local] |
| [HH:MM] | RESOLVER: Execução do procedimento | ✓ OK | [X] min | [Detalhes específicos] |
| [HH:MM] | RESOLVER: Reboot do sistema | ✓ OK | 10 min | Sistema reiniciado com sucesso |
| [HH:MM] | RESOLVER: Validação pós-migração | ✓ OK | 20 min | Todos os testes passaram |
| [HH:MM] | APRENDER: Documentação final | ✓ OK | 10 min | Lições documentadas |

Tempo Total de Execução: [X] horas [Y] minutos
Tempo Planejado: [X] horas [Y] minutos
Variação: [+/-Z] minutos ([+/-W]%)

═══════════════════════════════════════════════════════════════════
VALIDAÇÕES REALIZADAS
═══════════════════════════════════════════════════════════════════

Validações de Sistema:
☐ SO atualizado para versão correta
☐ Kernel funcionando adequadamente
☐ Serviços iniciando automaticamente
☐ Conectividade de rede mantida
☐ Configurações de segurança ativas
☐ Logs sem erros críticos
☐ Performance dentro dos parâmetros
☐ Espaço em disco adequado

Validações de Aplicação:
☐ [Aplicação 1]: [Status] - [Observações]
☐ [Aplicação 2]: [Status] - [Observações]
☐ [Aplicação 3]: [Status] - [Observações]
☐ Bases de dados acessíveis
☐ Serviços web respondendo
☐ Integrações funcionando

Validações de Segurança:
☐ Patches de segurança aplicados
☐ Vulnerabilidades reduzidas
☐ SELinux configurado
☐ Firewall ativo
☐ Certificados válidos
☐ Usuários e permissões corretos

═══════════════════════════════════════════════════════════════════
PROBLEMAS ENCONTRADOS E SOLUÇÕES
═══════════════════════════════════════════════════════════════════

| Problema | Severidade | Horário | Solução Aplicada | Tempo Resolução | Status |
|----------|------------|---------|------------------|-----------------|--------|
| [Descrição] | [Baixa/Média/Alta/Crítica] | [HH:MM] | [Solução detalhada] | [X] min | [Resolvido/Pendente] |

Problemas Pendentes:
- [Problema 1]: [Descrição] - [Ação necessária] - [Responsável] - [Prazo]
- [Problema 2]: [Descrição] - [Ação necessária] - [Responsável] - [Prazo]

═══════════════════════════════════════════════════════════════════
MÉTRICAS E INDICADORES
═══════════════════════════════════════════════════════════════════

Métricas de Tempo:
- Tempo Total Planejado: [X] horas
- Tempo Total Real: [Y] horas
- Variação: [+/-Z] horas ([+/-W]%)
- Tempo de Indisponibilidade: [X] minutos
- Tempo de Rollback (se aplicável): [X] minutos

Métricas de Qualidade:
- Taxa de Sucesso: [100%/Parcial/Falha]
- Número de Problemas: [X]
- Número de Rollbacks: [X]
- Satisfação do Usuário: [1-5]

Métricas de Segurança:
- Vulnerabilidades Antes: [X] (Ref: Planilha "Classificação")
- Vulnerabilidades Depois: [Y]
- Redução: [Z] vulnerabilidades ([W]%)
- Patches Aplicados: [X]

Métricas do Framework IARA:
- Tempo IDENTIFICAR: [X] min ([Y]% do total)
- Tempo ANALISAR: [X] min ([Y]% do total)
- Tempo RESOLVER: [X] min ([Y]% do total)
- Tempo APRENDER: [X] min ([Y]% do total)

═══════════════════════════════════════════════════════════════════
LIÇÕES APRENDIDAS
═══════════════════════════════════════════════════════════════════

Pontos Positivos:
1. [Lição positiva 1]
2. [Lição positiva 2]
3. [Lição positiva 3]

Pontos de Melhoria:
1. [Melhoria 1] - [Ação sugerida]
2. [Melhoria 2] - [Ação sugerida]
3. [Melhoria 3] - [Ação sugerida]

Recomendações para Próximas Execuções:
1. [Recomendação 1]
2. [Recomendação 2]
3. [Recomendação 3]

Conhecimento Técnico Adquirido:
- [Conhecimento 1]
- [Conhecimento 2]
- [Conhecimento 3]

Aplicação do Framework IARA:
- Efetividade da fase IDENTIFICAR: [1-5] - [Comentários]
- Efetividade da fase ANALISAR: [1-5] - [Comentários]
- Efetividade da fase RESOLVER: [1-5] - [Comentários]
- Efetividade da fase APRENDER: [1-5] - [Comentários]

═══════════════════════════════════════════════════════════════════
EVIDÊNCIAS E ARQUIVOS
═══════════════════════════════════════════════════════════════════

Arquivos de Backup:
- Configurações: [caminho/arquivo_backup_config.tar.gz]
- Dados: [caminho/arquivo_backup_dados.tar.gz]
- Logs: [caminho/arquivo_logs_pre_migracao.tar.gz]

Logs de Execução:
- Log principal: [caminho/log_execucao_principal.log]
- Log de erros: [caminho/log_erros.log]
- Log de validação: [caminho/log_validacao.log]

Screenshots/Evidências:
- Tela inicial: [caminho/screenshot_inicial.png]
- Tela final: [caminho/screenshot_final.png]
- Validações: [caminho/screenshot_validacoes.png]

Relatórios Técnicos:
- Relatório Leapp/Convert2RHEL: [caminho/relatorio_ferramenta.txt]
- Análise de compatibilidade: [caminho/analise_compatibilidade.log]
- Relatório de validação: [caminho/relatorio_validacao.txt]

═══════════════════════════════════════════════════════════════════
ASSINATURAS E APROVAÇÕES
═══════════════════════════════════════════════════════════════════

Executor Principal:
Nome: [Nome Completo]
Data: [DD/MM/AAAA]
Assinatura: _________________________

Revisor Técnico:
Nome: [Nome do Revisor]
Data: [DD/MM/AAAA]
Assinatura: _________________________

Aprovação do Cliente (se necessário):
Nome: [Nome do Responsável]
Data: [DD/MM/AAAA]
Assinatura: _________________________

═══════════════════════════════════════════════════════════════════
OBSERVAÇÕES FINAIS
═══════════════════════════════════════════════════════════════════

Observações Gerais:
[Espaço para observações adicionais, comentários especiais, ou informações relevantes que não se encaixam nas seções anteriores]

Próximos Passos:
1. [Ação 1] - [Responsável] - [Prazo]
2. [Ação 2] - [Responsável] - [Prazo]
3. [Ação 3] - [Responsável] - [Prazo]

Contatos para Dúvidas:
- Técnico: [Nome] - [telefone] - [email]
- Gerencial: [Nome] - [telefone] - [email]

═══════════════════════════════════════════════════════════════════
FIM DO RELATÓRIO
═══════════════════════════════════════════════════════════════════
```

### 5.2. Checklist de Validação Pós-Migração

```
CHECKLIST DE VALIDAÇÃO PÓS-MIGRAÇÃO
Framework IARA - Projeto Algar 2025

═══════════════════════════════════════════════════════════════════
INFORMAÇÕES BÁSICAS
═══════════════════════════════════════════════════════════════════

Servidor: [hostname]
IP: [endereço IP]
Data da Validação: [DD/MM/AAAA]
Responsável pela Validação: [Nome]
Onda: [Número] - [Nome da Onda]
Procedimento Executado: [tipo de migração]

═══════════════════════════════════════════════════════════════════
VALIDAÇÕES DE SISTEMA OPERACIONAL
═══════════════════════════════════════════════════════════════════

Sistema Operacional:
☐ Versão correta instalada (verificar: cat /etc/redhat-release)
   Versão esperada: ________________
   Versão atual: ________________
   Status: ☐ OK ☐ NOK

☐ Kernel funcionando (verificar: uname -r)
   Kernel: ________________
   Status: ☐ OK ☐ NOK

☐ Arquitetura correta (verificar: uname -m)
   Arquitetura: ________________
   Status: ☐ OK ☐ NOK

☐ Subscription Manager ativo (verificar: subscription-manager status)
   Status: ________________
   Status: ☐ OK ☐ NOK

☐ Red Hat Satellite registrado
   Status: ________________
   Status: ☐ OK ☐ NOK

═══════════════════════════════════════════════════════════════════
VALIDAÇÕES DE RECURSOS DO SISTEMA
═══════════════════════════════════════════════════════════════════

Memória:
☐ Memória total reconhecida (verificar: free -h)
   Memória Total: ________________
   Status: ☐ OK ☐ NOK

☐ Uso de memória aceitável (< 80%)
   Uso atual: ________________%
   Status: ☐ OK ☐ NOK

☐ Swap configurado
   Swap Total: ________________
   Status: ☐ OK ☐ NOK

CPU:
☐ Processadores reconhecidos (verificar: nproc)
   CPUs: ________________
   Status: ☐ OK ☐ NOK

☐ Load average aceitável (verificar: uptime)
   Load: ________________
   Status: ☐ OK ☐ NOK

Armazenamento:
☐ Sistemas de arquivos montados (verificar: df -h)
   Raiz (/): ________________% usado
   /var: ________________% usado
   /tmp: ________________% usado
   Status: ☐ OK ☐ NOK

☐ Espaço em disco adequado (< 80% usado)
   Status: ☐ OK ☐ NOK

═══════════════════════════════════════════════════════════════════
VALIDAÇÕES DE REDE E CONECTIVIDADE
═══════════════════════════════════════════════════════════════════

Interfaces de Rede:
☐ Interface principal ativa (verificar: ip addr show)
   Interface: ________________
   IP: ________________
   Status: ☐ OK ☐ NOK

☐ Conectividade externa (verificar: ping -c 3 8.8.8.8)
   Resultado: ________________
   Status: ☐ OK ☐ NOK

☐ Resolução DNS funcionando (verificar: nslookup google.com)
   Resultado: ________________
   Status: ☐ OK ☐ NOK

☐ Conectividade SSH ativa
   Porta SSH: ________________
   Status: ☐ OK ☐ NOK

☐ Rota padrão configurada (verificar: ip route)
   Gateway: ________________
   Status: ☐ OK ☐ NOK

═══════════════════════════════════════════════════════════════════
VALIDAÇÕES DE SERVIÇOS DO SISTEMA
═══════════════════════════════════════════════════════════════════

Serviços Essenciais:
☐ SSH (verificar: systemctl status sshd)
   Status: ☐ Ativo ☐ Inativo ☐ Erro

☐ Cron (verificar: systemctl status crond)
   Status: ☐ Ativo ☐ Inativo ☐ Erro

☐ Rsyslog (verificar: systemctl status rsyslog)
   Status: ☐ Ativo ☐ Inativo ☐ Erro

☐ NetworkManager (verificar: systemctl status NetworkManager)
   Status: ☐ Ativo ☐ Inativo ☐ Erro

☐ Firewall (verificar: systemctl status firewalld)
   Status: ☐ Ativo ☐ Inativo ☐ Erro

Serviços de Aplicação:
☐ Apache/Nginx (verificar: systemctl status httpd/nginx)
   Status: ☐ Ativo ☐ Inativo ☐ N/A ☐ Erro

☐ MySQL/PostgreSQL (verificar: systemctl status mysqld/postgresql)
   Status: ☐ Ativo ☐ Inativo ☐ N/A ☐ Erro

☐ Java Applications (verificar: ps aux | grep java)
   Processos Java: ________________
   Status: ☐ OK ☐ NOK ☐ N/A

☐ Outros serviços específicos:
   [Serviço 1]: ________________ Status: ☐ OK ☐ NOK
   [Serviço 2]: ________________ Status: ☐ OK ☐ NOK

═══════════════════════════════════════════════════════════════════
VALIDAÇÕES DE SEGURANÇA
═══════════════════════════════════════════════════════════════════

Configurações de Segurança:
☐ SELinux configurado (verificar: getenforce)
   Status SELinux: ________________
   Status: ☐ OK ☐ NOK

☐ Firewall ativo e configurado
   Zonas ativas: ________________
   Status: ☐ OK ☐ NOK

☐ Usuários e permissões corretos
   Usuários root: ________________
   Status: ☐ OK ☐ NOK

☐ Certificados SSL válidos (se aplicável)
   Certificados: ________________
   Status: ☐ OK ☐ NOK ☐ N/A

Atualizações e Patches:
☐ Sistema totalmente atualizado (verificar: yum check-update)
   Atualizações pendentes: ________________
   Status: ☐ OK ☐ NOK

☐ Patches de segurança aplicados
   Últimas atualizações: ________________
   Status: ☐ OK ☐ NOK

☐ Vulnerabilidades críticas corrigidas
   Vulnerabilidades restantes: ________________
   Status: ☐ OK ☐ NOK

☐ Red Hat Satellite registration ativo
   Status subscription: ________________
   Status: ☐ OK ☐ NOK

═══════════════════════════════════════════════════════════════════
VALIDAÇÕES DE APLICAÇÕES
═══════════════════════════════════════════════════════════════════

Aplicações Web:
☐ Página principal carregando (verificar: curl http://localhost)
   Resposta HTTP: ________________
   Status: ☐ OK ☐ NOK ☐ N/A

☐ Login funcionando
   Teste de login: ________________
   Status: ☐ OK ☐ NOK ☐ N/A

☐ Funcionalidades principais testadas
   Funcionalidades: ________________
   Status: ☐ OK ☐ NOK ☐ N/A

☐ Performance aceitável
   Tempo de resposta: ________________
   Status: ☐ OK ☐ NOK ☐ N/A

Bases de Dados:
☐ Conexão à base de dados OK
   Teste de conexão: ________________
   Status: ☐ OK ☐ NOK ☐ N/A

☐ Consultas básicas funcionando
   Teste de consulta: ________________
   Status: ☐ OK ☐ NOK ☐ N/A

☐ Integridade dos dados verificada
   Verificação: ________________
   Status: ☐ OK ☐ NOK ☐ N/A

☐ Backup automático funcionando
   Último backup: ________________
   Status: ☐ OK ☐ NOK ☐ N/A

═══════════════════════════════════════════════════════════════════
VALIDAÇÕES DE PERFORMANCE
═══════════════════════════════════════════════════════════════════

Recursos do Sistema:
☐ CPU usage < 80% (verificar: top)
   CPU atual: ________________%
   Status: ☐ OK ☐ NOK

☐ Memory usage < 80% (verificar: free)
   Memória atual: ________________%
   Status: ☐ OK ☐ NOK

☐ Disk I/O normal (verificar: iostat)
   I/O wait: ________________%
   Status: ☐ OK ☐ NOK

☐ Network latency aceitável (verificar: ping)
   Latência média: ________________ms
   Status: ☐ OK ☐ NOK

Performance de Aplicações:
☐ Tempo de resposta < [X] segundos
   Tempo atual: ________________s
   Status: ☐ OK ☐ NOK ☐ N/A

☐ Throughput mantido
   Throughput: ________________
   Status: ☐ OK ☐ NOK ☐ N/A

☐ Sem memory leaks detectados
   Verificação: ________________
   Status: ☐ OK ☐ NOK ☐ N/A

☐ Logs de performance OK
   Logs: ________________
   Status: ☐ OK ☐ NOK

═══════════════════════════════════════════════════════════════════
VALIDAÇÕES DE LOGS E MONITORAMENTO
═══════════════════════════════════════════════════════════════════

Logs do Sistema:
☐ Logs sem erros críticos (verificar: journalctl --priority=err)
   Erros encontrados: ________________
   Status: ☐ OK ☐ NOK

☐ Logs de boot OK (verificar: journalctl -b)
   Status do boot: ________________
   Status: ☐ OK ☐ NOK

☐ Logs de aplicação OK
   Aplicações verificadas: ________________
   Status: ☐ OK ☐ NOK

☐ Rotação de logs funcionando
   Configuração logrotate: ________________
   Status: ☐ OK ☐ NOK

Monitoramento:
☐ Agentes de monitoramento ativos
   Agentes: ________________
   Status: ☐ OK ☐ NOK ☐ N/A

☐ Métricas sendo coletadas
   Métricas: ________________
   Status: ☐ OK ☐ NOK ☐ N/A

☐ Alertas configurados
   Alertas: ________________
   Status: ☐ OK ☐ NOK ☐ N/A

═══════════════════════════════════════════════════════════════════
RESULTADO FINAL DA VALIDAÇÃO
═══════════════════════════════════════════════════════════════════

Resumo dos Resultados:
- Total de verificações: ________________
- Verificações OK: ________________
- Verificações NOK: ________________
- Verificações N/A: ________________

Taxa de Sucesso: ________________% (OK / Total aplicável)

Status Final:
☐ APROVADO - Todas as validações críticas passaram
☐ APROVADO COM RESSALVAS - Problemas menores identificados
☐ REPROVADO - Problemas críticos encontrados

Problemas Críticos Identificados:
1. [Problema 1]: [Descrição] - [Ação necessária]
2. [Problema 2]: [Descrição] - [Ação necessária]

Problemas Menores Identificados:
1. [Problema 1]: [Descrição] - [Ação sugerida]
2. [Problema 2]: [Descrição] - [Ação sugerida]

═══════════════════════════════════════════════════════════════════
RECOMENDAÇÕES E PRÓXIMOS PASSOS
═══════════════════════════════════════════════════════════════════

Recomendações Imediatas:
1. [Recomendação 1]
2. [Recomendação 2]
3. [Recomendação 3]

Monitoramento Contínuo:
1. [Item a monitorar 1] - [Frequência]
2. [Item a monitorar 2] - [Frequência]
3. [Item a monitorar 3] - [Frequência]

Próximas Ações:
1. [Ação 1] - [Responsável] - [Prazo]
2. [Ação 2] - [Responsável] - [Prazo]
3. [Ação 3] - [Responsável] - [Prazo]

═══════════════════════════════════════════════════════════════════
ASSINATURAS
═══════════════════════════════════════════════════════════════════

Responsável pela Validação:
Nome: [Nome Completo]
Data: [DD/MM/AAAA]
Assinatura: _________________________

Revisor Técnico:
Nome: [Nome do Revisor]
Data: [DD/MM/AAAA]
Assinatura: _________________________

Aprovação Final:
Nome: [Nome do Responsável]
Data: [DD/MM/AAAA]
Assinatura: _________________________

═══════════════════════════════════════════════════════════════════
FIM DO CHECKLIST
═══════════════════════════════════════════════════════════════════
```

### 5.3. Modelo de Solicitação de Mudança para Cliente

```
SOLICITAÇÃO DE MUDANÇA - MIGRAÇÃO DE SERVIDORES LINUX
Projeto: Modernização Infraestrutura Algar
Framework: IARA (Identificar, Analisar, Resolver, Aprender)

═══════════════════════════════════════════════════════════════════
INFORMAÇÕES GERAIS
═══════════════════════════════════════════════════════════════════

Número da Solicitação: CHG-ALGAR-[ONDA]-[LOTE]-[YYYYMMDD]
Data da Solicitação: [DD/MM/AAAA]
Solicitante: [Nome da Equipe de Migração]
Aprovador Técnico: [Nome do Responsável Técnico]
Aprovador de Negócio: [Nome do Responsável de Negócio]

Onda: [Número] - [Nome da Onda]
Lote: [Número do Lote]
Prioridade: [Baixa/Média/Alta/Crítica]
Categoria: Migração de Sistema Operacional

═══════════════════════════════════════════════════════════════════
SERVIDORES INCLUÍDOS NA MUDANÇA
═══════════════════════════════════════════════════════════════════

Total de Servidores: [X] servidores
Referência na Planilha: "Algar-Relatorio-Fase2-Linux_vf3.xlsx"

| Hostname | IP | SO Atual | SO Destino | Criticidade | Ambiente | Aplicações |
|----------|----|---------|-----------|-----------|---------|-----------| 
| [hostname1] | [IP1] | [SO atual] | [SO destino] | [criticidade] | [Prod/Não-Prod] | [apps] |
| [hostname2] | [IP2] | [SO atual] | [SO destino] | [criticidade] | [Prod/Não-Prod] | [apps] |

Filtros Aplicados na Planilha:
- Aba "Servidores": [critérios específicos]
- Aba "Classificação": [critérios de vulnerabilidades]
- Aba "Compatibilidade": [critérios de aplicações]

═══════════════════════════════════════════════════════════════════
JUSTIFICATIVA DA MUDANÇA
═══════════════════════════════════════════════════════════════════

Problema Identificado:
- [X] servidores sem suporte oficial (End-of-Life)
- [Y] vulnerabilidades de segurança identificadas
- Necessidade de padronização em Red Hat Enterprise Linux

Benefícios Esperados:
- Redução de vulnerabilidades de segurança
- Suporte oficial Red Hat
- Padronização da infraestrutura
- Melhoria na governança de patches

Referência de Vulnerabilidades:
- Planilha "Classificação", coluna "Total vulnerabilidades - Qualys"
- Servidores com [X] a [Y] vulnerabilidades

═══════════════════════════════════════════════════════════════════
DETALHES TÉCNICOS DA MUDANÇA
═══════════════════════════════════════════════════════════════════

Procedimentos a Serem Executados:
☐ Upgrade RHEL (mesmo SO): [X] servidores
☐ Conversão CentOS→RHEL: [Y] servidores  
☐ Conversão Oracle→RHEL: [Z] servidores
☐ Update/Patch: [W] servidores
☐ Instalação limpa RHEL 9: [V] servidores
☐ Migração de aplicações: [U] servidores

Ferramentas Utilizadas:
- Red Hat Leapp (upgrades RHEL)
- Red Hat Convert2RHEL (conversões)
- Red Hat Satellite (gerenciamento)
- Scripts customizados (validações)
- Ansible (automação)

Método de Acesso:
- Todos os acessos via bastion host
- Protocolo SSH com chaves autenticadas
- Logs de acesso registrados

═══════════════════════════════════════════════════════════════════
CRONOGRAMA E JANELAS DE MANUTENÇÃO
═══════════════════════════════════════════════════════════════════

Data de Início: [DD/MM/AAAA]
Data de Término: [DD/MM/AAAA]
Duração Total Estimada: [X] horas

Janelas de Manutenção Solicitadas:

| Servidor | Data | Horário Início | Horário Fim | Duração | Impacto |
|----------|------|---------------|-------------|---------|---------|
| [hostname1] | [DD/MM] | [HH:MM] | [HH:MM] | [X]h | [Alto/Médio/Baixo] |
| [hostname2] | [DD/MM] | [HH:MM] | [HH:MM] | [X]h | [Alto/Médio/Baixo] |

Observações de Cronograma:
- Servidores não-produtivos serão migrados primeiro
- Servidores produtivos seguirão ordem de criticidade
- Intervalos entre migrações para validação

═══════════════════════════════════════════════════════════════════
ANÁLISE DE RISCOS E MITIGAÇÕES
═══════════════════════════════════════════════════════════════════

Riscos Identificados:

| Risco | Probabilidade | Impacto | Mitigação |
|-------|--------------|---------|-----------|
| Falha na migração | Baixa | Alto | Backup completo + plano de rollback |
| Incompatibilidade de aplicação | Média | Médio | Testes prévios + ambiente de homologação |
| Indisponibilidade prolongada | Baixa | Alto | Procedimentos testados + equipe experiente |
| Perda de configurações | Baixa | Médio | Backup detalhado + documentação |

Planos de Contingência:
1. Rollback via snapshot (se disponível)
2. Restauração de backup completo
3. Reinstalação do SO anterior
4. Acionamento de ambiente de contingência

═══════════════════════════════════════════════════════════════════
CRITÉRIOS DE SUCESSO E VALIDAÇÃO
═══════════════════════════════════════════════════════════════════

Critérios de Sucesso:
☐ Sistema operacional atualizado conforme planejado
☐ Todas as aplicações funcionando corretamente
☐ Serviços iniciando automaticamente
☐ Conectividade de rede mantida
☐ Performance dentro dos parâmetros aceitáveis
☐ Logs sem erros críticos
☐ Redução de vulnerabilidades confirmada

Validações a Serem Realizadas:
1. Validação de SO e versão
2. Validação de serviços críticos
3. Validação de aplicações
4. Validação de conectividade
5. Validação de performance
6. Validação de segurança
7. Validação de logs

Métricas de Sucesso:
- Taxa de sucesso: > 95%
- Tempo de indisponibilidade: < [X] horas por servidor
- Redução de vulnerabilidades: > 80%
- Satisfação dos usuários: > 4/5

═══════════════════════════════════════════════════════════════════
COMUNICAÇÃO E STAKEHOLDERS
═══════════════════════════════════════════════════════════════════

Stakeholders Envolvidos:
- Equipe de Infraestrutura: [nomes]
- Equipe de Aplicações: [nomes]
- Equipe de Segurança: [nomes]
- Usuários de Negócio: [nomes]
- Gerência: [nomes]

Plano de Comunicação:
- Notificação 48h antes: Email para todos os stakeholders
- Notificação 2h antes: Confirmação de início
- Durante execução: Updates a cada 2 horas
- Pós-execução: Relatório de conclusão

Canais de Comunicação:
- Email: [lista de distribuição]
- Chat: [canal específico]
- Telefone: [números de emergência]

═══════════════════════════════════════════════════════════════════
APROVAÇÕES NECESSÁRIAS
═══════════════════════════════════════════════════════════════════

☐ Aprovação Técnica: [Nome] - Data: [DD/MM/AAAA]
☐ Aprovação de Segurança: [Nome] - Data: [DD/MM/AAAA]  
☐ Aprovação de Negócio: [Nome] - Data: [DD/MM/AAAA]
☐ Aprovação de Mudança: [Nome] - Data: [DD/MM/AAAA]

Observações das Aprovações:
[Comentários dos aprovadores]

═══════════════════════════════════════════════════════════════════
ANEXOS E REFERÊNCIAS
═══════════════════════════════════════════════════════════════════

Documentos de Referência:
- Planilha: "Algar-Relatorio-Fase2-Linux_vf3.xlsx"
- Plano de Ação Detalhado: [nome do arquivo]
- Procedimentos Técnicos: [nome do arquivo]
- Matriz de Riscos: [nome do arquivo]

Contatos de Emergência:
- Líder Técnico: [nome] - [telefone]
- Especialista Red Hat: [nome] - [telefone]
- Gerente do Projeto: [nome] - [telefone]

═══════════════════════════════════════════════════════════════════
ASSINATURAS
═══════════════════════════════════════════════════════════════════

Solicitante: _________________________ Data: ___/___/______

Aprovador Técnico: _________________________ Data: ___/___/______

Aprovador de Negócio: _________________________ Data: ___/___/______
```

---

## 6. Organização Centralizada de Documentos e Artefatos

### 6.1. Estrutura de Diretórios

```
/projeto_algar_migracao/
├── 01_documentacao/
│   ├── plano_acao_detalhado.md
│   ├── resumo_executivo.md
│   ├── matriz_riscos.xlsx
│   └── cronograma_geral.xlsx
├── 02_planilhas_origem/
│   ├── Algar-Relatorio-Fase2-Linux_vf3.xlsx
│   └── analises_complementares/
├── 03_scripts_automacao/
│   ├── validacao_acesso/
│   │   ├── test_ssh_connectivity.sh
│   │   ├── check_satellite_registration.sh
│   │   └── validate_bastion_access.sh
│   ├── procedimentos_migracao/
│   │   ├── upgrade_rhel7_to_rhel8_iara.sh
│   │   ├── upgrade_rhel8_to_rhel9_iara.sh
│   │   ├── convert_centos_to_rhel_iara.sh
│   │   ├── convert_oracle_to_rhel_iara.sh
│   │   ├── update_patch_system_iara.sh
│   │   └── clean_install_rhel9_iara.sh
│   ├── validacao_pos_migracao/
│   │   ├── validate_system_post_migration.sh
│   │   ├── check_services_status.sh
│   │   └── verify_applications.sh
│   └── rollback/
│       ├── rollback_rhel_upgrade.sh
│       ├── rollback_centos_conversion.sh
│       └── emergency_restore.sh
├── 04_playbooks_ansible/
│   ├── inventario/
│   │   ├── hosts_onda_01.yml
│   │   ├── hosts_onda_02.yml
│   │   └── hosts_all.yml
│   ├── roles/
│   │   ├── pre_migration_backup/
│   │   ├── rhel_upgrade/
│   │   ├── centos_conversion/
│   │   ├── post_migration_validation/
│   │   └── rollback_procedures/
│   └── playbooks/
│       ├── site.yml
│       ├── pre_migration.yml
│       ├── migration.yml
│       ├── post_migration.yml
│       └── rollback.yml
├── 05_modelos_documentacao/
│   ├── relatorio_execucao.md
│   ├── checklist_validacao.md
│   ├── solicitacao_mudanca.md
│   └── template_comunicacao.md
├── 06_ondas_execucao/
│   ├── onda_01_nao_prod_simples/
│   │   ├── lista_servidores.csv
│   │   ├── cronograma_detalhado.xlsx
│   │   ├── relatorios_execucao/
│   │   └── licoes_aprendidas.md
│   ├── onda_02_nao_prod_complexo/
│   ├── onda_03_prod_baixa/
│   ├── onda_04_prod_media/
│   ├── onda_05_prod_alta/
│   └── onda_06_casos_especiais/
├── 07_base_conhecimento/
│   ├── licoes_aprendidas/
│   │   ├── problemas_comuns.md
│   │   ├── solucoes_efetivas.md
│   │   └── melhorias_processo.md
│   ├── problemas_solucoes/
│   │   ├── leapp_issues.md
│   │   ├── convert2rhel_issues.md
│   │   └── application_compatibility.md
│   └── melhores_praticas/
│       ├── backup_strategies.md
│       ├── rollback_procedures.md
│       └── validation_techniques.md
├── 08_comunicacao/
│   ├── templates_email/
│   │   ├── notificacao_inicio.html
│   │   ├── update_progresso.html
│   │   └── relatorio_conclusao.html
│   ├── apresentacoes/
│   │   ├── kickoff_projeto.pptx
│   │   ├── status_semanal.pptx
│   │   └── resultados_finais.pptx
│   └── relatorios_status/
│       ├── status_semanal_01.md
│       ├── status_semanal_02.md
│       └── dashboard_metricas.html
└── 09_backup_evidencias/
    ├── logs_execucao/
    │   ├── onda_01/
    │   ├── onda_02/
    │   └── consolidado/
    ├── backups_configuracao/
    │   ├── pre_migration/
    │   └── post_migration/
    └── screenshots_validacao/
        ├── before/
        ├── during/
        └── after/
```

### 6.2. Lista Completa de Tarefas com Referências Específicas

#### 6.2.1. Tarefas de Preparação (Pré-Execução)

**1. Validação de Acesso e Conectividade**
- **Tarefa 1.1**: Validar acesso SSH via bastion para todos os 1.893 servidores
  - **Referência**: Aba "Servidores", coluna "Hostname" e "IP"
  - **Script**: `/03_scripts_automacao/validacao_acesso/test_ssh_connectivity.sh`
  - **Responsável**: Equipe de Infraestrutura
  - **Prazo**: Semana -2

- **Tarefa 1.2**: Verificar cadastro no Red Hat Satellite
  - **Referência**: Aba "Servidores", todos os hostnames
  - **Script**: `/03_scripts_automacao/validacao_acesso/check_satellite_registration.sh`
  - **Responsável**: Equipe de Infraestrutura
  - **Prazo**: Semana -2

- **Tarefa 1.3**: Testar conectividade de rede
  - **Referência**: Aba "Servidores", coluna "IP"
  - **Método**: Ping e traceroute via bastion
  - **Responsável**: Equipe de Rede
  - **Prazo**: Semana -1

- **Tarefa 1.4**: Validar credenciais de acesso
  - **Referência**: Todos os servidores da planilha
  - **Método**: Teste de sudo e permissões
  - **Responsável**: Equipe de Segurança
  - **Prazo**: Semana -1

**2. Análise Detalhada da Planilha**
- **Tarefa 2.1**: Filtrar servidores por onda conforme critérios definidos
  - **Referência**: Aba "Servidores", colunas "Ambiente Produtivo", "Criticidade"
  - **Entregável**: `/06_ondas_execucao/*/lista_servidores.csv`
  - **Responsável**: Analista de Dados
  - **Prazo**: Semana -3

- **Tarefa 2.2**: Validar dados de inventário
  - **Referência**: Aba "Servidores", todas as colunas
  - **Método**: Verificação cruzada com ferramentas de inventário
  - **Responsável**: Equipe de Infraestrutura
  - **Prazo**: Semana -2

- **Tarefa 2.3**: Identificar dependências de aplicação
  - **Referência**: Aba "Compatibilidade - OP1/OP2/OP3"
  - **Entregável**: Matriz de dependências
  - **Responsável**: Equipe de Aplicações
  - **Prazo**: Semana -2

- **Tarefa 2.4**: Mapear vulnerabilidades por servidor
  - **Referência**: Aba "Classificação", coluna "Total vulnerabilidades - Qualys"
  - **Entregável**: Relatório de vulnerabilidades por onda
  - **Responsável**: Equipe de Segurança
  - **Prazo**: Semana -1

**3. Preparação de Ambiente**
- **Tarefa 3.1**: Configurar bastion host
  - **Referência**: Acesso a todos os 1.893 servidores
  - **Configuração**: SSH keys, logs, monitoramento
  - **Responsável**: Equipe de Infraestrutura
  - **Prazo**: Semana -3

- **Tarefa 3.2**: Instalar ferramentas necessárias
  - **Ferramentas**: Leapp, Convert2RHEL, Ansible
  - **Local**: Bastion host e servidores de gestão
  - **Responsável**: Equipe de Infraestrutura
  - **Prazo**: Semana -2

- **Tarefa 3.3**: Configurar Red Hat Satellite
  - **Referência**: Todos os servidores da planilha
  - **Configuração**: Grupos, políticas, patches
  - **Responsável**: Especialista Red Hat
  - **Prazo**: Semana -2

- **Tarefa 3.4**: Preparar scripts de automação
  - **Scripts**: Todos os procedimentos IARA
  - **Local**: `/03_scripts_automacao/`
  - **Responsável**: Equipe de Automação
  - **Prazo**: Semana -1

#### 6.2.2. Tarefas por Onda de Execução

**Onda 1: Não-Produção Simples (177 servidores)**

- **Tarefa O1.1**: Executar 177 migrações individuais
  - **Referência**: Aba "Servidores", filtro Ambiente="NÃO" AND Criticidade="Baixa"
  - **Procedimento**: Principalmente conversão CentOS→RHEL
  - **Duração**: 4 semanas
  - **Responsável**: Equipe completa (aprendizado)

- **Tarefa O1.2**: Documentar cada execução
  - **Template**: `/05_modelos_documentacao/relatorio_execucao.md`
  - **Local**: `/06_ondas_execucao/onda_01/relatorios_execucao/`
  - **Responsável**: Cada executor
  - **Prazo**: Imediato pós-execução

- **Tarefa O1.3**: Coletar lições aprendidas
  - **Método**: Retrospectivas semanais
  - **Entregável**: `/06_ondas_execucao/onda_01/licoes_aprendidas.md`
  - **Responsável**: Líder de Projeto
  - **Prazo**: Final da onda

- **Tarefa O1.4**: Otimizar procedimentos
  - **Base**: Lições aprendidas da Onda 1
  - **Entregável**: Scripts otimizados para Onda 2
  - **Responsável**: Equipe de Automação
  - **Prazo**: Entre ondas 1 e 2

**Onda 2: Não-Produção Complexo (250 servidores)**

- **Tarefa O2.1**: Executar 250 migrações com maior complexidade
  - **Referência**: Aba "Servidores", filtro Ambiente="NÃO" AND Criticidade IN ("Media","Alta")
  - **Procedimento**: Mix de conversões e upgrades
  - **Duração**: 5 semanas
  - **Responsável**: Equipe experiente

- **Tarefa O2.2**: Validar aplicações específicas
  - **Referência**: Aba "Compatibilidade", aplicações complexas
  - **Método**: Testes funcionais pós-migração
  - **Responsável**: Equipe de Aplicações
  - **Prazo**: Durante execução

- **Tarefa O2.3**: Documentar problemas e soluções
  - **Entregável**: Base de conhecimento atualizada
  - **Local**: `/07_base_conhecimento/problemas_solucoes/`
  - **Responsável**: Todos os executores
  - **Prazo**: Contínuo

- **Tarefa O2.4**: Refinar procedimentos
  - **Base**: Experiência das ondas 1 e 2
  - **Entregável**: Procedimentos finalizados para produção
  - **Responsável**: Equipe técnica
  - **Prazo**: Entre ondas 2 e 3

**Ondas 3-6: Produção (1.466 servidores)**

- **Tarefa O3-6.1**: Executar migrações em ambiente produtivo
  - **Referência**: Aba "Servidores", filtro Ambiente="SIM"
  - **Distribuição**: 2 + 728 + 707 + 29 servidores
  - **Duração**: 30 semanas
  - **Responsável**: Equipe especializada

- **Tarefa O3-6.2**: Coordenar janelas de manutenção
  - **Referência**: Criticidade e tipo de aplicação
  - **Método**: Solicitações de mudança individuais
  - **Responsável**: Gerente de Projeto
  - **Prazo**: 48h antes de cada janela

- **Tarefa O3-6.3**: Comunicar com stakeholders
  - **Templates**: `/08_comunicacao/templates_email/`
  - **Frequência**: Antes, durante e após cada migração
  - **Responsável**: Equipe de Comunicação
  - **Prazo**: Conforme cronograma

- **Tarefa O3-6.4**: Validar sistemas críticos
  - **Checklist**: `/05_modelos_documentacao/checklist_validacao.md`
  - **Critério**: 100% de validações OK para produção
  - **Responsável**: Equipe de Validação
  - **Prazo**: Imediato pós-migração

#### 6.2.3. Tarefas de Documentação e Aprendizado

**1. Documentação Contínua**
- **Tarefa D1.1**: Preencher relatórios de execução
  - **Frequência**: Cada servidor migrado
  - **Template**: Modelo padronizado
  - **Responsável**: Executor da migração
  - **Prazo**: Máximo 24h pós-execução

- **Tarefa D1.2**: Atualizar base de conhecimento
  - **Frequência**: Semanal
  - **Conteúdo**: Problemas, soluções, melhorias
  - **Responsável**: Líder Técnico
  - **Prazo**: Sexta-feira de cada semana

- **Tarefa D1.3**: Documentar lições aprendidas
  - **Frequência**: Final de cada onda
  - **Método**: Retrospectivas estruturadas
  - **Responsável**: Toda a equipe
  - **Prazo**: Última semana de cada onda

- **Tarefa D1.4**: Manter métricas atualizadas
  - **Frequência**: Diária
  - **Métricas**: Progresso, qualidade, problemas
  - **Responsável**: Analista de Dados
  - **Prazo**: Final do dia

**2. Comunicação**
- **Tarefa C2.1**: Enviar solicitações de mudança
  - **Frequência**: Por lote de servidores
  - **Template**: Modelo padronizado
  - **Responsável**: Gerente de Projeto
  - **Prazo**: 72h antes da execução

- **Tarefa C2.2**: Comunicar status para stakeholders
  - **Frequência**: Semanal + ad-hoc
  - **Canais**: Email, reuniões, dashboard
  - **Responsável**: Equipe de Comunicação
  - **Prazo**: Conforme cronograma

- **Tarefa C2.3**: Reportar problemas e soluções
  - **Frequência**: Imediata para problemas críticos
  - **Método**: Escalação estruturada
  - **Responsável**: Todos os executores
  - **Prazo**: Máximo 2h para problemas críticos

- **Tarefa C2.4**: Apresentar resultados
  - **Frequência**: Final de cada onda + final do projeto
  - **Audiência**: Stakeholders e gerência
  - **Responsável**: Gerente de Projeto
  - **Prazo**: Conforme marcos do projeto

**3. Melhoria Contínua**
- **Tarefa M3.1**: Analisar métricas de performance
  - **Frequência**: Semanal
  - **Métricas**: Tempo, qualidade, satisfação
  - **Responsável**: Analista de Qualidade
  - **Prazo**: Segunda-feira de cada semana

- **Tarefa M3.2**: Otimizar procedimentos
  - **Frequência**: Entre ondas
  - **Base**: Lições aprendidas e métricas
  - **Responsável**: Equipe técnica
  - **Prazo**: Período entre ondas

- **Tarefa M3.3**: Implementar automações
  - **Frequência**: Contínua
  - **Foco**: Tarefas repetitivas e validações
  - **Responsável**: Equipe de Automação
  - **Prazo**: Conforme oportunidades

- **Tarefa M3.4**: Treinar equipe
  - **Frequ


ência**: Entre ondas
- **Base**: Novas tecnologias e lições aprendidas
- **Responsável**: Líder Técnico
- **Prazo**: Conforme necessidade

#### 6.2.4. Tarefas de Validação e Qualidade

**1. Validações Técnicas**
- **Tarefa V1.1**: Executar checklist de validação pós-migração
  - **Frequência**: Cada servidor migrado
  - **Checklist**: Template padronizado completo
  - **Responsável**: Equipe de Validação
  - **Prazo**: Imediato pós-migração

- **Tarefa V1.2**: Validar aplicações específicas
  - **Referência**: Aba "Compatibilidade", aplicações por servidor
  - **Método**: Testes funcionais e de integração
  - **Responsável**: Equipe de Aplicações
  - **Prazo**: Dentro da janela de manutenção

- **Tarefa V1.3**: Verificar redução de vulnerabilidades
  - **Referência**: Aba "Classificação", comparar antes/depois
  - **Ferramenta**: Qualys + Red Hat Insights
  - **Responsável**: Equipe de Segurança
  - **Prazo**: 24h pós-migração

- **Tarefa V1.4**: Validar performance do sistema
  - **Métricas**: CPU, memória, I/O, rede
  - **Baseline**: Dados pré-migração
  - **Responsável**: Equipe de Monitoramento
  - **Prazo**: 48h pós-migração

**2. Validações de Negócio**
- **Tarefa V2.1**: Confirmar funcionamento de aplicações críticas
  - **Referência**: Servidores com Criticidade="Alta"
  - **Método**: Testes de usuário final
  - **Responsável**: Usuários de Negócio
  - **Prazo**: Dentro da janela de manutenção

- **Tarefa V2.2**: Validar integrações entre sistemas
  - **Foco**: Sistemas que se comunicam entre si
  - **Método**: Testes de integração end-to-end
  - **Responsável**: Equipe de Aplicações
  - **Prazo**: 24h pós-migração

- **Tarefa V2.3**: Confirmar disponibilidade de serviços
  - **Método**: Monitoramento de uptime e SLA
  - **Ferramenta**: Ferramentas de monitoramento existentes
  - **Responsável**: Equipe de Operações
  - **Prazo**: Contínuo pós-migração

#### 6.2.5. Tarefas de Rollback e Contingência

**1. Preparação de Rollback**
- **Tarefa R1.1**: Criar snapshots pré-migração
  - **Frequência**: Antes de cada migração
  - **Método**: VM snapshots ou backup completo
  - **Responsável**: Equipe de Backup
  - **Prazo**: Imediatamente antes da migração

- **Tarefa R1.2**: Documentar procedimentos de rollback
  - **Conteúdo**: Passos específicos por tipo de migração
  - **Local**: `/03_scripts_automacao/rollback/`
  - **Responsável**: Equipe técnica
  - **Prazo**: Antes do início de cada onda

- **Tarefa R1.3**: Testar procedimentos de rollback
  - **Frequência**: Em ambiente de teste
  - **Método**: Simulação completa
  - **Responsável**: Equipe de Testes
  - **Prazo**: Antes da execução em produção

**2. Execução de Rollback (se necessário)**
- **Tarefa R2.1**: Decidir sobre necessidade de rollback
  - **Critérios**: Falhas críticas, problemas de aplicação
  - **Responsável**: Comitê de Mudança
  - **Prazo**: Máximo 2h após identificação do problema

- **Tarefa R2.2**: Executar rollback
  - **Método**: Procedimentos documentados
  - **Responsável**: Equipe técnica especializada
  - **Prazo**: Conforme SLA acordado

- **Tarefa R2.3**: Validar rollback
  - **Método**: Checklist de validação
  - **Responsável**: Equipe de Validação
  - **Prazo**: Imediato pós-rollback

- **Tarefa R2.4**: Documentar lições do rollback
  - **Conteúdo**: Causa raiz, ações corretivas
  - **Responsável**: Líder Técnico
  - **Prazo**: 24h pós-rollback

#### 6.2.6. Tarefas de Finalização do Projeto

**1. Consolidação Final**
- **Tarefa F1.1**: Consolidar todos os relatórios de execução
  - **Fonte**: Todos os relatórios individuais
  - **Entregável**: Relatório consolidado final
  - **Responsável**: Analista de Dados
  - **Prazo**: Final do projeto

- **Tarefa F1.2**: Calcular métricas finais do projeto
  - **Métricas**: Taxa de sucesso, tempo total, redução de vulnerabilidades
  - **Entregável**: Dashboard de métricas finais
  - **Responsável**: Analista de Qualidade
  - **Prazo**: Final do projeto

- **Tarefa F1.3**: Documentar lições aprendidas do projeto
  - **Conteúdo**: Lições de todas as ondas consolidadas
  - **Entregável**: Documento de lições aprendidas final
  - **Responsável**: Gerente de Projeto
  - **Prazo**: Final do projeto

- **Tarefa F1.4**: Criar base de conhecimento final
  - **Conteúdo**: Todos os problemas, soluções e melhorias
  - **Entregável**: Base de conhecimento completa
  - **Responsável**: Equipe técnica
  - **Prazo**: Final do projeto

**2. Entrega e Transição**
- **Tarefa F2.1**: Preparar apresentação final
  - **Audiência**: Stakeholders e alta gerência
  - **Conteúdo**: Resultados, benefícios, lições aprendidas
  - **Responsável**: Gerente de Projeto
  - **Prazo**: Última semana do projeto

- **Tarefa F2.2**: Transferir conhecimento para equipe de operações
  - **Método**: Sessões de treinamento e documentação
  - **Conteúdo**: Novos procedimentos e melhores práticas
  - **Responsável**: Equipe técnica
  - **Prazo**: Última semana do projeto

- **Tarefa F2.3**: Entregar documentação final
  - **Conteúdo**: Todos os documentos, scripts e evidências
  - **Local**: Repositório centralizado organizado
  - **Responsável**: Gerente de Projeto
  - **Prazo**: Final do projeto

- **Tarefa F2.4**: Realizar retrospectiva final do projeto
  - **Método**: Sessão estruturada com toda a equipe
  - **Entregável**: Relatório de retrospectiva final
  - **Responsável**: Gerente de Projeto
  - **Prazo**: Final do projeto

---

## 7. Sistema de Comunicação Centralizada

### 7.1. Estrutura de Comunicação

**Canais Principais:**
- **Email**: Lista de distribuição por stakeholder
- **Chat/Teams**: Canal dedicado ao projeto
- **Dashboard**: Portal web com status em tempo real
- **Reuniões**: Cadência estruturada de reuniões

**Frequência de Comunicação:**
- **Diária**: Updates no chat para equipe técnica
- **Semanal**: Relatório de status para stakeholders
- **Por evento**: Comunicações de início/fim de migração
- **Emergencial**: Escalação imediata para problemas críticos

### 7.2. Templates de Comunicação

#### 7.2.1. Template de Notificação de Início

```html
<!DOCTYPE html>
<html>
<head>
    <title>Início de Migração - Projeto Algar</title>
</head>
<body>
    <h2>🚀 INÍCIO DE MIGRAÇÃO - ONDA [X] LOTE [Y]</h2>
    
    <p><strong>Data/Hora:</strong> [DD/MM/AAAA às HH:MM]</p>
    <p><strong>Servidores:</strong> [X] servidores</p>
    <p><strong>Duração Estimada:</strong> [X] horas</p>
    
    <h3>📋 Servidores Incluídos:</h3>
    <table border="1">
        <tr><th>Hostname</th><th>IP</th><th>Procedimento</th><th>Duração Est.</th></tr>
        <tr><td>[hostname1]</td><td>[IP1]</td><td>[procedimento]</td><td>[X]h</td></tr>
    </table>
    
    <h3>📞 Contatos de Emergência:</h3>
    <ul>
        <li>Líder Técnico: [nome] - [telefone]</li>
        <li>Gerente Projeto: [nome] - [telefone]</li>
    </ul>
    
    <p><em>Próximo update em 2 horas ou conforme necessário.</em></p>
</body>
</html>
```

#### 7.2.2. Template de Update de Progresso

```html
<!DOCTYPE html>
<html>
<head>
    <title>Update de Progresso - Projeto Algar</title>
</head>
<body>
    <h2>📊 UPDATE DE PROGRESSO - ONDA [X] LOTE [Y]</h2>
    
    <p><strong>Horário do Update:</strong> [DD/MM/AAAA às HH:MM]</p>
    <p><strong>Progresso Geral:</strong> [X]% concluído</p>
    
    <h3>✅ Servidores Concluídos ([X]):</h3>
    <ul>
        <li>[hostname1] - ✅ Sucesso</li>
        <li>[hostname2] - ✅ Sucesso</li>
    </ul>
    
    <h3>🔄 Servidores em Andamento ([Y]):</h3>
    <ul>
        <li>[hostname3] - 🔄 Em migração (ETA: [HH:MM])</li>
    </ul>
    
    <h3>⏳ Servidores Pendentes ([Z]):</h3>
    <ul>
        <li>[hostname4] - ⏳ Aguardando</li>
    </ul>
    
    <h3>⚠️ Problemas Identificados:</h3>
    <ul>
        <li>[Problema 1] - [Status] - [Ação]</li>
    </ul>
    
    <p><strong>Próximo Update:</strong> [HH:MM] ou conforme necessário</p>
</body>
</html>
```

#### 7.2.3. Template de Relatório de Conclusão

```html
<!DOCTYPE html>
<html>
<head>
    <title>Conclusão de Migração - Projeto Algar</title>
</head>
<body>
    <h2>🎉 MIGRAÇÃO CONCLUÍDA - ONDA [X] LOTE [Y]</h2>
    
    <p><strong>Horário de Conclusão:</strong> [DD/MM/AAAA às HH:MM]</p>
    <p><strong>Duração Total:</strong> [X] horas [Y] minutos</p>
    
    <h3>📈 Resultados:</h3>
    <ul>
        <li><strong>Taxa de Sucesso:</strong> [X]% ([Y] de [Z] servidores)</li>
        <li><strong>Vulnerabilidades Reduzidas:</strong> [X] vulnerabilidades</li>
        <li><strong>Sistemas Atualizados:</strong> [X] para RHEL [versão]</li>
    </ul>
    
    <h3>✅ Servidores Migrados com Sucesso:</h3>
    <table border="1">
        <tr><th>Hostname</th><th>SO Anterior</th><th>SO Atual</th><th>Status</th></tr>
        <tr><td>[hostname1]</td><td>[SO ant]</td><td>[SO atual]</td><td>✅ OK</td></tr>
    </table>
    
    <h3>⚠️ Problemas Resolvidos:</h3>
    <ul>
        <li>[Problema 1] - [Solução aplicada]</li>
    </ul>
    
    <h3>📋 Próximos Passos:</h3>
    <ul>
        <li>Monitoramento contínuo por 48h</li>
        <li>Relatório detalhado em 24h</li>
        <li>Próxima onda: [data]</li>
    </ul>
    
    <h3>📞 Suporte Pós-Migração:</h3>
    <p>Para qualquer problema, contatar: [contatos]</p>
</body>
</html>
```

### 7.3. Dashboard de Métricas em Tempo Real

```html
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - Projeto Migração Algar</title>
    <style>
        .metric-card { border: 1px solid #ccc; padding: 20px; margin: 10px; display: inline-block; }
        .success { background-color: #d4edda; }
        .warning { background-color: #fff3cd; }
        .danger { background-color: #f8d7da; }
        .progress-bar { width: 100%; background-color: #f0f0f0; }
        .progress-fill { height: 30px; background-color: #28a745; text-align: center; line-height: 30px; }
    </style>
</head>
<body>
    <h1>🖥️ Dashboard - Projeto Migração Algar</h1>
    <p><strong>Última Atualização:</strong> [DD/MM/AAAA HH:MM:SS]</p>
    
    <div class="metric-card success">
        <h3>📊 Progresso Geral</h3>
        <div class="progress-bar">
            <div class="progress-fill" style="width: [X]%">[X]% Concluído</div>
        </div>
        <p>[Y] de 1.893 servidores migrados</p>
    </div>
    
    <div class="metric-card success">
        <h3>✅ Taxa de Sucesso</h3>
        <h2>[X]%</h2>
        <p>[Y] sucessos de [Z] tentativas</p>
    </div>
    
    <div class="metric-card warning">
        <h3>🔄 Em Andamento</h3>
        <h2>[X]</h2>
        <p>servidores sendo migrados</p>
    </div>
    
    <div class="metric-card danger">
        <h3>⚠️ Problemas</h3>
        <h2>[X]</h2>
        <p>problemas ativos</p>
    </div>
    
    <h2>📈 Métricas por Onda</h2>
    <table border="1" style="width: 100%">
        <tr>
            <th>Onda</th>
            <th>Total</th>
            <th>Concluídos</th>
            <th>Taxa Sucesso</th>
            <th>Status</th>
        </tr>
        <tr>
            <td>Onda 1</td>
            <td>177</td>
            <td>[X]</td>
            <td>[Y]%</td>
            <td>✅ Concluída</td>
        </tr>
        <tr>
            <td>Onda 2</td>
            <td>250</td>
            <td>[X]</td>
            <td>[Y]%</td>
            <td>🔄 Em andamento</td>
        </tr>
    </table>
    
    <h2>🔍 Detalhes da Onda Atual</h2>
    <p><strong>Onda [X] - [Nome da Onda]</strong></p>
    <p><strong>Progresso:</strong> [X] de [Y] servidores ([Z]%)</p>
    <p><strong>ETA:</strong> [DD/MM/AAAA]</p>
    
    <h3>🖥️ Servidores por Status</h3>
    <ul>
        <li>✅ Concluídos: [X]</li>
        <li>🔄 Em andamento: [Y]</li>
        <li>⏳ Pendentes: [Z]</li>
        <li>❌ Com problemas: [W]</li>
    </ul>
    
    <h2>📊 Métricas de Qualidade</h2>
    <div class="metric-card">
        <h3>🛡️ Vulnerabilidades Reduzidas</h3>
        <h2>[X]</h2>
        <p>vulnerabilidades corrigidas</p>
    </div>
    
    <div class="metric-card">
        <h3>⏱️ Tempo Médio por Servidor</h3>
        <h2>[X]h [Y]m</h2>
        <p>tempo médio de migração</p>
    </div>
    
    <div class="metric-card">
        <h3>😊 Satisfação</h3>
        <h2>[X]/5</h2>
        <p>avaliação dos stakeholders</p>
    </div>
    
    <h2>🚨 Alertas Ativos</h2>
    <ul>
        <li class="danger">❌ [Servidor X] - Falha na migração - [Ação necessária]</li>
        <li class="warning">⚠️ [Servidor Y] - Migração demorada - [Monitorando]</li>
    </ul>
    
    <h2>📞 Contatos de Emergência</h2>
    <ul>
        <li><strong>Líder Técnico:</strong> [nome] - [telefone]</li>
        <li><strong>Gerente Projeto:</strong> [nome] - [telefone]</li>
        <li><strong>Especialista Red Hat:</strong> [nome] - [telefone]</li>
    </ul>
    
    <p><em>Dashboard atualizado automaticamente a cada 5 minutos</em></p>
</body>
</html>
```

---

## 8. Conclusão e Próximos Passos

### 8.1. Resumo do Plano de Ação

Este plano de ação definitivo para migração e atualização dos 1.893 servidores Linux da Algar foi estruturado com base no Framework IARA (Identificar, Analisar, Resolver, Aprender) e contempla:

**Escopo Completo:**
- **1.893 servidores** Linux identificados na planilha
- **364.002 vulnerabilidades** de segurança a serem corrigidas
- **6 procedimentos técnicos** diferentes conforme necessidade
- **6 ondas de execução** distribuídas em 39 semanas
- **Framework IARA** aplicado sistematicamente

**Estrutura Organizacional:**
- Documentação centralizada e padronizada
- Scripts de automação com Framework IARA
- Modelos de documentação para equipe
- Sistema de comunicação estruturado
- Base de conhecimento para melhoria contínua

**Metodologia Robusta:**
- Validação de acesso via bastion host
- Procedimentos testados e documentados
- Planos de rollback para cada cenário
- Validações completas pós-migração
- Aprendizado contínuo e otimização

### 8.2. Fatores Críticos de Sucesso

**1. Preparação Adequada:**
- Validação completa de conectividade
- Testes em ambiente não-produtivo
- Treinamento da equipe
- Documentação detalhada

**2. Execução Disciplinada:**
- Seguir rigorosamente o Framework IARA
- Documentar cada execução
- Comunicar proativamente
- Validar completamente cada migração

**3. Aprendizado Contínuo:**
- Coletar lições aprendidas
- Otimizar procedimentos entre ondas
- Compartilhar conhecimento
- Implementar melhorias

**4. Gestão de Riscos:**
- Planos de rollback testados
- Comunicação clara com stakeholders
- Escalação estruturada de problemas
- Monitoramento contínuo

### 8.3. Próximos Passos Imediatos

**Semana -3:**
1. Aprovação final do plano pela gerência
2. Alocação de recursos e equipe
3. Configuração do ambiente de trabalho
4. Preparação da estrutura de documentação

**Semana -2:**
1. Validação de acesso a todos os servidores
2. Instalação de ferramentas necessárias
3. Configuração do Red Hat Satellite
4. Testes dos procedimentos em laboratório

**Semana -1:**
1. Treinamento final da equipe
2. Validação de todos os scripts
3. Preparação da comunicação
4. Confirmação das janelas de manutenção

**Semana 1:**
1. Início da Onda 1 (177 servidores não-produtivos)
2. Aplicação rigorosa do Framework IARA
3. Documentação detalhada de cada execução
4. Coleta de lições aprendidas

### 8.4. Indicadores de Sucesso

**Métricas Quantitativas:**
- Taxa de sucesso > 95%
- Redução de vulnerabilidades > 80%
- Tempo médio por servidor dentro do estimado
- Zero perda de dados

**Métricas Qualitativas:**
- Satisfação dos stakeholders > 4/5
- Qualidade da documentação
- Efetividade do aprendizado
- Maturidade dos processos

**Benefícios Esperados:**
- Infraestrutura padronizada em RHEL
- Redução significativa de vulnerabilidades
- Suporte oficial Red Hat ativo
- Base sólida para futuras atualizações
- Equipe capacitada e experiente

### 8.5. Considerações Finais

Este plano de ação representa um guia completo e detalhado para a migração bem-sucedida dos servidores Linux da Algar. A aplicação sistemática do Framework IARA garante que cada migração seja executada com rigor metodológico, gerando aprendizado contínuo e melhoria dos processos.

O sucesso do projeto depende da disciplina na execução, da comunicação efetiva com stakeholders e do comprometimento da equipe com a excelência técnica e a melhoria contínua.

Com este plano, a Algar terá não apenas uma infraestrutura modernizada e segura, mas também uma equipe experiente e processos maduros para futuras iniciativas de modernização tecnológica.

---

**Documento Completo - Framework IARA Aplicado**  
**Projeto: Migração e Atualização de Servidores Linux Algar**  
**Total de Páginas: [Calculado automaticamente]**  
**Versão Final: 5.0 - Fusão Completa e Definitiva**  
**Data: 09 de setembro de 2025**

═══════════════════════════════════════════════════════════════════
**FIM DO DOCUMENTO**
═══════════════════════════════════════════════════════════════════

