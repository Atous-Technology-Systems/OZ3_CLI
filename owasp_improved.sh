#!/bin/bash

# ==============================================================================
# |                                                                            |
# |            ATOUS NETWORK - OWASP PENTESTING SUITE (IMPROVED)              |
# |                                                                            |
# |      Script Seguro e Aprimorado para Testes de Segurança na Rede Atous   |
# |                                                                            |
# |                          !!! AVISO LEGAL !!!                             |
# | Este script foi criado para fins educacionais e de testes autorizados.   |
# | O uso indevido deste script em sistemas sem permissão explícita é ilegal.|
# | O autor não se responsabiliza por qualquer dano ou uso indevido.         |
# |              USE COM RESPONSABILIDADE E ÉTICA.                           |
# |              author: Atous Technology Systems                                |
# |              version: 2.0.0-improved                                        |
# |              date: 2025-06-22                                                |
# |              license: MIT                                                     |
# |                                                                            |
# |                                                                            |
# ==============================================================================

# ------------------------------------------------------------------------------
# Configuração Global e Constantes
# ------------------------------------------------------------------------------

# Versão do script
readonly SCRIPT_VERSION="2.0.0-improved"
readonly SCRIPT_NAME="ATOUS OWASP Pentest Suite"

# Configurações padrão
readonly DEFAULT_TARGET_HOST=""
readonly DEFAULT_TARGET_PORT=""
readonly DEFAULT_TIMEOUT=30
readonly DEFAULT_NMAP_TIMING="T3"

# Configuração inicial
TARGET_HOST="${TARGET_HOST:-$DEFAULT_TARGET_HOST}"
TARGET_PORT="${TARGET_PORT:-$DEFAULT_TARGET_PORT}"
TIMEOUT="${TIMEOUT:-$DEFAULT_TIMEOUT}"
NMAP_TIMING="${NMAP_TIMING:-$DEFAULT_NMAP_TIMING}"

# Modos de operação
INTERACTIVE_MODE=true
QUIET_MODE=false
DEBUG_MODE=false

# Diretório para salvar os relatórios
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="${REPORT_DIR:-atous_pentest_report_${TIMESTAMP}}"
REPORT_FILE="${REPORT_DIR}/atous_security_report_${TIMESTAMP}.md"

# Cores para a saída
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Logs
LOG_FILE="${REPORT_DIR}/pentest.log"

# ------------------------------------------------------------------------------
# Funções de Logging e Output
# ------------------------------------------------------------------------------

# Cria arquivo com permissões seguras
create_secure_file() {
    local file_path="$1"
    local permissions="${2:-640}"
    
    # Cria o arquivo se não existir
    touch "$file_path"
    
    # Define permissões seguras
    chmod "$permissions" "$file_path"
}

# Função de log segura
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Cria arquivo de log com permissões seguras se não existir
    if [[ ! -f "$LOG_FILE" ]]; then
        create_secure_file "$LOG_FILE" "640"
    fi
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    if [[ "$DEBUG_MODE" == "true" ]] || [[ "$level" != "DEBUG" ]]; then
        case "$level" in
            "ERROR")   echo -e "${RED}[ERROR] $message${NC}" >&2 ;;
            "WARN")    echo -e "${YELLOW}[WARN] $message${NC}" ;;
            "INFO")    echo -e "${GREEN}[INFO] $message${NC}" ;;
            "DEBUG")   echo -e "${PURPLE}[DEBUG] $message${NC}" ;;
            *)         echo "$message" ;;
        esac
    fi
}

# Imprime cabeçalho formatado
print_header() {
    local title="$1"
    if [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "\n${BLUE}======================================================================${NC}"
        echo -e "${BLUE}| ${YELLOW}$title${NC} ${BLUE}|${NC}"
        echo -e "${BLUE}======================================================================${NC}"
    fi
    
    # Adiciona ao relatório em formato Markdown
    echo -e "\n## $title\n" >> "$REPORT_FILE"
    log_message "INFO" "Iniciando módulo: $title"
}

# Registra a saída no console e no arquivo de relatório
log_and_report() {
    local message="$1"
    local log_level="${2:-INFO}"
    
    if [[ "$QUIET_MODE" != "true" ]]; then
        echo -e "$message"
    fi
    
    # Remove códigos de cor para o arquivo de relatório
    local clean_message=$(echo -e "$message" | sed 's/\x1B\[[0-9;]*[JKmsu]//g')
    echo -e "$clean_message" >> "$REPORT_FILE"
    
    log_message "$log_level" "$clean_message"
}

# ------------------------------------------------------------------------------
# Funções de Validação e Sanitização
# ------------------------------------------------------------------------------

# Valida IP ou hostname
validate_ip_or_hostname() {
    local input="$1"
    
    # Verifica se a entrada não está vazia
    if [[ -z "$input" ]]; then
        return 1
    fi
    
    # Remove espaços em branco
    input=$(echo "$input" | tr -d '[:space:]')
    
    # Verifica se contém caracteres perigosos
    if [[ "$input" == *";"* ]] || [[ "$input" == *"&"* ]] || [[ "$input" == *"|"* ]] || \
       [[ "$input" == *'$'* ]] || [[ "$input" == *"("* ]] || [[ "$input" == *")"* ]] || \
       [[ "$input" == *"'"* ]] || [[ "$input" == *'"'* ]] || [[ "$input" == *"<"* ]] || \
       [[ "$input" == *">"* ]] || [[ "$input" == *'`'* ]]; then
        log_message "WARN" "Entrada rejeitada por conter caracteres perigosos: $input"
        return 1
    fi
    
    # Valida IP (formato básico)
    if [[ "$input" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        # Valida cada octeto do IP
        IFS='.' read -ra OCTETS <<< "$input"
        for octet in "${OCTETS[@]}"; do
            if [[ "$octet" -gt 255 ]] || [[ "$octet" -lt 0 ]]; then
                log_message "WARN" "IP inválido: $input - octeto fora do range"
                return 1
            fi
        done
        return 0
    fi
    
    # Valida hostname (formato básico)
    if [[ "$input" =~ ^[a-zA-Z0-9.-]+$ ]] && [[ ${#input} -le 253 ]]; then
        return 0
    fi
    
    log_message "WARN" "Formato de IP/hostname inválido: $input"
    return 1
}

# Valida porta
validate_port() {
    local port="$1"
    
    if [[ -z "$port" ]]; then
        return 1
    fi
    
    # Remove espaços e verifica se é numérico
    port=$(echo "$port" | tr -d '[:space:]')
    
    if [[ ! "$port" =~ ^[0-9]+$ ]]; then
        log_message "WARN" "Porta deve ser numérica: $port"
        return 1
    fi
    
    if [[ "$port" -ge 1 ]] && [[ "$port" -le 65535 ]]; then
        return 0
    fi
    
    log_message "WARN" "Porta fora do range válido (1-65535): $port"
    return 1
}

# Sanitiza parâmetros de URL
sanitize_url_parameter() {
    local param="$1"
    
    # Remove caracteres perigosos para evitar command injection
    echo "$param" | sed 's/[;&|`$()'\''"]//g' | sed 's/<script[^>]*>//gi' | sed 's@</script>@@gi'
}

# Sanitiza entrada geral
sanitize_input() {
    local input="$1"
    
    # Remove caracteres de controle e caracteres perigosos
    echo "$input" | tr -d '\000-\037' | sed 's/[;&|`$()'\''"]//g'
}

# ------------------------------------------------------------------------------
# Funções de Verificação do Sistema
# ------------------------------------------------------------------------------

# Verifica se ferramentas necessárias estão instaladas
check_dependencies() {
    print_header "Verificando Dependências do Sistema"
    
    local missing_deps=0
    local required_tools=("nmap" "curl" "docker")
    local optional_tools=("websocat" "jq")
    
    for cmd in "${required_tools[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_and_report "${RED}[-] Ferramenta necessária não encontrada: $cmd${NC}" "ERROR"
            missing_deps=1
        else
            local version
            case "$cmd" in
                "nmap")
                    version=$(nmap --version 2>/dev/null | head -n1 | cut -d' ' -f3)
                    ;;
                "curl")
                    version=$(curl --version 2>/dev/null | head -n1 | cut -d' ' -f2)
                    ;;
                "docker")
                    version=$(docker --version 2>/dev/null | cut -d' ' -f3 | tr -d ',')
                    ;;
            esac
            log_and_report "${GREEN}[+] $cmd encontrado (versão: ${version:-desconhecida})${NC}"
        fi
    done
    
    for cmd in "${optional_tools[@]}"; do
        if command -v "$cmd" &> /dev/null; then
            log_and_report "${GREEN}[+] Ferramenta opcional encontrada: $cmd${NC}"
        else
            log_and_report "${YELLOW}[!] Ferramenta opcional não encontrada: $cmd${NC}"
        fi
    done
    
    if [[ $missing_deps -eq 1 ]]; then
        log_and_report "${RED}[!] Instale as dependências faltantes para continuar.${NC}" "ERROR"
        return 1
    fi
    
    log_and_report "\n${GREEN}✓ Todas as dependências necessárias estão instaladas.${NC}"
    return 0
}

# Solicita informações do alvo de forma segura
get_target_info() {
    if [[ "$INTERACTIVE_MODE" != "true" ]]; then
        if [[ -z "$TARGET_HOST" ]] || [[ -z "$TARGET_PORT" ]]; then
            log_message "ERROR" "Modo não-interativo requer TARGET_HOST e TARGET_PORT definidos"
            return 1
        fi
        return 0
    fi
    
    # Modo interativo
    while [[ -z "$TARGET_HOST" ]]; do
        echo -n "Por favor, insira o IP ou hostname do alvo: "
        read -r TARGET_HOST
        
        if ! validate_ip_or_hostname "$TARGET_HOST"; then
            echo -e "${RED}Entrada inválida. Tente novamente.${NC}"
            TARGET_HOST=""
        fi
    done
    
    while [[ -z "$TARGET_PORT" ]]; do
        echo -n "Por favor, insira a porta da API REST do alvo: "
        read -r TARGET_PORT
        
        if ! validate_port "$TARGET_PORT"; then
            echo -e "${RED}Porta inválida. Tente novamente.${NC}"
            TARGET_PORT=""
        fi
    done
    
    log_and_report "${GREEN}✓ Alvo configurado para: ${TARGET_HOST}:${TARGET_PORT}${NC}"
    return 0
}

# ------------------------------------------------------------------------------
# Funções de Rede e Conectividade
# ------------------------------------------------------------------------------

# Testa conectividade básica
test_connectivity() {
    local host="$1"
    local port="$2"
    local timeout="${3:-5}"
    
    log_message "DEBUG" "Testando conectividade com $host:$port"
    
    # Testa com netcat se disponível, senão usa telnet
    if command -v nc &> /dev/null; then
        if timeout "$timeout" nc -z "$host" "$port" 2>/dev/null; then
            return 0
        fi
    elif command -v telnet &> /dev/null; then
        if timeout "$timeout" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
            return 0
        fi
    fi
    
    return 1
}

# ------------------------------------------------------------------------------
# Módulos de Teste de Segurança (Melhorados)
# ------------------------------------------------------------------------------

# 1. Reconhecimento e Análise de Superfície de Ataque
recon_and_scan() {
    print_header "MÓDULO 1: Reconhecimento e Varredura de Portas (Nmap)"
    
    if ! test_connectivity "$TARGET_HOST" "$TARGET_PORT" 5; then
        log_and_report "${YELLOW}[!] Aviso: Host $TARGET_HOST:$TARGET_PORT não responde. Continuando com scan...${NC}" "WARN"
    fi
    
    log_and_report "Iniciando varredura de portas TCP e detecção de serviços em ${TARGET_HOST}..."
    log_and_report "Configuração do scan: Timing $NMAP_TIMING, Timeout ${TIMEOUT}s"
    log_and_report "Isso pode levar alguns minutos..."
    
    local nmap_output_file="${REPORT_DIR}/nmap_scan.txt"
    local nmap_cmd="nmap -sV -sC -p- -$NMAP_TIMING --max-rtt-timeout ${TIMEOUT}s"
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        nmap_cmd="$nmap_cmd -v"
    fi
    
    log_message "DEBUG" "Executando comando: $nmap_cmd $TARGET_HOST"
    
    {
        echo -e "\`\`\`"
        if timeout $((TIMEOUT * 10)) $nmap_cmd "$TARGET_HOST" 2>&1; then
            log_message "INFO" "Scan Nmap concluído com sucesso"
        else
            log_message "WARN" "Scan Nmap falhou ou expirou"
            echo "AVISO: Scan falhou ou expirou após $((TIMEOUT * 10)) segundos"
        fi
        echo -e "\`\`\`"
    } | tee "$nmap_output_file" >> "$REPORT_FILE"

    log_and_report "\n${GREEN}[+] Varredura Nmap concluída. Resultados salvos em ${nmap_output_file}${NC}"
    log_and_report "*Análise:* Verifique as portas abertas, versões de software e quaisquer scripts que retornem informações sensíveis. Softwares desatualizados são um grande risco (OWASP A06)."
}

# 2. Testes de Injeção (SQLi, XSS) - Versão Segura
injection_tests() {
    print_header "MÓDULO 2: Testes de Injeção (SQL Injection e XSS)"
    
    local injection_endpoint
    
    if [[ "$INTERACTIVE_MODE" == "true" ]]; then
        log_and_report "Por favor, forneça um endpoint vulnerável a injeção para teste."
        echo -n "Endpoint (ex: /api/v1/tasks/search?name=): "
        read -r injection_endpoint
    else
        injection_endpoint="${INJECTION_ENDPOINT:-/api/v1/test}"
    fi
    
    # Sanitiza o endpoint
    injection_endpoint=$(sanitize_input "$injection_endpoint")
    
    # Valida o formato do endpoint
    if [[ ! "$injection_endpoint" =~ ^/[a-zA-Z0-9/_?=\&-]*$ ]]; then
        log_and_report "${RED}[-] Endpoint inválido ou perigoso: $injection_endpoint${NC}" "ERROR"
        return 1
    fi
    
    local target_url="http://${TARGET_HOST}:${TARGET_PORT}${injection_endpoint}"
    
    # Lista de payloads de teste (seguros para demonstração)
    local sqli_payloads=(
        "' OR '1'='1' --"
        "'; SELECT 'test' --"
        "' UNION SELECT NULL --"
    )
    
    local xss_payloads=(
        "<script>console.log('XSS-TEST')</script>"
        "<img src=x onerror=console.log('XSS')>"
        "javascript:alert('XSS')"
    )
    
    # Teste de SQL Injection
    log_and_report "\n${YELLOW}[*] Testando SQL Injection Básico...${NC}"
    log_and_report "\`\`\`" >> "$REPORT_FILE"
    
    for payload in "${sqli_payloads[@]}"; do
        local safe_payload
        safe_payload=$(sanitize_url_parameter "$payload")
        local encoded_payload
        encoded_payload=$(printf '%s' "$safe_payload" | sed 's/ /%20/g; s/'\''/%27/g; s/"/%22/g')
        
        log_and_report "Testando payload SQLi: ${payload}"
        
        local response
        if response=$(timeout "$TIMEOUT" curl -s -m "$TIMEOUT" --max-redirs 3 "${target_url}${encoded_payload}" 2>&1); then
            echo "$response" | head -c 500 >> "$REPORT_FILE"  # Limita output
            log_message "DEBUG" "SQLi response received for payload: $payload"
        else
            log_and_report "Timeout ou erro na requisição"
            log_message "WARN" "SQLi request failed for payload: $payload"
        fi
    done
    
    log_and_report "\n\`\`\`" >> "$REPORT_FILE"
    log_and_report "*Análise (SQLi):* Se a resposta for diferente da normal (e.g., mais dados retornados, erro de sintaxe SQL), o endpoint pode ser vulnerável (OWASP A03)."

    # Teste de Cross-Site Scripting (XSS) Refletido
    log_and_report "\n${YELLOW}[*] Testando XSS Refletido Básico...${NC}"
    log_and_report "\`\`\`" >> "$REPORT_FILE"
    
    for payload in "${xss_payloads[@]}"; do
        local safe_payload
        safe_payload=$(sanitize_url_parameter "$payload")
        local encoded_payload
        encoded_payload=$(printf '%s' "$safe_payload" | sed 's/ /%20/g; s/</%3C/g; s/>/%3E/g')
        
        log_and_report "Testando payload XSS: ${payload}"
        
        local response
        if response=$(timeout "$TIMEOUT" curl -s -m "$TIMEOUT" --max-redirs 3 "${target_url}${encoded_payload}" 2>&1); then
            echo "$response" | head -c 500 >> "$REPORT_FILE"  # Limita output
            log_message "DEBUG" "XSS response received for payload: $payload"
        else
            log_and_report "Timeout ou erro na requisição"
            log_message "WARN" "XSS request failed for payload: $payload"
        fi
    done
    
    log_and_report "\n\`\`\`" >> "$REPORT_FILE"
    log_and_report "*Análise (XSS):* Se o payload for refletido na resposta HTML sem sanitização, o endpoint é vulnerável (OWASP A03). Verifique o código-fonte da resposta."
}

# 3. Teste de Controle de Acesso Quebrado - Versão Segura
broken_access_control_test() {
    print_header "MÓDULO 3: Teste de Controle de Acesso Quebrado (IDOR)"
    log_and_report "Este teste tenta acessar um recurso que não deveria ser permitido (IDOR - Insecure Direct Object Reference)."
    
    local idor_endpoint own_id other_id bearer_token
    
    if [[ "$INTERACTIVE_MODE" == "true" ]]; then
        log_and_report "Por favor, forneça um endpoint que acesse um recurso por ID."
        echo -n "Endpoint (ex: /api/v1/users/{ID}/profile): "
        read -r idor_endpoint
        echo -n "Insira um ID de recurso que pertence a VOCÊ (para referência): "
        read -r own_id
        echo -n "Insira um ID de recurso que pertence a OUTRO USUÁRIO (para atacar): "
        read -r other_id
        echo -n "Insira seu Bearer Token de autenticação (se necessário, ou deixe em branco): "
        read -r bearer_token
    else
        idor_endpoint="${IDOR_ENDPOINT:-/api/v1/users/{ID}/profile}"
        own_id="${OWN_ID:-1}"
        other_id="${OTHER_ID:-2}"
        bearer_token="${BEARER_TOKEN:-}"
    fi

    # Sanitiza entradas
    idor_endpoint=$(sanitize_input "$idor_endpoint")
    own_id=$(sanitize_input "$own_id")
    other_id=$(sanitize_input "$other_id")
    bearer_token=$(sanitize_input "$bearer_token")
    
    # Valida IDs (devem ser alfanuméricos)
    if [[ ! "$own_id" =~ ^[a-zA-Z0-9_-]+$ ]] || [[ ! "$other_id" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        log_and_report "${RED}[-] IDs devem ser alfanuméricos${NC}" "ERROR"
        return 1
    fi

    local own_url="http://${TARGET_HOST}:${TARGET_PORT}${idor_endpoint//\{ID\}/$own_id}"
    local attack_url="http://${TARGET_HOST}:${TARGET_PORT}${idor_endpoint//\{ID\}/$other_id}"

    local auth_header=""
    if [[ -n "$bearer_token" ]]; then
        auth_header="Authorization: Bearer $bearer_token"
    fi

    log_and_report "\n${YELLOW}[*] Acessando seu próprio recurso...${NC}"
    log_and_report "\`\`\`" >> "$REPORT_FILE"
    
    local own_response
    if own_response=$(timeout "$TIMEOUT" curl -s -m "$TIMEOUT" -H "$auth_header" "$own_url" 2>&1); then
        echo "$own_response" | head -c 500 | tee -a "$REPORT_FILE"
    else
        log_and_report "Erro ou timeout na requisição própria"
    fi
    
    log_and_report "\n\`\`\`" >> "$REPORT_FILE"

    log_and_report "\n${YELLOW}[*] Tentando acessar o recurso de outro usuário...${NC}"
    log_and_report "\`\`\`" >> "$REPORT_FILE"
    
    local attack_response
    if attack_response=$(timeout "$TIMEOUT" curl -s -m "$TIMEOUT" -H "$auth_header" "$attack_url" 2>&1); then
        echo "$attack_response" | head -c 500 | tee -a "$REPORT_FILE"
    else
        log_and_report "Erro ou timeout na requisição de ataque"
    fi
    
    log_and_report "\n\`\`\`" >> "$REPORT_FILE"

    log_and_report "*Análise (IDOR):* Se a resposta para o recurso do outro usuário for bem-sucedida (e.g., status 200 OK com dados) em vez de um erro 403 Forbidden ou 404 Not Found, há uma falha grave de controle de acesso (OWASP A01)."
}

# 4. Varredura Automatizada de API com OWASP ZAP - Versão Segura
api_security_scan_zap() {
    print_header "MÓDULO 4: Varredura Automatizada de API com OWASP ZAP"
    log_and_report "Este módulo usa o Docker para rodar o OWASP ZAP e escanear a API da Atous."

    local openapi_url
    if [[ "$INTERACTIVE_MODE" == "true" ]]; then
        echo -n "Por favor, forneça a URL completa da sua definição OpenAPI/Swagger: "
        read -r openapi_url
    else
        openapi_url="${OPENAPI_URL:-http://${TARGET_HOST}:${TARGET_PORT}/v3/api-docs}"
    fi
    
    # Valida URL
    if [[ ! "$openapi_url" =~ ^https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/.*)?$ ]]; then
        log_and_report "${RED}[-] URL OpenAPI inválida${NC}" "ERROR"
        return 1
    fi
    
    local zap_report_name_base="Atous_API_ZAP_Scan_${TIMESTAMP}"
    local zap_report_dir_container="/zap/wrk/"
    
    log_and_report "${YELLOW}Iniciando OWASP ZAP API Scan...${NC}"
    log_and_report "Os relatórios serão salvos em: ${REPORT_DIR}"

    # Executa o container Docker do ZAP com timeout
    if timeout $((TIMEOUT * 20)) docker run --rm \
        -v "${REPORT_DIR}:${zap_report_dir_container}:rw" \
        owasp/zap2docker-stable \
        zap-api-scan.py \
        -t "$openapi_url" \
        -f openapi \
        -r "${zap_report_name_base}.html" \
        -x "${zap_report_name_base}.xml" \
        -d 2>&1 | tee "${REPORT_DIR}/zap_run.log"; then
        
        if [[ -f "${REPORT_DIR}/${zap_report_name_base}.html" ]]; then
            log_and_report "${GREEN}[+] Scan da API com ZAP concluído. Relatório HTML gerado.${NC}"
            log_and_report "*Análise:* Abra o arquivo '${zap_report_name_base}.html' no seu navegador para ver os resultados detalhados. O ZAP testa uma vasta gama de vulnerabilidades do OWASP Top 10 para APIs."
        else
            log_and_report "${RED}[-] O scan com ZAP não gerou relatórios esperados. Verifique o log em 'zap_run.log'.${NC}" "WARN"
        fi
    else
        log_and_report "${RED}[-] O scan com ZAP falhou ou expirou. Verifique o log em 'zap_run.log'.${NC}" "ERROR"
    fi
}

# 5. Teste de Protocolo WebSocket - Versão Melhorada
websocket_test() {
    print_header "MÓDULO 5: Teste de Protocolos WebSocket"
    
    local ws_url
    if [[ "$INTERACTIVE_MODE" == "true" ]]; then
        echo -n "Insira a URL do WebSocket para teste: "
        read -r ws_url
    else
        ws_url="${WS_URL:-ws://${TARGET_HOST}:${TARGET_PORT}/ws}"
    fi
    
    # Valida URL WebSocket
    if [[ ! "$ws_url" =~ ^wss?://[a-zA-Z0-9.-]+(:[0-9]+)?(/.*)?$ ]]; then
        log_and_report "${RED}[-] URL WebSocket inválida${NC}" "ERROR"
        return 1
    fi

    log_and_report "\n${YELLOW}[*] Verificando se 'websocat' está instalado...${NC}"
    if ! command -v websocat &> /dev/null; then
        log_and_report "${YELLOW}[-] 'websocat' não encontrado. Instalação recomendada para testes avançados.${NC}"
        log_and_report "Ferramentas alternativas: ${YELLOW}wscat${NC}, ou scripts customizados em Python/Node.js."
        log_and_report "URL de instalação: https://github.com/vi/websocat"
    else
        log_and_report "${GREEN}[+] 'websocat' encontrado.${NC}"
        log_and_report "Testando conectividade WebSocket..."
        
        # Teste básico de conectividade WebSocket
        if timeout "$TIMEOUT" websocat --ping-interval 5 --ping-timeout 3 "$ws_url" <<< '{"test":"connectivity"}' 2>/dev/null; then
            log_and_report "${GREEN}[+] Conectividade WebSocket estabelecida${NC}"
        else
            log_and_report "${YELLOW}[!] Não foi possível estabelecer conexão WebSocket${NC}"
        fi
        
        log_and_report "\nExemplo de teste de payload XSS via websocat:"
        log_and_report "\`\`\`bash" >> "$REPORT_FILE"
        log_and_report "echo '{\"message\":\"<img src=x onerror=console.log(1)>\"}' | websocat ${ws_url}"
        log_and_report "\`\`\`" >> "$REPORT_FILE"
    fi

    log_and_report "\n*Análise (WebSocket):* A segurança de WebSockets envolve:"
    log_and_report "  1. ${YELLOW}Validação de Entrada:${NC} O servidor deve sanitizar todas as mensagens recebidas para prevenir XSS e outras injeções."
    log_and_report "  2. ${YELLOW}Controle de Acesso:${NC} A conexão inicial (handshake) deve ser autenticada e autorizada."
    log_and_report "  3. ${YELLOW}Cross-Site WebSocket Hijacking (CSWSH):${NC} O servidor deve validar o cabeçalho 'Origin' no handshake."
    log_and_report "  4. ${YELLOW}Rate Limiting:${NC} Implementar limitação de taxa para prevenir ataques de DoS."
}

# 6. Verificação de Segurança de Cabeçalhos HTTP - Versão Melhorada
http_headers_check() {
    print_header "MÓDULO 6: Verificação de Cabeçalhos de Segurança HTTP"
    log_and_report "Verificando a presença de cabeçalhos de segurança na resposta da API."

    local target_url="http://${TARGET_HOST}:${TARGET_PORT}"
    
    log_and_report "\n${YELLOW}[*] Obtendo cabeçalhos de ${target_url}...${NC}"
    
    local headers
    if headers=$(timeout "$TIMEOUT" curl -s -I -m "$TIMEOUT" "$target_url" 2>&1); then
        log_and_report "\`\`\`" >> "$REPORT_FILE"
        echo "$headers" | tee -a "$REPORT_FILE"
        log_and_report "\`\`\`" >> "$REPORT_FILE"
    else
        log_and_report "${RED}[-] Erro ao obter cabeçalhos HTTP${NC}" "ERROR"
        return 1
    fi
    
    log_and_report "\n*Análise de Cabeçalhos:*"
    
    # Lista expandida de cabeçalhos de segurança recomendados
    local recommended_headers=(
        "Strict-Transport-Security"
        "Content-Security-Policy"
        "X-Content-Type-Options"
        "X-Frame-Options"
        "X-XSS-Protection"
        "Referrer-Policy"
        "Permissions-Policy"
        "Cross-Origin-Embedder-Policy"
        "Cross-Origin-Opener-Policy"
        "Cross-Origin-Resource-Policy"
    )

    local missing_headers=0
    for header in "${recommended_headers[@]}"; do
        if echo "$headers" | grep -q -i "$header:"; then
            log_and_report "${GREEN}[+] Cabeçalho encontrado: $header${NC}"
        else
            log_and_report "${RED}[-] Cabeçalho ausente: $header${NC} (Risco: A05-Security Misconfiguration)"
            missing_headers=$((missing_headers + 1))
        fi
    done
    
    if [[ $missing_headers -gt 0 ]]; then
        log_and_report "\n${YELLOW}[!] $missing_headers cabeçalho(s) de segurança ausente(s)${NC}"
    else
        log_and_report "\n${GREEN}[+] Todos os cabeçalhos de segurança recomendados estão presentes${NC}"
    fi
}

# ------------------------------------------------------------------------------
# Funções de Menu e Interface
# ------------------------------------------------------------------------------

# Mostra ajuda
show_help() {
    cat << EOF
${SCRIPT_NAME} v${SCRIPT_VERSION}

USAGE:
    $0 [OPTIONS]

OPTIONS:
    -h, --help              Mostra esta ajuda
    -v, --version           Mostra a versão
    -q, --quiet             Modo silencioso (apenas erros)
    -d, --debug             Modo debug (verbose)
    -n, --non-interactive   Modo não-interativo
    -t, --target HOST       Define o host alvo
    -p, --port PORT         Define a porta alvo
    --timeout SECONDS       Define timeout para operações (padrão: $DEFAULT_TIMEOUT)
    --timing TIMING         Define timing do Nmap (T0-T5, padrão: $DEFAULT_NMAP_TIMING)
    --report-dir DIR        Define diretório de relatórios

ENVIRONMENT VARIABLES:
    TARGET_HOST             Host alvo
    TARGET_PORT             Porta alvo
    TIMEOUT                 Timeout em segundos
    NMAP_TIMING             Timing do Nmap
    INJECTION_ENDPOINT      Endpoint para teste de injeção
    IDOR_ENDPOINT           Endpoint para teste IDOR
    OPENAPI_URL             URL da documentação OpenAPI
    WS_URL                  URL do WebSocket

EXAMPLES:
    # Modo interativo (padrão)
    $0

    # Modo não-interativo
    $0 -n -t localhost -p 8080

    # Com variáveis de ambiente
    TARGET_HOST=localhost TARGET_PORT=8080 $0 -n

    # Debug mode
    $0 -d -t example.com -p 443

LEGAL NOTICE:
    Este script foi criado para fins educacionais e de testes autorizados.
    Use apenas em sistemas que você possui ou tem permissão explícita para testar.

EOF
}

# Menu principal melhorado
main_menu() {
    while true; do
        echo -e "\n${BLUE}===== SUÍTE DE PENTESTING DA REDE ATOUS (v${SCRIPT_VERSION}) =====${NC}"
        echo "Alvo: ${GREEN}${TARGET_HOST}:${TARGET_PORT}${NC}"
        echo "Relatório sendo salvo em: ${GREEN}${REPORT_FILE}${NC}"
        echo -e "\n${YELLOW}Selecione uma opção de teste:${NC}"
        echo "1.  Reconhecimento e Varredura de Portas (Nmap)"
        echo "2.  Testes de Injeção (SQLi, XSS)"
        echo "3.  Teste de Controle de Acesso Quebrado (IDOR)"
        echo "4.  Varredura Automatizada de API (OWASP ZAP)"
        echo "5.  Teste de Protocolo WebSocket"
        echo "6.  Verificação de Cabeçalhos de Segurança HTTP"
        echo "7.  EXECUTAR TODOS OS TESTES (Exceto ZAP)"
        echo "8.  EXECUTAR SCAN COMPLETO (Todos os testes incluindo ZAP)"
        echo "0.  Sair"
        echo -n "Opção: "
        read -r choice

        case $choice in
            1) recon_and_scan ;;
            2) injection_tests ;;
            3) broken_access_control_test ;;
            4) api_security_scan_zap ;;
            5) websocket_test ;;
            6) http_headers_check ;;
            7)
                log_message "INFO" "Executando bateria completa de testes (exceto ZAP)"
                recon_and_scan
                injection_tests
                broken_access_control_test
                websocket_test
                http_headers_check
                ;;
            8)
                log_message "INFO" "Executando scan completo incluindo ZAP"
                recon_and_scan
                injection_tests
                broken_access_control_test
                api_security_scan_zap
                websocket_test
                http_headers_check
                ;;
            0) 
                log_message "INFO" "Encerrando suite de pentesting"
                break 
                ;;
            *) 
                echo -e "${RED}Opção inválida. Tente novamente.${NC}" 
                ;;
        esac
    done
}

# ------------------------------------------------------------------------------
# Processamento de Argumentos
# ------------------------------------------------------------------------------

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                echo "${SCRIPT_NAME} v${SCRIPT_VERSION}"
                exit 0
                ;;
            -q|--quiet)
                QUIET_MODE=true
                shift
                ;;
            -d|--debug)
                DEBUG_MODE=true
                shift
                ;;
            -n|--non-interactive)
                INTERACTIVE_MODE=false
                shift
                ;;
            -t|--target)
                TARGET_HOST="$2"
                shift 2
                ;;
            -p|--port)
                TARGET_PORT="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --timing)
                NMAP_TIMING="$2"
                shift 2
                ;;
            --report-dir)
                REPORT_DIR="$2"
                REPORT_FILE="${REPORT_DIR}/atous_security_report_${TIMESTAMP}.md"
                shift 2
                ;;
            *)
                echo -e "${RED}Opção desconhecida: $1${NC}" >&2
                echo "Use --help para ver as opções disponíveis."
                exit 1
                ;;
        esac
    done
}

# ------------------------------------------------------------------------------
# Função Principal
# ------------------------------------------------------------------------------

main() {
    # Parse dos argumentos
    parse_arguments "$@"
    
    # Configuração inicial
    mkdir -p "$REPORT_DIR"
    
    # Define umask para arquivos seguros (rw-r-----)
    umask 026
    
    # Header
    if [[ "$QUIET_MODE" != "true" ]]; then
        clear
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║                 ${SCRIPT_NAME} v${SCRIPT_VERSION}                 ║${NC}"
        echo -e "${YELLOW}║                        VERSÃO MELHORADA                          ║${NC}"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
    fi
    
    # Verifica dependências
    if ! check_dependencies; then
        exit 1
    fi
    
    # Obtém informações do alvo
    if ! get_target_info; then
        exit 1
    fi
    
    # Inicia o relatório com permissões seguras
    create_secure_file "$REPORT_FILE" "644"
    {
        echo "# Relatório de Segurança da Rede Atous"
        echo "**Script:** ${SCRIPT_NAME} v${SCRIPT_VERSION}"
        echo "**Data do Teste:** $(date)"
        echo "**Alvo:** ${TARGET_HOST}:${TARGET_PORT}"
        echo "**Modo:** $([ "$INTERACTIVE_MODE" = "true" ] && echo "Interativo" || echo "Não-interativo")"
        echo "---"
    } > "$REPORT_FILE"
    
    log_message "INFO" "Iniciando suite de pentesting para ${TARGET_HOST}:${TARGET_PORT}"
    
    if [[ "$INTERACTIVE_MODE" == "true" ]]; then
        main_menu
    else
        # Modo não-interativo: executa todos os testes
        log_message "INFO" "Executando todos os testes em modo não-interativo"
        recon_and_scan
        injection_tests
        broken_access_control_test
        http_headers_check
        websocket_test
    fi
    
    log_and_report "\n${GREEN}✓ Suíte de Pentesting finalizada.${NC}"
    log_and_report "${GREEN}📄 Relatório completo salvo em: ${REPORT_FILE}${NC}"
    log_and_report "${GREEN}📝 Log detalhado salvo em: ${LOG_FILE}${NC}"
    
    log_message "INFO" "Suite de pentesting finalizada com sucesso"
}

# ------------------------------------------------------------------------------
# Tratamento de Sinais
# ------------------------------------------------------------------------------

cleanup_on_exit() {
    log_message "INFO" "Limpeza em andamento..."
    # Adicione aqui qualquer limpeza necessária
    exit 0
}

trap cleanup_on_exit SIGINT SIGTERM

# ------------------------------------------------------------------------------
# Execução Principal
# ------------------------------------------------------------------------------

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi 