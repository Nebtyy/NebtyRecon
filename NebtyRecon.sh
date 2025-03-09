#!/bin/bash

echo "███╗   ██╗███████╗██████╗ ████████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
████╗  ██║██╔════╝██╔══██╗╚══██╔══╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██╔██╗ ██║█████╗  ██████╔╝   ██║    ╚████╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║╚██╗██║██╔══╝  ██╔══██╗   ██║     ╚██╔╝  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║ ╚████║███████╗██████╔╝   ██║      ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═══╝╚══════╝╚═════╝    ╚═╝      ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
echo "                                                                        Made by Nebty"
# Проверка на наличие двух или трёх аргументов
if [ $# -lt 4 ] || [ $# -gt 4 ]; then
    echo "Usage: $0 <target_domain> <mode> <search_pattern> <sudo_password>"
    exit 1
fi

# Определение целевого домена, режима и шаблона поиска
TARGET="$1"
MODE="$2"
SEARCH_PATTERN="$3"
PASSWORD="$4"

echo "we are preparing the system..."
# Экранирование точки в шаблоне поиска
SEARCH_PATTERN="${SEARCH_PATTERN//./\\.}"

api_key="" # Change this 
virustotal_url="https://www.virustotal.com/api/v3/domains/$TARGET/subdomains"
XSL_PATH=$(find ~ /home /usr /etc /root -type f -name "nmap-bootstrap.xsl" 2>/dev/null | head -n 1)
SECRET_FINDER_PATH=$(find ~ /home /usr /etc /root -type f -name "SecretFinder.py" 2>/dev/null | head -n 1)
WAYMORE_PATH=$(find ~ /home /usr /etc /root -type f -name "waymore.py" 2>/dev/null | head -n 1)
CLOUDRECON_PATH=$(find ~ /home /usr /etc /root -type f -path "*/cloudrecon/main.sh" 2>/dev/null | head -n 1)
AQUATONE_PATH=$(find ~ /home /usr /etc /root -type f -name "aquatone" 2>/dev/null | head -n 1)
BASE_DIR="."
TARGET_DIR="${BASE_DIR}/${TARGET}"
OUTPUT_ALL="${TARGET_DIR}/subdomains/all_subdomains.txt"
OUTPUT_ALL_BEFORE_FILTRING="${TARGET_DIR}/for_debugging/all_subdomains_before_filtering.txt"
OUTPUT_AVAILABLE="${TARGET_DIR}/subdomains/in_scope_available_subdomains.txt"
DOMAIN_FILE="${OUTPUT_AVAILABLE}"
SORTURLS_FILE="${BASE_DIR}/${TARGET_DIR}/for_debugging/sorturls.txt"
SUBZY_OUTPUT="${TARGET_DIR}/reports/subdomain_takeover.txt"
TEMP_SECRET_FILE="${TARGET_DIR}/secrets/secret_findings.txt"
ALL_PARAMETER="${TARGET_DIR}/urls/all_filtered_url.txt"
FILT_PARAM="${TARGET_DIR}/urls/possible_param.txt"
FILT_PATH="${TARGET_DIR}/urls/possible_path.txt"
AVAILABLE_URLS="${TARGET_DIR}/urls/available_urls.txt"
FILT_PARAM_WV="${TARGET_DIR}/urls/possible_parameters_without_value.txt" #For x8
output_file_of_scope_domains="${BASE_DIR}/${TARGET_DIR}/for_debugging/out_of_scope_domains.txt"
SUBDOMAINS_TECHNOLOGY="${TARGET_DIR}/reports/subdomain_technology.txt"

output_dir="${BASE_DIR}/${TARGET}/potential_vulnerable_urls/"
KATANA_OUT="${BASE_DIR}/${TARGET_DIR}/for_debugging/katanaUrls.txt" # Файл для вывода katana , надо в конце удалять подобные файлы
DNSZONETRANSFER="${TARGET_DIR}/reports/dns_zone_transfer.txt"       # Файл для вывода dnsrecon
DNSVULN="${TARGET_DIR}/reports/dns_vulnerabilities.txt"             # Файл для вывода уязвимостей DNS

# Создание директории для вывода, если она не существует
mkdir -p "${TARGET_DIR}"
mkdir -p "${BASE_DIR}/${TARGET_DIR}/urls"
mkdir -p "${BASE_DIR}/${TARGET_DIR}/for_debugging"
mkdir -p "${BASE_DIR}/${TARGET_DIR}/secrets"
mkdir -p "${BASE_DIR}/${TARGET_DIR}/reports"
mkdir -p "${BASE_DIR}/${TARGET_DIR}/subdomains"
mkdir -p "$output_dir"

# Создание всех необходимых файлов перед их очисткой
for file in "${BASE_DIR}/${TARGET_DIR}/for_debugging/domain_out.txt" \
    "${BASE_DIR}/${TARGET_DIR}/for_debugging/domain_out_httpx.txt" \
    "${BASE_DIR}/${TARGET_DIR}/for_debugging/domain_out_uro.txt" \
    "${BASE_DIR}/${TARGET_DIR}/for_debugging/domain_out_gau.txt" \
    "${BASE_DIR}/${TARGET_DIR}/for_debugging/unique_urls.txt" \
    "${TEMP_SECRET_FILE}" \
    "${SORTURLS_FILE}" \
    "${SUBZY_OUTPUT}" \
    "${ALL_PARAMETER}" \
    "${FILT_PARAM}" \
    "${FILT_PATH}" \
    "${FILT_PARAM_WV}" \
    "${AVAILABLE_URLS}" \
    "${DNSZONETRANSFER}" \
    "${DNSVULN}" \
    "${KATANA_OUT}"; do
    touch "$file"
done

date "+%Y-%m-%d %H:%M:%S"

# Функция для проверки доступности домена
check_domain() {

    echo "Проверка доступности домена ${TARGET}..."
    HTTP_STATUS=$(curl -o /dev/null -s -w "%{http_code}\n" "${TARGET}")

    if [[ "$HTTP_STATUS" -lt 200 || "$HTTP_STATUS" -ge 300 ]]; then
        echo "Домен ${TARGET} доступен, но HTTP статус: ${HTTP_STATUS}. Продолжаем выполнение скрипта."
    else
        echo "Домен ${TARGET} доступен с HTTP статусом: ${HTTP_STATUS}."
    fi
}

# Функция для поиска поддоменов с использованием различных инструментов
search_subdomains() {
    echo "Запуск поиска поддоменов для ${TARGET}..."

    # subfinder
    #echo "subfinder"
    #subfinder -recursive -d "${TARGET}" | sort -u >"${TARGET_DIR}/${TARGET}_subfinder.txt"

    # sublist3r
    echo "sublist3r"
    sublist3r -d "${TARGET}" -o "${TARGET_DIR}/${TARGET}_sublist3r.txt"

    # crt.sh
    echo "crt.sh"
    curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >"${TARGET_DIR}/${TARGET}_crt.sh.txt"
    if [ $? -ne 0 ]; then
        echo "Ошибка при обработке данных crt.sh. Проверьте формат ответа."
    fi

    # amass
    echo "amass"
    amass enum -passive -d "${TARGET}" | sort -u >"${TARGET_DIR}/${TARGET}_amass.txt"

    # assetfinder
    echo "assetfinder"
    assetfinder "${TARGET}" | sort -u >"${TARGET_DIR}/${TARGET}_assetfinder.txt"

    # virustotal
    echo "virustotal"
    # VirusTotal - Подсчет общего числа результатов
    
    count=$(curl -s -X GET "$virustotal_url" --header "x-apikey: $api_key" | jq -r .meta.count)

    # Проверка и расчет числа итераций
    if [[ -z "$count" || "$count" -eq 0 ]]; then
        echo "No results found or unable to fetch count"
        exit 1
    fi

    check=$((count / 40))
    check_2=$((count % 40))
    if [ "$check_2" -gt 0 ]; then
        iters=$((check + 1))
    else
        iters=$check
    fi

    # Итерации, так как лимит API - 40
    cursor="?cursor=&limit=40"
    for ((i = 1; i <= iters; i++)); do
        response=$(curl -s -X GET "$virustotal_url$cursor" --header "x-apikey: $api_key")
        if [[ -z "$response" ]]; then
            echo "No response from API"
            break
        fi

        # Извлечение ID и запись в файл
        echo "$response" | jq -r .data[].id | sort -u >>"${TARGET_DIR}/${TARGET}_virus-total-api-subs.txt"

        # Получение следующего курсора
        next=$(echo "$response" | jq -r .links.next)
        if [[ -n "$next" ]]; then
            cursor=$(echo "$next" | grep -oE "\?.*")
        else
            break
        fi
    done

    echo "VirusTotal fetching completed"

    echo "bash $CLOUDRECON_PATH -u -s $TARGET"
    bash "${CLOUDRECON_PATH}" -u -s "$TARGET" | grep -v "*" > "${TARGET_DIR}/${TARGET}_main_sh.txt"

}


add_more_subdomains() {
    echo "Would you like to add additional subdomains? (yes/no)"
    > "${OUTPUT_ALL_BEFORE_FILTRING}"
    read -r response

    if [[ "$response" =~ ^[Yy]es$ ]]; then
        echo "Please enter the subdomains, each on a new line (press Enter twice to finish):"

        additional_subdomains=""
        while true; do
            read -r line
            if [[ -z "$line" ]]; then
                break # Exit the loop if the user presses Enter without input
            fi
            additional_subdomains+="$line"$'\n' # Append each subdomain with a newline
        done

        # Remove the trailing newline character and any empty lines
        additional_subdomains=$(echo -e "$additional_subdomains" | sed '/^$/d')
        echo -e "$additional_subdomains" >>"${OUTPUT_ALL_BEFORE_FILTRING}"

        echo "Additional subdomains added to the file ${OUTPUT_ALL_BEFORE_FILTRING}."
    fi
}

add_out_of_scope_domains() {
    touch "$output_file_of_scope_domains"
    echo "Would you like to add out-of-scope domains? (yes/no)"
    output_file_of_scope_domains="${BASE_DIR}/${TARGET_DIR}/for_debugging/out_of_scope_domains.txt"
    if [ -f "$output_file_of_scope_domains" ]; then
        > "$output_file_of_scope_domains"
    fi
    read -r response

    if [[ "$response" =~ ^[Yy]es$ ]]; then
        echo "Please enter the out-of-scope domains, each on a new line (press Enter twice to finish):"

        out_of_scope_domains=""
        while true; do
            read -r line
            if [[ -z "$line" ]]; then
                break # Выход из цикла, если пользователь нажимает Enter без ввода
            fi
            out_of_scope_domains+="$line"$'\n' # Добавляем каждый домен с новой строкой
        done

        # Удаляем пустые строки
        out_of_scope_domains=$(echo -e "$out_of_scope_domains" | sed '/^$/d')

        # Записываем в файл
        
        echo -e "$out_of_scope_domains" >>"$output_file_of_scope_domains"

        echo "Out-of-scope domains have been added to the file $output_file_of_scope_domains."
    else
        echo "No domains were added."
    fi
}
# Функция для объединения результатов и удаления дубликатов
combine_results() {
    echo "Объединение результатов и удаление дубликатов..."

    cat "${TARGET_DIR}/${TARGET}_subfinder.txt" \
        "${TARGET_DIR}/${TARGET}_sublist3r.txt" \
        "${TARGET_DIR}/${TARGET}_crt.sh.txt" \
        "${TARGET_DIR}/${TARGET}_amass.txt" \
        "${OUTPUT_ALL_BEFORE_FILTRING}" \
        "${TARGET_DIR}/${TARGET}_virus-total-api-subs.txt" \
        "${TARGET_DIR}/${TARGET}_main_sh.txt" \
        "${TARGET_DIR}/${TARGET}_assetfinder.txt" | sort -u > "${OUTPUT_ALL_BEFORE_FILTRING}"
        
        
    >"${OUTPUT_ALL}"    
    cat ${OUTPUT_ALL_BEFORE_FILTRING} | sort -u | grep -v "*">> "${OUTPUT_ALL}"

    # Удаление временных файлов
    rm -f "${TARGET_DIR}/${TARGET}_subfinder.txt" \
        "${TARGET_DIR}/${TARGET}_sublist3r.txt" \
        "${TARGET_DIR}/${TARGET}_crt.sh.txt" \
        "${TARGET_DIR}/${TARGET}_amass.txt" \
        "${TARGET_DIR}/${TARGET}_main_sh.txt" \
        "${OUTPUT_ALL_BEFORE_FILTRING}" \ 
        
    echo ${PASSWORD} | sudo -S rm "${TARGET_DIR}/${TARGET}_virus-total-api-subs.txt" \
        "${TARGET_DIR}/${TARGET}_assetfinder.txt"
}
# Функция для проверки доступности поддоменов с использованием xargs

check_availability() {
    echo "Проверка доступности поддоменов с использованием httpx..."

    local ALL_SCOPE="${TARGET_DIR}/for_debugging/all_subdomains.txt"

    if [ -z "$SEARCH_PATTERN" ]; then
        echo "Ошибка: Шаблон поиска не задан. Проверьте аргументы."
        exit 1
    fi

    >"${OUTPUT_AVAILABLE}"
    >"${ALL_SCOPE}"
    >"${SUBDOMAINS_TECHNOLOGY}"

    # Фильтрация поддоменов по шаблону и проверка доступности с помощью httpx
    grep "${SEARCH_PATTERN}" "${OUTPUT_ALL}" | httpx -silent -status-code -threads 50 | grep -E "200|301|302|307|403|401" | awk '{print $1}' >>"${ALL_SCOPE}"

    echo "Фильтрация поддоменов вне зоны..."
    cat "${ALL_SCOPE}" | grep -vFf "$output_file_of_scope_domains" >>"${OUTPUT_AVAILABLE}"
    cat "${OUTPUT_AVAILABLE}" | httpx -title -tech-detect -status-code -follow-host-redirects -max-redirects 2 | sed 's/\x1b\[[0-9;]*m//g' >>"${SUBDOMAINS_TECHNOLOGY}"

    echo "Процесс проверки доступности завершён."
}


run_nmap() {
    echo "Запуск Nmap..."

    # Путь к отчету
    local BBNMAP_SCAN_OUT="${TARGET_DIR}/reports/bbnmap_scan.html"
    local BBNMAP_SCAN_BASE="${TARGET_DIR}/reports/bbnmap_scan"

    # Преобразование списка URL-ов, удаляя https:// или http://
    local NMAP_TARGETS_FILE=$(mktemp)
    cat "${OUTPUT_AVAILABLE}" | sed 's/^https\?:\/\///' > "$NMAP_TARGETS_FILE"

    # Запуск Nmap с использованием временного файла
    echo ${PASSWORD} | sudo -S nmap -iL "$NMAP_TARGETS_FILE" -sS -T4 -A -sC -p- \
        -oA "${BBNMAP_SCAN_BASE}" -Pn --min-rate 5000 --max-retries 1 --max-scan-delay 20ms \
         --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl

    # Проверка, был ли создан отчет
    if [ ! -f "${BBNMAP_SCAN_BASE}.xml" ]; then
        echo "Ошибка: Файл bbnmap_scan.xml не был создан."
        rm -f "$NMAP_TARGETS_FILE"  # Удалить временный файл
        exit 1
    fi

    echo "Преобразование результата в HTML..."
    xsltproc -o "${BBNMAP_SCAN_OUT}" "${XSL_PATH}" "${BBNMAP_SCAN_BASE}.xml"

    if [ ! -f "${BBNMAP_SCAN_OUT}" ]; then
        echo "Ошибка: Не удалось создать HTML отчет."
        rm -f "$NMAP_TARGETS_FILE"  # Удалить временный файл
        exit 1
    fi

    echo "Отчет доступен по пути: ${BBNMAP_SCAN_OUT}."
    rm -f "${BBNMAP_SCAN_BASE}".{gnmap,nmap,xml} "$NMAP_TARGETS_FILE"  # Удалить временные файлы
    echo "Временные файлы удалены."
}



take_screenshots() {
    cat "${OUTPUT_AVAILABLE}" | "${AQUATONE_PATH}" -out "${TARGET_DIR}/domain_screens/"
}

find_open_redirects() {
    echo "Поиск Open Redirect уязвимостей..."

    local REDIRECT_OUT="${TARGET_DIR}/reports/open_redirect_results.txt"
    >"${REDIRECT_OUT}"

    while IFS= read -r subdomain; do
        if [[ -z "$subdomain" || "$subdomain" =~ ^# ]]; then
            continue
        fi

        local url="https://${subdomain}//evil.com"
        local response=$(curl -s -L -I "$url" | grep -i "^Location:")

        if [[ -z "$response" ]]; then
            echo "Ничего не найдено для ${subdomain}" >>"$REDIRECT_OUT"
        else
            echo "Редирект на: ${response#Location: } для ${subdomain}" >>"$REDIRECT_OUT"
        fi
    done <"${OUTPUT_AVAILABLE}"

    echo "Результаты записаны в файл: $REDIRECT_OUT"
}

find_crlf_injection() {
    echo "Поиск CRLF Injection уязвимостей..."

    # Указываем файл для результатов
    local CRLF_OUT="${TARGET_DIR}/reports/crlf_injection_results.txt"
    >"${CRLF_OUT}"  # Очищаем файл перед записью

    # Проверяем существование файла с поддоменами
    if [[ ! -f "${OUTPUT_AVAILABLE}" ]]; then
        echo "Файл с поддоменами не найден: ${OUTPUT_AVAILABLE}"
        exit 1
    fi

    # Перебираем поддомены из файла
    while IFS= read -r subdomain; do
        # Пропускаем пустые строки и строки с комментариями
        if [[ -z "$subdomain" || "$subdomain" =~ ^# ]]; then
            continue
        fi

        # Формируем целевой URL с CRLF полезной нагрузкой
        local url="https://${subdomain}/%0aSet-Cookie:whoami=nebty"

        # Выполняем запрос, следуем редиректам (-L) и ищем `Set-Cookie:` с новой строки
        local response=$(curl -s -L -I "$url" | awk '/^Set-Cookie:/ {getline; print}')

        # Проверяем на наличие Set-Cookie после редиректа
        if [[ -z "$response" ]]; then
            echo "CRLF не обнаружен для ${subdomain}" >>"$CRLF_OUT"
        else
            echo "CRLF найден: ${response} для ${subdomain}" >>"$CRLF_OUT"
        fi
    done <"${OUTPUT_AVAILABLE}"

    echo "Результаты записаны в файл: $CRLF_OUT"
}



dns_zone_transfer_check() {
    echo "Запуск проверки зон DNS..."
    >"${DNSZONETRANSFER}"
    >"${DNSVULN}"

    while read -r domain; do
        echo "Проверка зоны для: $domain..."
        dnsrecon -d "$domain" -t axfr >>"${DNSZONETRANSFER}"
        echo "------------------------------------------------------------------------" >>"${DNSZONETRANSFER}"
    done <"${OUTPUT_AVAILABLE}"

    echo "Фильтрация успешных зоновых трансферов..."
    grep "Zone Transfer successful" "${DNSZONETRANSFER}" >"${DNSVULN}"
}

check_TLS() {
    # Имя файла с поддоменами
    input="${OUTPUT_AVAILABLE}"

    # Директория для результатов
    sslscan_output="${TARGET_DIR}/for_debugging/sslscan_results.txt"
    vulnerabilities_report="${TARGET_DIR}/reports/tls_vulnerabilities_report.txt"

    # Очистка файлов перед записью
    >"$sslscan_output"
    >"$vulnerabilities_report"

    # Проверяем существование файла с доменами
    if [[ ! -f "$input" ]]; then
        echo "Файл с доменами не найден: $input"
        exit 1
    fi

    # Функция для выполнения sslscan и записи результата в файл
    perform_sslscan() {
        local domain="$1"
         echo "================================================================================" >> "$sslscan_output"

        # Запуск sslscan и удаление цветовых кодов из вывода
        echo "Scanning $domain..." | tee -a "$sslscan_output"
        sslscan --sleep=200 "$domain" | sed 's/\x1B\[[0-9;]*[JKmsu]//g' >>"$sslscan_output"

        # Добавляем красивое разделение после каждого домена в отчёт
        echo -e "\n$(printf '=%.0s' {1..80})\n" >>"$sslscan_output"
    }

    # Функция для анализа уязвимостей в результатах сканирования
    analyze_vulnerabilities() {
        local input_file="$1"

        # Чтение файла и поиск уязвимостей
        while IFS= read -r line; do
            # Определяем домен для текущего сканирования
            if [[ "$line" =~ Scanning\ (.+)\.\.\. ]]; then
                domain="${BASH_REMATCH[1]}"
                # Выводим разделитель и домен
                echo "================================================================================" >>"$vulnerabilities_report"
                echo "Scanning $domain..." >>"$vulnerabilities_report"
            fi

            # Ищем уязвимости и добавляем их в файл
            # 1. Фильтрация для SSLv2, SSLv3, TLSv1.0 и TLSv1.1, если они включены
            if [[ "$line" =~ SSLv2.*enabled ]]; then
                echo "  $line" >>"$vulnerabilities_report"
            fi
            if [[ "$line" =~ SSLv3.*enabled ]]; then
                echo "  $line" >>"$vulnerabilities_report"
            fi
            if [[ "$line" =~ TLSv1\.0.*enabled ]]; then
                echo "  $line" >>"$vulnerabilities_report"
            fi
            if [[ "$line" =~ TLSv1\.1.*enabled ]]; then
                echo "  $line" >>"$vulnerabilities_report"
            fi

            # 2. Heartbleed уязвимость
            if [[ "$line" =~ vulnerable\ to\ heartbleed && ! "$line" =~ not ]]; then
                echo "  $line" >>"$vulnerabilities_report"
            fi

            # 3. TLS Compression включен
            if [[ "$line" =~ Compression\ enabled ]]; then
                echo "  $line" >>"$vulnerabilities_report"
            fi

            # 4. TLS renegotiation поддержка/неподдержка
            if [[ "$line" =~ "TLS renegotiation:.*supported" || "$line" =~ "TLS renegotiation:.*not supported" ]]; then
                echo "  $line" >>"$vulnerabilities_report"
            fi

            # 5. Используется самоподписанный сертификат
            if [[ "$line" =~ Self-signed\ certificate ]]; then
                echo "  $line" >>"$vulnerabilities_report"
            fi

            # 6. HSTS отсутствует
            if [[ "$line" =~ Strict-Transport-Security && ! "$line" =~ missing ]]; then
                echo "  $line" >>"$vulnerabilities_report"
            fi

            # 7. Слабые шифры
            if [[ "$line" =~ RC4|DES|3DES|RC2 ]]; then
                echo "  $line" >>"$vulnerabilities_report"
            fi

            # 8. Слабые группы для обмена ключами
            if [[ "$line" =~ weak\ dh\ group ]]; then
                echo "  $line" >>"$vulnerabilities_report"
            fi

            # 9. Проблемы с сертификатом (RSA < 2048 бит)
            if [[ "$line" =~ RSA\ Key\ Strength:.*\b[1-9][0-9]{0,3}\b ]]; then
                echo "  $line" >>"$vulnerabilities_report"
            fi

        done <"$input_file"

    }

    # Основной процесс: чтение доменов и их сканирование
    while IFS= read -r domain; do
        domain=$(echo "$domain" | xargs) # Удаление лишних пробелов
        if [[ -n "$domain" ]]; then      # Пропуск пустых строк
            perform_sslscan "$domain"
        fi
    done <"$input"

    echo "Результаты сканирования сохранены в файл: $sslscan_output"

    # Анализ уязвимостей
    analyze_vulnerabilities "$sslscan_output"
    echo "Результаты уязвимостей сохранены в файл: $vulnerabilities_report"
}



# Функция для запуска subzy
run_subzy() {
    echo "Запуск subzy для обработки поддоменов..."
    if command -v subzy &>/dev/null; then
        subzy run --targets "${OUTPUT_ALL}" >"${SUBZY_OUTPUT}"
        echo "Вывод subzy сохранен в ${SUBZY_OUTPUT}"
    else
        echo "Ошибка: Команда subzy не найдена."
    fi
}

# Функция для поиска и обработки URL с использованием waybackurls, gau, katana
find_urls() {
    # Определение переменных
    DOMAIN_FILE="${OUTPUT_AVAILABLE}"
    DOMAIN_OUT="${BASE_DIR}/${TARGET_DIR}/for_debugging/domain_out.txt"
    HTTPX_OUT="${BASE_DIR}/${TARGET_DIR}/for_debugging/domain_out_httpx.txt"
    GAU_OUT="${BASE_DIR}/${TARGET_DIR}/for_debugging/domain_out_gau.txt"
    UNIQUE_URLS="${BASE_DIR}/${TARGET_DIR}/for_debugging/unique_urls.txt"
    KATANA_OUT="${BASE_DIR}/${TARGET_DIR}/for_debugging/katanaUrls.txt"
    ALL_PARAMETER="${TARGET_DIR}/urls/all_filtered_url.txt"
    FILT_PARAM="${TARGET_DIR}/urls/possible_param.txt"
    FILT_PATH="${TARGET_DIR}/urls/possible_path.txt"
    AVAILABLE_URLS="${TARGET_DIR}/urls/available_urls.txt"

    echo "Очистка всех выходных файлов..."
    #>"${DOMAIN_OUT}"
    >"${HTTPX_OUT}"
    >"${GAU_OUT}"
    >"${UNIQUE_URLS}"
    >"${KATANA_OUT}"
    >"${ALL_PARAMETER}"
    >"${FILT_PARAM}"
    >"${FILT_PATH}"
    >"${AVAILABLE_URLS}"

    # Проверка входного файла
    echo "Проверка содержимого DOMAIN_FILE: ${DOMAIN_FILE}"
    if [[ ! -s "${DOMAIN_FILE}" ]]; then
        echo "Ошибка: DOMAIN_FILE пустой или не существует."
        return 1
    fi

    # Step 1: Получение URL с помощью waybackurls
    echo "Получение URL через waymore..."
    if command -v python &>/dev/null && [ -f "${WAYMORE_PATH}" ]; then
        python3 "${WAYMORE_PATH}" -i "${TARGET}" -mode U -oU "${DOMAIN_OUT}" --config ../config.yml
    else
    echo "Ошибка: Скрипт waymore не найден или не установлен Python."
    fi

    # Step 2: Получение URL с помощью gau
    echo "Получение URL через gau..."
    if command -v gau &>/dev/null; then
        cat "${DOMAIN_FILE}" | gau >>"${GAU_OUT}"
    else
        echo "Ошибка: Команда gau не найдена."
    fi

    # Step 3: Запуск katana
    echo "Запуск katana..."
    if command -v katana &>/dev/null; then
        cat "${DOMAIN_OUT}" | uro | uniq | sort -u | \
            grep "${SEARCH_PATTERN}" | katana  | grep "${SEARCH_PATTERN}" | hakrawler -d 3 | sort -u >>"${KATANA_OUT}"      
    else
        echo "Ошибка: Команда katana не найдена."
    fi  

    # Step 4: Проверка доступности URL через httpx
    echo "Проверка доступности URL через httpx..."
    if command -v httpx &>/dev/null; then
        cat "${DOMAIN_OUT}" "${GAU_OUT}" "${KATANA_OUT}" | uro | httpx >>"${HTTPX_OUT}"
    else
        echo "Ошибка: Команда httpx не найдена."
    fi

    # Step 5: Сбор уникальных URL
    echo "Сбор всех уникальных URL..."
    cat "${HTTPX_OUT}" | uro | sort -u >"${UNIQUE_URLS}"

    # Step 6: Фильтрация URL для параметров и путей
    echo "Фильтрация параметров и путей..."
    cat "${UNIQUE_URLS}" | sed -E 's#https?://[^/]+(/[^?]*).*#\1#' | grep -v "http" | sort -u >"${FILT_PATH}"
    cat "${UNIQUE_URLS}" | sed -E 's#.*\?(.*)#\1#' | tr '&' '\n' | grep -v "http" | sort -t'=' -k1,1 -u >"${FILT_PARAM}"

    echo "Процесс find_urls завершен."
    cat "${UNIQUE_URLS}" | grep "${SEARCH_PATTERN}" | sort -u | uro | tee -a "${ALL_PARAMETER}"
}


# Функция для поиска секретов в JavaScript файлах
find_secrets() {
    echo "Поиск конфиденциальных данных в JavaScript файлах..."

    echo "Очистка всех выходных файлов..."
    >"${TEMP_SECRET_FILE}"

    # Определение директорий и файлов
    BASE_DIR="."
    DOMAIN_FILE="${BASE_DIR}/${TARGET_DIR}/for_debugging/domain_out_httpx.txt"
    SORTURLS_FILE="${BASE_DIR}/${TARGET_DIR}/for_debugging/sorturls.txt"

    # Очистка файла sorturls.txt
    echo "Очистка файла ${SORTURLS_FILE}..."
    >"${SORTURLS_FILE}"

    # Поиск строк, содержащих указанный шаблон и ".js", и запись в sorturls.txt
    echo "Поиск и запись URL в ${SORTURLS_FILE} с шаблоном '${SEARCH_PATTERN}'..."
    grep "${SEARCH_PATTERN}" "${DOMAIN_FILE}" | grep ".js" >"${SORTURLS_FILE}"

    # Проверка наличия строк в sorturls.txt
    if [ ! -s "${SORTURLS_FILE}" ]; then
        echo "Файл ${SORTURLS_FILE} пуст. Нет URL для обработки."
        exit 0
    fi

    # Обработка каждой строки из sorturls.txt с помощью SecretFinder.py
    echo "Обработка URL с помощью SecretFinder.py..."
    while IFS= read -r url; do
        python "${SECRET_FINDER_PATH}" -i "$url" -o cli >>"${TEMP_SECRET_FILE}"
    done <"${SORTURLS_FILE}"

    echo "Процесс завершен."

    echo "Результаты поиска конфиденциальных данных сохранены в ${TEMP_SECRET_FILE}"
}

Sort_Urls_Like_Possible_Vuln() {
    echo "сортировка urls..."
    output_dir="${BASE_DIR}/${TARGET}/potential_vulnerable_urls/"

    # Паттерны для параметров, которые могут указывать на уязвимости
    open_redirect_pattern="([?&](redirect|url|destination|next|link|return|redir|go|continue|target|back|forward|reload|location|path|redirect_uri|goto|start|loc)[^&]*)"
    ssrf_pattern="([?&](url|target|destination|proxy|request|host|server|file|endpoint|redirect|fetch|load|source|port|vhost|path|localhost|backend|forward|forwarded|forwarded-for|range)[^&]*)"
    lfi_pattern="([?&](file|path|page|doc|dir|include|view|content|filename|template|source|root|url|document|log|config|uploads|var|etc|windows|template|script|config|wp-content|media|debug)[^&]*)"
    xss_pattern="([?&](q|search|query|input|ref|url|js|script|message|comment|id|name|data|redirect|goto|value|username|value|password|cookie|meta|http-equiv|header|form|content|action)[^&]*)"
    sql_injection_pattern="([?&](id|search|q|query|page|input|user|pass|value|table|column|order|limit|count|offset|group|union|select|insert|drop|--|%27|%22|%3B|%3D|%2D%2D|%2F%2A|%2A%2F|%2F%2D|%3C|%3E|%28|%29|%24|%2F|%40|%5C|%2F%3A)|\.php|\.asp|\.aspx|\.jsp|\.jspx)"
    secret_document_pattern="\.xls$|\.tar\.gz$|\.bak$|\.xml$|\.xlsx$|\.json$|\.rar$|\.pdf$|\.sql$|\.doc$|\.docx$|\.pptx$|\.txt$|\.git$|\.zip$|\.tgz$|\.7z$"

    # Чтение URL-ов из файла и анализ
    while IFS= read -r url; do
        # Поиск Open Redirect
        echo "$url" | grep -E "$open_redirect_pattern"| sort -u  >>"$output_dir/open_redirect.txt"

        # Поиск SSRF
        echo "$url" | grep -E "$ssrf_pattern"| sort -u  >>"$output_dir/ssrf.txt"

        # Поиск LFI
        echo "$url" | grep -E "$lfi_pattern" | sort -u  >>"$output_dir/lfi.txt"

        # Поиск XSS
        echo "$url" | grep -E "$xss_pattern"| sort -u  >>"$output_dir/xss.txt"

        # Поиск SQL инъекций
        echo "$url" | grep -E "$sql_injection_pattern" | sort -u  >>"$output_dir/sql_injections.txt"

        # Поиск утечек секретных документов
        echo "$url" | grep -E "$secret_document_pattern" | sort -u  >>"$output_dir/sensitive_docs.txt"
    done <"${ALL_PARAMETER}"

    echo "Анализ завершен. Результаты находятся в директории $output_dir."
    

}
check_host_access() {
    # Убираем протокол (http:// или https://) из URL
    domain=$(echo "$TARGET" | sed -e 's|^https\?://||' -e 's|/$||')

    # Получаем конечный URL, если происходит редирект
    final_url=$(curl -Ls -o /dev/null -w %{url_effective} "$TARGET" 2>/dev/null)

    # Если curl не может получить URL (например, нет ответа), используем исходный домен
    if [ -z "$final_url" ]; then
        final_url="$domain"
    else
        # Убираем протокол из конечного URL
        final_url=$(echo "$final_url" | sed -e 's|^https\?://||' -e 's|/$||')
    fi
    
    # Пингуем конечный URL или исходный домен
    while ! ping -c 1 -W 1 "$final_url" &>/dev/null; do
        echo "Хост $final_url недоступен. Ожидаю подключения..."
        sleep 5 # Подождем перед повторной проверкой
    done
}



# Главная логика работы скрипта, в зависимости от выбранного режима
case "$MODE" in
"search")
    #check_host_access
    add_more_subdomains
    add_out_of_scope_domains
    #check_host_access
    check_domain
    #check_host_access
    search_subdomains
    #check_host_access
    combine_results
    ;;

"find")
    #check_host_access
    check_availability
    #check_host_access
    run_nmap
    #check_host_access
    take_screenshots
    #check_host_access
    find_open_redirects
    #check_host_access
    find_crlf_injection
    #check_host_access
    dns_zone_transfer_check
    #check_host_access
    run_subzy
    #check_host_access
    check_TLS
    ;;

"process")
    #check_host_access
    find_urls
    #check_host_access
    find_secrets
    #check_host_access
    Sort_Urls_Like_Possible_Vuln
    ;;

"all")
    #check_host_access
    add_more_subdomains
    add_out_of_scope_domains
    #check_host_access
    check_domain
    #check_host_access
    search_subdomains
    #check_host_access
    combine_results
    #check_host_access
    check_availability
    #check_host_access
    run_nmap
    #check_host_access
    take_screenshots
    #check_host_access
    find_open_redirects
    #check_host_access
    find_crlf_injection
    #check_host_access
    dns_zone_transfer_check
    #check_host_access
    run_subzy
    #check_host_access
    check_TLS
    #check_host_access
    find_urls
    #check_host_access
    find_secrets
    #check_host_access
    Sort_Urls_Like_Possible_Vuln
    ;;

*)
    echo "Not allowed modes: ${MODE}"
    echo "Acceptable modes: search, find, process, all"
    exit 1
    ;;
esac

echo "Завершено!"
date "+%Y-%m-%d %H:%M:%S"
