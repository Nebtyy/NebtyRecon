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

XSL_PATH=$(find ~ /home /usr /etc -type f -name "nmap-bootstrap.xsl" 2>/dev/null | head -n 1)
SECRET_FINDER_PATH=$(find ~ /home /usr /etc -type f -name "SecretFinder.py" 2>/dev/null | head -n 1)
BASE_DIR="."
TARGET_DIR="${BASE_DIR}/${TARGET}"
OUTPUT_ALL="${TARGET_DIR}/${TARGET}_all_subdomains.txt"
OUTPUT_AVAILABLE="${TARGET_DIR}/${TARGET}_available_subdomains.txt"
DOMAIN_FILE="${OUTPUT_AVAILABLE}"
SORTURLS_FILE="${BASE_DIR}/wayback/sorturls.txt"
SECRET_FINDER_PATH="/home/kali/Downloads/secretfinder/SecretFinder.py"
SUBZY_OUTPUT="${TARGET_DIR}/subzy_output.txt"
TEMP_SECRET_FILE="${TARGET_DIR}/secretfind_output.txt"
ALL_PARAMETER="${TARGET_DIR}/all_url_with_filtered_parametr"  #записывать после uro последнего файла
FILT_PARAM="${TARGET_DIR}/possible_parameters.txt"
FILT_PATH="${TARGET_DIR}/possible_path.txt"
AVAILABLE_URLS="${TARGET_DIR}/Available_urls.txt"
FILT_PARAM_WV="${TARGET_DIR}/possible_parameters_without_value.txt"

KATANA_OUT="${BASE_DIR}/wayback/katanaUrls.txt"  # Файл для вывода katana
DNSZONETRANSFER="${TARGET_DIR}/DNSzonetransfer.txt"  # Файл для вывода dnsrecon
DNSVULN="${TARGET_DIR}/DNSVULN.txt"  # Файл для вывода уязвимостей DNS

# Создание директории для вывода, если она не существует
mkdir -p "${TARGET_DIR}"
mkdir -p "${BASE_DIR}/wayback"

# Создание всех необходимых файлов перед их очисткой
for file in "${BASE_DIR}/wayback/domain_out.txt" \
            "${BASE_DIR}/wayback/domain_out_httpx.txt" \
            "${BASE_DIR}/wayback/domain_out_uro.txt" \
            "${BASE_DIR}/wayback/domain_out_gau.txt" \
            "${BASE_DIR}/wayback/unique_urls.txt" \
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

> "${DNSZONETRANSFER}"
> "${DNSVULN}"

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
    echo "subfinder"
    subfinder  -recursive -d "${TARGET}" | sort -u > "${TARGET_DIR}/${TARGET}_subfinder.txt"

    # sublist3r
    echo "sublist3r"
    sublist3r -d "${TARGET}" -o "${TARGET_DIR}/${TARGET}_sublist3r.txt"

    # crt.sh
    echo "crt.sh"
    curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > "${TARGET_DIR}/${TARGET}_crt.sh.txt"
    if [ $? -ne 0 ]; then
        echo "Ошибка при обработке данных crt.sh. Проверьте формат ответа."
    fi

    # amass
    echo "amass"
    amass enum -passive -d "${TARGET}" | sort -u > "${TARGET_DIR}/${TARGET}_amass.txt"

    # assetfinder
    echo "assetfinder"
    assetfinder "${TARGET}" | sort -u > "${TARGET_DIR}/${TARGET}_assetfinder.txt"
}

# Функция для объединения результатов и удаления дубликатов
combine_results() {
    echo "Объединение результатов и удаление дубликатов..."

    cat "${TARGET_DIR}/${TARGET}_subfinder.txt" \
        "${TARGET_DIR}/${TARGET}_sublist3r.txt" \
        "${TARGET_DIR}/${TARGET}_crt.sh.txt" \
        "${TARGET_DIR}/${TARGET}_amass.txt" \
        "${TARGET_DIR}/${TARGET}_assetfinder.txt" | sort -u > "${OUTPUT_ALL}"

    # Удаление временных файлов
    rm -f "${TARGET_DIR}/${TARGET}_subfinder.txt" \
          "${TARGET_DIR}/${TARGET}_sublist3r.txt" \
          "${TARGET_DIR}/${TARGET}_crt.sh.txt" \
          "${TARGET_DIR}/${TARGET}_amass.txt" \
          "${TARGET_DIR}/${TARGET}_assetfinder.txt"
}

add_more_subdomains() {
    echo "Would you like to add additional subdomains? (yes/no)"
    read -r response

    if [[ "$response" =~ ^[Yy]es$ ]]; then
        echo "Please enter the subdomains, each on a new line (press Enter twice to finish):"

        additional_subdomains=""
        while true; do
            read -r line
            if [[ -z "$line" ]]; then
                break  # Exit the loop if the user presses Enter without input
            fi
            additional_subdomains+="$line"$'\n'  # Append each subdomain with a newline
        done

        # Remove the trailing newline character and any empty lines
        additional_subdomains=$(echo -e "$additional_subdomains" | sed '/^$/d')
        echo -e "$additional_subdomains" >> "${OUTPUT_ALL}"
        
        echo "Additional subdomains added to the file ${OUTPUT_ALL}."
    fi
}


# Функция для проверки доступности поддоменов с использованием xargs
check_availability() {
    echo "Проверка доступности поддоменов..."

    # Проверка, задан ли шаблон поиска
    if [ -z "$SEARCH_PATTERN" ]; then
        echo "Ошибка: Шаблон поиска не задан. Проверьте аргументы."
        exit 1
    fi

    # Очистка файла с доступными поддоменами
    > "${OUTPUT_AVAILABLE}"

    # Фильтрация поддоменов по шаблону и проверка их доступности
    grep "${SEARCH_PATTERN}" "${OUTPUT_ALL}" | xargs -I {} -P 50 bash -c '
        subdomain="{}"
        HTTP_STATUS=$(curl -o /dev/null -s -w "%{http_code}\n" "http://${subdomain}")
        if [[ "$HTTP_STATUS" =~ ^(200|301|302|307)$ ]]; then
            echo "$subdomain"
        fi
    ' >> "${OUTPUT_AVAILABLE}"
    
    
    
########################################################################################################    
     # Запуск nmap и вывод HTML отчета
    BBNMAP_SCAN_OUT="${TARGET_DIR}/bbnmap_scan.html"

    # Запуск nmap с указанными параметрами
    echo "Запуск nmap..."
    echo ${PASSWORD} | sudo -S nmap -iL "${OUTPUT_AVAILABLE}" -sS -T4 -A -sC -oA bbnmap_scan -Pn --min-rate 5000 --max-retries 1 --max-scan-delay 20ms --top-ports 1000 --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl

    # Проверка наличия созданных файлов
    if [ ! -f "bbnmap_scan.xml" ]; then
        echo "Ошибка: Файл bbnmap_scan.xml не был создан."
        exit 1
    fi

    # Преобразование результата в HTML с использованием xsltproc
    echo "Преобразование в HTML..."
    xsltproc -o "${BBNMAP_SCAN_OUT}" "${XSL_PATH}" bbnmap_scan.xml

    # Проверка успешности преобразования
    if [ ! -f "${BBNMAP_SCAN_OUT}" ]; then
        echo "Ошибка: Не удалось создать HTML отчет."
        exit 1
    fi

    
    echo "Путь к отчету: ${BBNMAP_SCAN_OUT}."
    


########################################################################################################
    if command -v aquatone &> /dev/null; then
        echo "Делаем снимок домена (aquatone найден)"
        cat "${OUTPUT_AVAILABLE}" | aquatone -out "${TARGET_DIR}/Domain_Screen"
    else
        echo "Ошибка: aquatone не установлен или не доступен в PATH"
    fi


     
     
     
     
########################################################################################################
     # Поиск базовой Open Redirect  после имени поддомена 

    REDIRECT_OUT="${TARGET_DIR}/REDIRECT_results.txt"
    > "${REDIRECT_OUT}"
    
        # Чтение поддоменов из файла и проверка каждого
    while IFS= read -r subdomain; do
      # Пропускаем пустые строки и строки, начинающиеся с комментариев
      if [[ -z "$subdomain" || "$subdomain" =~ ^# ]]; then
        continue
      fi

      # Формируем URL с поддоменом и добавляем //evil.com
      url="https://${subdomain}//evil.com"

      # Выполнение запроса с опцией для отслеживания редиректов
      response=$(curl -s -L -I "$url" | grep -i "^Location:")

      # Проверка наличия редиректа и запись результата в файл
      if [[ -z "$response" ]]; then
        echo "Ничего не найдено для ${subdomain}" >> "$REDIRECT_OUT"
      else
        echo "Редирект на: ${response#Location: } для ${subdomain}" >> "$REDIRECT_OUT"
      fi
    done < "${OUTPUT_AVAILABLE}"

    # Информируем о завершении
    echo "Результаты записаны в файл $REDIRECT_OUT"

########################################################################################################
    
     # Запуск dnsrecon для проверки зон
    echo "Запуск dnsrecon для проверки зон..."
    while read -r domain; do
        echo "Запуск dnsrecon для $domain..."
        dnsrecon -d "$domain" -t axfr >> "${DNSZONETRANSFER}"
        echo "------------------------------------------------------------------------" >> "${DNSZONETRANSFER}"
    done < "${OUTPUT_AVAILABLE}"

    # Фильтрация уязвимостей DNS
    echo "Фильтрация уязвимостей DNS..."
    cat "${DNSZONETRANSFER}" | grep "Zone Transfer successful" > "${DNSVULN}"
    
    # Запуск linkchecker для каждого поддомена из ${OUTPUT_AVAILABLE}
    echo "Запуск linkchecker для проверки внешних ссылок поддоменов..."
    INTERMEDIATE_FILE="${TARGET_DIR}/linkchecker_output.txt"
    > "${INTERMEDIATE_FILE}"  # Очистка промежуточного файла

    while read -r subdomain; do
        echo "Обработка поддомена: ${subdomain}"
        linkchecker "http://${subdomain}" --check-extern --ignore-url '\?.*' --verbose | tee -a "${INTERMEDIATE_FILE}"
    done < "${OUTPUT_AVAILABLE}"

    # Фильтрация ссылок и доменов
    echo "Фильтрация ссылок и доменов..."
    cat "${INTERMEDIATE_FILE}" | grep "Real URL" | grep -oP 'https?://[^ ]+' | grep -v -E "twitter.com|google.com|youtube.com|github.com|pinterest.com|wikipedia.org|reddit.com|apple.com|facebook.com|instagram.com|linkedin.com" | awk -F/ '{print $3}' | sort -u >> "${OUTPUT_ALL}"
########################################################################################################
}

# Функция для запуска subzy
run_subzy() {
    echo "Запуск subzy для обработки поддоменов..."
    if command -v subzy &> /dev/null; then
        subzy run --targets "${OUTPUT_ALL}" > "${SUBZY_OUTPUT}"
        echo "Вывод subzy сохранен в ${SUBZY_OUTPUT}"
    else
        echo "Ошибка: Команда subzy не найдена."
    fi
}

# Функция для поиска и обработки URL с использованием waybackurls, gau, katana
find_urls() {
    DOMAIN_FILE="${OUTPUT_AVAILABLE}"
    DOMAIN_OUT="${BASE_DIR}/wayback/domain_out.txt"
    HTTPX_OUT="${BASE_DIR}/wayback/domain_out_httpx.txt"
    GAU_OUT="${BASE_DIR}/wayback/domain_out_gau.txt"
    UNIQUE_URLS="${BASE_DIR}/wayback/unique_urls.txt"
    KATANA_OUT="${BASE_DIR}/wayback/katanaUrls.txt"  # Файл для вывода katana
    ALL_PARAMETER="${TARGET_DIR}/all_url_with_filtered_parametr"  #записывать после uro последнего файла
    FILT_PARAM="${TARGET_DIR}/possible_parameters.txt"
    FILT_PATH="${TARGET_DIR}/possible_path.txt"
    AVAILABLE_URLS="${TARGET_DIR}/Available_urls.txt"
    

    echo "Очистка всех выходных файлов..."
    > "${DOMAIN_OUT}"
    > "${HTTPX_OUT}"
    > "${GAU_OUT}"
    > "${UNIQUE_URLS}"
    > "${KATANA_OUT}"
    > "${ALL_PARAMETER}"
    > "${FILT_PARAM}"
    > "${FILT_PARAM_WV}"
    > "${FILT_PATH}"
    > "${AVAILABLE_URLS}"
    

    echo "Проверка содержимого DOMAIN_FILE: ${DOMAIN_FILE}"
    cat "${DOMAIN_FILE}"

    echo "Получение возможных каталогов и конечных точек с помощью waybackurls..."
    if command -v waybackurls &> /dev/null; then
        cat "${DOMAIN_FILE}" | waybackurls | tee -a "${DOMAIN_OUT}"
    else
        echo "Ошибка: Команда wayb${FILT_PARAM}ackurls не найдена."
    fi

    echo "Получение возможных каталогов и конечных точек с помощью gau..."
    if command -v gau &> /dev/null; then
        cat "${DOMAIN_FILE}" | gau | tee -a "${GAU_OUT}"
    else
        echo "Ошибка: Команда gau не найдена."
    fi
    
    echo "Запуск katana для обработки URL..."
    if command -v katana &> /dev/null; then
    	 cat "${DOMAIN_OUT}" | uro | tee >(sort -u | tee >(grep "${SEARCH_PATTERN}" | tee >(hakrawler -d 3 | tee >(sort -u > "${KATANA_OUT}"))))
    else
        echo "Ошибка: Команда katana не найдена."
    fi
    
    echo "Проверка доступности URL..."
    if command -v httpx &> /dev/null; then
        cat "${DOMAIN_OUT}" "${GAU_OUT}" "${KATANA_OUT}" | uro | httpx | tee -a "${HTTPX_OUT}"
    else
        echo "Ошибка: Команда httpx не найдена."
    fi
    
    cat "${HTTPX_OUT}" | grep "${SEARCH_PATTERN}" | tee "${AVAILABLE_URLS}"



    echo "Сбор всех уникальных URL, включая katana..."
    cat "${DOMAIN_OUT}" "${GAU_OUT}" "${HTTPX_OUT}" "${KATANA_OUT}" | uro | sort -u > "${UNIQUE_URLS}"

    echo "Поиск и запись URL в ${UNIQUE_URLS} завершен."
    
    echo "Удаление дублирующихся параметров из URL..."
    if command -v uro &> /dev/null; then
        cat "${UNIQUE_URLS}" | uro | tee -a "${ALL_PARAMETER}"
    else
        echo "Ошибка: Команда uro не найдена."
    fi
    
    echo "Сбор всех уникальных path and parameters"
    cat "${UNIQUE_URLS}" | sed -E 's#https?://[^/]+(/[^?]*).*#\1#' | grep -v "http" | sort -u | tee "${FILT_PATH}"
    cat "${UNIQUE_URLS}" | sed -E 's#.*\?(.*)#\1#' | tr '&' '\n' | grep -v "http" | sort -t'=' -k1,1 -u | tee "${FILT_PARAM}"
    cat "${UNIQUE_URLS}" | sed -E 's#.*\?(.*)#\1#' | tr '&' '\n' | grep -v "http" | awk -F '=' '{print $1}' | sort -u | tee "${FILT_PARAM_WV}"

}

# Функция для поиска секретов в JavaScript файлах
find_secrets() {
    echo "Поиск конфиденциальных данных в JavaScript файлах..."
    
    echo "Очистка всех выходных файлов..."
    > "${TEMP_SECRET_FILE}"

    # Определение директорий и файлов
    BASE_DIR="."
    DOMAIN_FILE="${BASE_DIR}/wayback/domain_out_httpx.txt"
    SORTURLS_FILE="${BASE_DIR}/wayback/sorturls.txt"
    

    # Очистка файла sorturls.txt
    echo "Очистка файла ${SORTURLS_FILE}..."
    > "${SORTURLS_FILE}"

    # Поиск строк, содержащих указанный шаблон и ".js", и запись в sorturls.txt
    echo "Поиск и запись URL в ${SORTURLS_FILE} с шаблоном '${SEARCH_PATTERN}'..."
    grep "${SEARCH_PATTERN}" "${DOMAIN_FILE}" | grep ".js" > "${SORTURLS_FILE}"

    # Проверка наличия строк в sorturls.txt
    if [ ! -s "${SORTURLS_FILE}" ]; then
        echo "Файл ${SORTURLS_FILE} пуст. Нет URL для обработки."
        exit 0
    fi

    # Обработка каждой строки из sorturls.txt с помощью SecretFinder.py
    echo "Обработка URL с помощью SecretFinder.py..."
    while IFS= read -r url; do
    python3 "${SECRET_FINDER_PATH}" -i "$url" -o cli >> "${TEMP_SECRET_FILE}"
    done < "${SORTURLS_FILE}"

    echo "Процесс завершен."

    echo "Результаты поиска конфиденциальных данных сохранены в ${TEMP_SECRET_FILE}"
}


Sort_Urls_Like_Possible_Vuln(){
    output_dir="${BASE_DIR}/${TARGET}/URL_WITH_POSSIBLY_VULN_PARAM"
    mkdir -p "$output_dir"

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
        echo "$url" | grep -E "$open_redirect_pattern" >> "$output_dir/open_redirect_found.txt"
    
        # Поиск SSRF
        echo "$url" | grep -E "$ssrf_pattern" >> "$output_dir/ssrf_found.txt"

        # Поиск LFI
        echo "$url" | grep -E "$lfi_pattern" >> "$output_dir/lfi_found.txt"

        # Поиск XSS
        echo "$url" | grep -E "$xss_pattern" >> "$output_dir/xss_found.txt"

        # Поиск SQL инъекций
        echo "$url" | grep -E "$sql_injection_pattern" >> "$output_dir/sql_injections_found.txt"

        # Поиск утечек секретных документов
        echo "$url" | grep -E "$secret_document_pattern" >> "$output_dir/secret_documents_found.txt"
    done < "${ALL_PARAMETER}"

    echo "Анализ завершен. Результаты находятся в директории $output_dir."

}
check_host_access() {
    while ! ping -c 1 -W 1 "$TARGET" &> /dev/null; do
        echo "Хост $TARGET недоступен. Ожидаю подключения..."
        sleep 5  # Подождем перед повторной проверкой
    done
}


# Главная логика работы скрипта, в зависимости от выбранного режима
case "$MODE" in
    "search")
        check_host_access
        add_more_subdomains
        check_host_access
        check_domain
        check_host_access
        search_subdomains
        check_host_access
        combine_results        
        ;;

    "find")
        check_host_access        
        check_availability
        check_host_access
        run_subzy
        ;;

    "process")
        check_host_access
        find_urls
        check_host_access
        find_secrets
        check_host_access
        Sort_Urls_Like_Possible_Vuln
        ;;



    "all")
        check_host_access
        add_more_subdomains
        check_host_access
        check_domain
        check_host_access
        search_subdomains
        check_host_access
        combine_results
        check_host_access
        check_availability
        check_host_access
        run_subzy
        check_host_access
        find_urls
        check_host_access       
        find_secrets
        check_host_access
        Sort_Urls_Like_Possible_Vuln
        ;;

    *)
        echo "Недопустимый режим: ${MODE}"
        echo "Допустимые режимы: search, find, process, all"
        exit 1
        ;;
esac




echo "Завершено!"
