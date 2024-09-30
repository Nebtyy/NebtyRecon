#!/bin/bash
echo "Made by "
echo "███╗   ██╗███████╗██████╗ ████████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
████╗  ██║██╔════╝██╔══██╗╚══██╔══╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██╔██╗ ██║█████╗  ██████╔╝   ██║    ╚████╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║╚██╗██║██╔══╝  ██╔══██╗   ██║     ╚██╔╝  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║ ╚████║███████╗██████╔╝   ██║      ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═══╝╚══════╝╚═════╝    ╚═╝      ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"


# Проверка на наличие двух или трёх аргументов
if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo "Usage: $0 <target_domain> <mode> [search_pattern]"
    exit 1
fi

# Определение целевого домена, режима и шаблона поиска
TARGET="$1"
MODE="$2"
SEARCH_PATTERN="$3"

# Экранирование точки в шаблоне поиска
SEARCH_PATTERN="${SEARCH_PATTERN//./\\.}"

BASE_DIR="."
TARGET_DIR="${BASE_DIR}/${TARGET}"
OUTPUT_ALL="${TARGET_DIR}/${TARGET}_all_subdomains.txt"
OUTPUT_AVAILABLE="${TARGET_DIR}/${TARGET}_available_subdomains.txt"
DOMAIN_FILE="${OUTPUT_AVAILABLE}"
SORTURLS_FILE="${BASE_DIR}/wayback/sorturls.txt"
SECRET_FINDER_PATH="/home/kali/Downloads/secretfinder/SecretFinder.py"
SUBZY_OUTPUT="${TARGET_DIR}/subzy_output.txt"
TEMP_SECRET_FILE="${TARGET_DIR}/secretfind_output.txt"
KATANA_OUT="${TARGET_DIR}/katanaUrls.txt"  # Файл для вывода katana

# Создание директории для вывода, если она не существует
mkdir -p "${TARGET_DIR}"
mkdir -p "${BASE_DIR}/wayback"

# Создание всех необходимых файлов перед их очисткой
for file in "${BASE_DIR}/wayback/domain_out.txt" \
            "${BASE_DIR}/wayback/domain_out_httpx.txt" \
            "${BASE_DIR}/wayback/domain_out_httpx_uro.txt" \
            "${BASE_DIR}/wayback/domain_out_gau.txt" \
            "${BASE_DIR}/wayback/unique_urls.txt" \
            "${TEMP_SECRET_FILE}" \
            "${SORTURLS_FILE}" \
            "${SUBZY_OUTPUT}" \
            "${KATANA_OUT}"; do
    touch "$file"
done

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
    subfinder -d "${TARGET}" | sort -u > "${TARGET_DIR}/${TARGET}_subfinder.txt"

    # sublist3r
    echo "sublist3r"
    sublist3r -d "${TARGET}" -o "${TARGET_DIR}/${TARGET}_sublist3r.txt"

    # crt.sh
    echo "crt.sh"
    curl -s "https://crt.sh/?q=${TARGET}&output=json" | jq -r '.[] | .name_value, .common_name' | sort -u > "${TARGET_DIR}/${TARGET}_crt.sh.txt"
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
    DOMAIN_OUT="${BASE_DIR}/wayback/domain_out.txt"
    HTTPX_OUT="${BASE_DIR}/wayback/domain_out_httpx.txt"
    URO_OUT="${BASE_DIR}/wayback/domain_out_httpx_uro.txt"
    GAU_OUT="${BASE_DIR}/wayback/domain_out_gau.txt"
    UNIQUE_URLS="${BASE_DIR}/wayback/unique_urls.txt"

    echo "Очистка всех выходных файлов..."
    > "${DOMAIN_OUT}"
    > "${HTTPX_OUT}"
    > "${URO_OUT}"
    > "${GAU_OUT}"
    > "${UNIQUE_URLS}"

    echo "Проверка содержимого DOMAIN_FILE: ${DOMAIN_FILE}"
    cat "${DOMAIN_FILE}"

    echo "Получение возможных каталогов и конечных точек с помощью waybackurls..."
    if command -v waybackurls &> /dev/null; then
        cat "${DOMAIN_FILE}" | waybackurls | tee -a "${DOMAIN_OUT}"
    else
        echo "Ошибка: Команда waybackurls не найдена."
    fi

    echo "Получение возможных каталогов и конечных точек с помощью gau..."
    if command -v gau &> /dev/null; then
        cat "${DOMAIN_FILE}" | gau | tee -a "${GAU_OUT}"
    else
        echo "Ошибка: Команда gau не найдена."
    fi

    echo "Проверка доступности URL..."
    if command -v httpx &> /dev/null; then
        cat "${DOMAIN_OUT}" "${GAU_OUT}" | httpx | tee -a "${HTTPX_OUT}"
    else
        echo "Ошибка: Команда httpx не найдена."
    fi

    echo "Удаление дублирующихся параметров из URL..."
    if command -v uro &> /dev/null; then
        cat "${HTTPX_OUT}" | uro | tee -a "${URO_OUT}"
    else
        echo "Ошибка: Команда uro не найдена."
    fi
    
    echo "Запуск katana для обработки URL..."
    if command -v katana &> /dev/null; then
        cat "${DOMAIN_OUT}" | katana | hakrawler -d 3 | grep "${SEARCH_PATTERN}" | tee -a "${KATANA_OUT}"
    else
        echo "Ошибка: Команда katana не найдена."
    fi

    echo "Сбор всех уникальных URL, включая katana..."
    cat "${DOMAIN_OUT}" "${GAU_OUT}" "${HTTPX_OUT}" "${URO_OUT}" "${KATANA_OUT}" | sort -u > "${UNIQUE_URLS}"

    echo "Поиск и запись URL в ${UNIQUE_URLS} завершен."
}

# Функция для поиска секретов в JavaScript файлах
find_secrets() {
    echo "Поиск конфиденциальных данных в JavaScript файлах..."

    # Определение директорий и файлов
    BASE_DIR=./wayback
    DOMAIN_FILE="${BASE_DIR}/domain_out_httpx.txt"
    SORTURLS_FILE="${BASE_DIR}/sorturls.txt"
    SECRET_FINDER_PATH=~/Downloads/secretfinder/SecretFinder.py

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


# Главная логика работы скрипта, в зависимости от выбранного режима
case "$MODE" in
    "search")
        search_subdomains
        combine_results
        ;;

    "find")
        check_availability
        run_subzy
        ;;

    "process")
        find_urls
        find_secrets
        ;;

    "all")
        search_subdomains
        combine_results
        check_availability
        run_subzy
        find_urls
        find_secrets
        ;;

    *)
        echo "Недопустимый режим: ${MODE}"
        echo "Допустимые режимы: search, find, process, all"
        exit 1
        ;;
esac

echo "Завершено!"
