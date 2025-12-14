### How Work

```
1. crs-setup.conf                    # Основная конфигурация
2. REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf  # Исключения ДО CRS
3. REQUEST-901-INITIALIZATION.conf   # Инициализация
4. REQUEST-905-COMMON-EXCEPTIONS.conf # Общие исключения
5. REQUEST-910-IP-REPUTATION.conf    # Репутация IP
6. REQUEST-911-METHOD-ENFORCEMENT.conf # Проверка методов
7. ... (остальные файлы REQUEST-*)    # Основные правила
8. REQUEST-949-BLOCKING-EVALUATION.conf # Оценка блокировки
9. RESPONSE-950-DATA-LEAKAGE.conf    # Утечки данных (ответы)
10. RESPONSE-951-DATA-LEAKAGE-SQL.conf # Утечки SQL (ответы)
11. RESPONSE-952-DATA-LEAKAGE-JAVA.conf # Утечки Java (ответы)
12. RESPONSE-953-DATA-LEAKAGE-PHP.conf # Утечки PHP (ответы)
13. RESPONSE-954-DATA-LEAKAGE-IIS.conf # Утечки IIS (ответы)
14. RESPONSE-959-BLOCKING-EVALUATION.conf # Оценка (ответы)
15. RESPONSE-980-CORRELATION.conf    # Корреляция
16. REQUEST-900-EXCLUSION-RULES-AFTER-CRS.conf # Исключения ПОСЛЕ CRS
```

Это файл **crs-setup.conf** версии OWASP CRS 4.22.0-dev. Это **основной конфигурационный файл** для настройки OWASP ModSecurity Core Rule Set (CRS). Давайте разберем его ключевые части:

## **Основные разделы файла:**

### 1. **Режимы работы CRS**
- **Anomaly Scoring Mode (режим оценки аномалий)** - режим по умолчанию
  - Каждое сработавшее правило увеличивает счетчик "аномалий"
  - Решение о блокировке принимается в конце обработки запроса/ответа
  - Более гибкий и информативный режим
  
- **Self-Contained Mode (автономный режим)**
  - Правила применяют действие немедленно
  - Меньшая нагрузка, но меньше информации в логах

### 2. **Уровень паранойи (Paranoia Level)**
- **PL1** (по умолчанию) - для начинающих, минимальное количество ложных срабатываний
- **PL2** - дополнительные правила, требует больше настройки
- **PL3** - для опытных пользователей с высокими требованиями безопасности
- **PL4** - максимальная безопасность, много ложных срабатываний

### 3. **Настройки скоринга (оценки)**
```apache
# Баллы за серьезность нарушений:
tx.critical_anomaly_score=5    # Критические (атаки на приложение)
tx.error_anomaly_score=4       # Ошибки (утечки данных)
tx.warning_anomaly_score=3     # Предупреждения (злонамеренные клиенты)
tx.notice_anomaly_score=2      # Уведомления (нарушения протокола)

# Пороги блокировки:
tx.inbound_anomaly_score_threshold=5   # Для входящих запросов
tx.outbound_anomaly_score_threshold=4  # Для исходящих ответов
```

### 4. **Политики HTTP**
- **Разрешенные HTTP методы**: `GET HEAD POST OPTIONS`
- **Разрешенные Content-Type**:
  - `application/x-www-form-urlencoded`
  - `multipart/form-data`
  - `text/xml`, `application/xml`, `application/soap+xml`
  - `application/json`, `application/reports+json`, `application/csp-report`

- **Запрещенные расширения файлов**: `.bak`, `.sql`, `.config`, `.log` и т.д.
- **Запрещенные заголовки**: `/proxy/`, `/x-http-method-override/` и другие

### 5. **Лимиты запросов**
```apache
# Примеры лимитов (по умолчанию отключены):
tx.max_num_args=255           # Максимальное количество аргументов
tx.arg_name_length=100        # Максимальная длина имени аргумента
tx.arg_length=400             # Максимальная длина значения аргумента
tx.total_arg_length=64000     # Общая длина всех аргументов
tx.max_file_size=1048576      # Максимальный размер файла
```

### 6. **Важные настройки по умолчанию**
```apache
# Режим работы (раскомментировано по умолчанию):
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"

# Уровень паранойи (закомментировано):
# setvar:tx.blocking_paranoia_level=1

# Проверка кодировки UTF-8 (закомментировано):
# setvar:tx.crs_validate_utf8_encoding=1

# Пропуск проверки ответов (закомментировано):
# setvar:tx.crs_skip_response_analysis=1
```

## **Что нужно сделать для работы:**

### 1. **Раскомментировать обязательные настройки**
Добавьте в конец файла (или раскомментируйте) минимальную конфигурацию:

```apache
# Минимальная рабочая конфигурация
SecAction \
    "id:900000,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    setvar:tx.blocking_paranoia_level=1,\
    setvar:tx.inbound_anomaly_score_threshold=5,\
    setvar:tx.outbound_anomaly_score_threshold=4"
```

### 2. **Или создать упрощенный crs-setup.conf**
```bash
cat > rules/crs-setup.conf << 'EOF'
# Базовая конфигурация CRS
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"

# Настройки паранойи и скоринга
SecAction \
    "id:900000,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    setvar:tx.crs_setup_version=4220,\
    setvar:tx.blocking_paranoia_level=1,\
    setvar:tx.critical_anomaly_score=5,\
    setvar:tx.error_anomaly_score=4,\
    setvar:tx.warning_anomaly_score=3,\
    setvar:tx.notice_anomaly_score=2,\
    setvar:tx.inbound_anomaly_score_threshold=5,\
    setvar:tx.outbound_anomaly_score_threshold=4"

# Разрешенные HTTP методы
SecAction \
    "id:900200,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    setvar:'tx.allowed_methods=GET HEAD POST OPTIONS'"

# Разрешенные Content-Type
SecAction \
    "id:900220,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/reports+json| |application/csp-report|'"
EOF
```

### 3. **Порядок загрузки в вашем плагине**
Убедитесь, что файлы загружаются в правильном порядке:
1. `crs-setup.conf` (этот файл) - **обязательно первым!**
2. `REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`
3. `REQUEST-901-INITIALIZATION.conf`
4. Остальные файлы правил

## **Почему вы видите предупреждение:**
Правило `901001` проверяет, что `tx.crs_setup_version` установлена. В текущем файле она установлена в конце (строка с `id:900990`), но другие правила могут проверять эту переменную раньше.

**Решение:** Перенесите установку `tx.crs_setup_version` в начало файла или создайте упрощенный конфиг, как показано выше.