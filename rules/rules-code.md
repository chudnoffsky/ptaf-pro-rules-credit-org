# Код правил PTAF Pro 4.2.2

Маршруты и имена полей указаны для стенда Vulnbank — заменить на фактические.
Описание, обоснование и UUID указано в `rules/all-rules.md`.

---

## Адаптационные правила

### WAF-01: Rate limit
*Настройка через интерфейс PTAF Pro -> Набор пользовательских правил -> Создать правило*
```
Тип правила: Ограничение частоты запросов (Rate limit)
Маршрут:     /*
Порог:       > 20 запросов/сек с одного IP
Действие:    Block (HTTP 403)
Критичность: Низкая
```

### WAF-02: Агрегация и blacklist
*Настройка через интерфейс PTAF Pro -> Набор пользовательских правил -> Создать правило*
```
Тип правила:          Агрегация
Правило-источник:     WAF-01
Порог агрегации:      >= 1000 срабатываний за 10 секунд с одного IP
Действие:             Close connection
Добавить в blacklist: да, TTL 10 минут
Критичность:          Средняя
```

### WAF-03: User-Agent сканера
```
if REQUEST_HEADERS.select("user-agent").extract(values).any()
   matches ~"(sqlmap|gobuster|nikto|curl)"
then Log to db
```

### WAF-04: SQL injection в GET/POST-параметрах
```
if REQUEST_QUERY matches ~"(OR 1=1|UNION SELECT|extractvalue)"
   OR REQUEST_POST matches ~"(OR 1=1|UNION SELECT|extractvalue)"
then Block
```

### WAF-06: XXE через внешние сущности XML
```
if REQUEST_BODY matches ~"DOCTYPE"
   AND REQUEST_BODY matches ~"ENTITY"
   AND REQUEST_BODY matches ~"SYSTEM"
then Block
```

### WAF-07: SSRF через XML
```
if REQUEST_BODY matches ~"file://"
   OR REQUEST_BODY matches ~"http://169[.]254[.]"
then Block
```

### WAF-08: Детектирование попыток аутентификации
*Настройка через интерфейс PTAF Pro -> Параметры аутентификации*
```
Тип:             На основе форм
Метод:           POST
URL:             /vulnbank/online/login.php
Коды успеха:     200
Коды неуспеха:   401, 403
Cookie:          PHPSESSID
Действие:        Log to db
Критичность:     Информационная
```

### WAF-09: Brute-force с агрегацией
*Настройка через интерфейс PTAF Pro -> Набор пользовательских правил -> Создать правило*
```
Тип правила:          Агрегация
Правило-источник:     WAF-08
Порог агрегации:      >= 10 срабатываний за 30 секунд с одного IP
Действие:             Block
Добавить в blacklist: да, TTL 10 минут
Критичность:          Высокая
```

### WAF-10: Логирование успешной аутентификации
*Настройка через интерфейс PTAF Pro -> Параметры аутентификации*
```
Тип:             На основе форм
Метод:           POST
URL:             /vulnbank/online/login.php
Коды успеха:     200
Cookie:          PHPSESSID
Действие:        Log to db
Критичность:     Информационная
```

### WAF-11: RCE через ImageMagick (CVE-2016-3714)
```
if REQUEST_BODY matches ~"[.](svg|mvg)"
   AND REQUEST_BODY matches ~"SYSTEM"
then Block
```

### WAF-12: Webshell в HTTP-ответе
*Встроенный модуль `webshell_detector.so` — активен по умолчанию, настройка не требуется*

### WAF-13: Обращение к загруженному webshell
```
if REQUEST_METHOD matches ~"(GET|POST)"
   AND REQUEST_URI matches ~"^/uploads/[^/]+[.](php|phtml)$"
then Block
```

### WAF-16: XML bomb (DoS)
*Настройка через интерфейс PTAF Pro -> Защита от DoS -> Ограничения XML*
```
Параметр:    Максимальная глубина вложенности XML-сущностей
Значение:    задать пороговое значение под нагрузку приложения
Действие:    Block
Критичность: Высокая
```

### WAF-17: Геофильтрация (блокировка зарубежного трафика)
```
if NOT CLIENT_COUNTRY == "RU"
   AND NOT CLIENT_IP in [@@ip_list]
then Block
```

### WAF-18: Whitelist на RU
*Настройка через интерфейс PTAF Pro -> Геофильтрация*
```
Режим:                   Whitelist
Разрешенные страны:      RU
Действие для остальных:  Block
Критичность:             Средняя
```

---

## Авторские правила

### WAF-05: SQL injection в JSON-теле POST-запроса
```
if REQUEST_BODY matches ~"(OR 1=1|UNION SELECT|extractvalue)"
   AND REQUEST_CONTENT_TYPE == "application/json"
then Block
```

### WAF-14: Отрицательная сумма транзакции
```
if REQUEST_PATH == "/vulnbank/online/api.php"
   AND REQUEST_POST.select("amount").extract(values).any()
      matches ~"^\-\d+$"
then Block
```

### WAF-15: CRLF Injection (CWE-113)
```
if REQUEST_QUERY matches ~"%0[aAdD]|%0[aA]%0[dD]"
then Block, Log
```

### WAF-19: Sensitive Token in URL (CWE-598)
```
if REQUEST_QUERY matches ~"(token|api_key|apikey|secret|password|passwd|auth)="
then Block, Log
```

### WAF-20: OTP Bruteforce / Account Takeover
*Настройка через интерфейс PTAF Pro -> Параметры аутентификации*
```
Тип:             На основе форм
Метод:           POST
URL:             /vulnbank/online/api.php
Поле логина:     username
Поле OTP:        sms_code
Коды успеха:     200
Коды неуспеха:   400, 502
Cookie:          PHPSESSID

Агрегация:
  Порог:         10 срабатываний за 30 секунд с одного IP
  TTL:           10 минут
  Действие:      Aggregation blacklist
```

### WAF-21: Credential Stuffing Detection
```
if REQUEST_PATH == "/vulnbank/online/login.php"
   AND REQUEST_METHOD == "POST"
   AND REQUEST_POST.select("username").extract(values).any()
      matches ~"^[a-zA-Z0-9]{1,3}$"
then Block, Log
```

### WAF-22: Mass Assignment
```
if REQUEST_BODY matches ~"(\"admin\"|\"role\"|\"is_admin\"|\"is_superuser\"|\"permissions\")"
then Block, Log
```

### WAF-23: Server-Side Template Injection (CWE-94)
```
if REQUEST_BODY matches ~"[{][{][^}]+[}][}]"
   OR REQUEST_QUERY matches ~"[{][{]|[$][{]|[#][{]"
then Block, Log
```

### WAF-24: XML Signature Wrapping (CWE-347)
```
if REQUEST_BODY matches ~"<[a-zA-Z:]*Signature[^>]*>.*<[a-zA-Z:]*Signature[^>]*>"
then Block, Log
```
