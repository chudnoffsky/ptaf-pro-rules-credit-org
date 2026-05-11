# Перенос правил на ModSecurity

Правила в этом наборе писались с расчетом на то, чтобы детектирующая логика не зависела от конкретного WAF. Регулярные выражения, имена полей HTTP-запроса (REQUEST_QUERY, REQUEST_BODY, REQUEST_POST) и фазы обработки запроса либо одинаковы между PTAF Pro и ModSecurity, либо имеют прямой эквивалент.

Ниже три иллюстративных переноса. Цель не написать полный набор правил для ModSecurity, а показать, что миграция сводится к замене синтаксиса при сохранении логики.

---

## Пример 1. WAF-22: Mass Assignment

### PTAF Pro

```
if REQUEST_BODY matches ~"(\"admin\"|\"role\"|\"is_admin\"|\"is_superuser\"|\"permissions\")"
```

### ModSecurity

```
SecRule REQUEST_BODY "@rx (\"admin\"|\"role\"|\"is_admin\"|\"is_superuser\"|\"permissions\")" \
    "id:1022, phase:2, deny, log, msg:'Mass Assignment'"
```

### Комментарий

Регулярное выражение и поле REQUEST_BODY идентичны. Фаза 2 в ModSecurity — это анализ тела запроса после его полного прочтения, что функционально эквивалентно поведению PTAF Pro с условием на REQUEST_BODY. Различается только синтаксис записи: у PTAF Pro конструкция `if ... matches ~"..."`, у ModSecurity директива `SecRule` с набором действий (id, phase, deny, log, msg).

---

## Пример 2. WAF-15: CRLF Injection (CWE-113)

### PTAF Pro

```
if REQUEST_QUERY matches ~"%0[aAdD]|%0[aA]%0[dD]"
```

### ModSecurity

```
SecRule REQUEST_QUERY_STRING "@rx %0[aAdD]|%0[aA]%0[dD]" \
    "id:1015, phase:1, deny, log, msg:'CRLF Injection (CWE-113)'"
```

### Комментарий

Различие только в имени поля: REQUEST_QUERY в PTAF Pro и REQUEST_QUERY_STRING в ModSecurity — семантически это одно и то же: строка параметров URL. Фаза 1 в ModSecurity — анализ заголовков и строки запроса, что подходит для детектирования CRLF в GET-параметрах.

---

## Пример 3. WAF-19: Sensitive Token in URL (CWE-598)

### PTAF Pro

```
if REQUEST_QUERY matches ~"(token|api_key|apikey|secret|password|passwd|auth)="
```

### ModSecurity

```
SecRule REQUEST_QUERY_STRING "@rx (token|api_key|apikey|secret|password|passwd|auth)=" \
    "id:1019, phase:1, deny, log, msg:'Sensitive Token in URL (CWE-598)'"
```

### Комментарий

Полная аналогия с предыдущим примером. Регулярное выражение и фаза идентичны, отличается только имя поля.

---

## Что не переносится напрямую

Прямых аналогов нет у нескольких элементов набора:

**WAF-20 (OTP Bruteforce)** реализована через встроенный механизм «Параметры аутентификации» PTAF Pro с агрегацией попыток. В ModSecurity аналогичная логика реализуется через счетчики на уровне IP-адреса, но это уже написание правила заново, а не трансляция синтаксиса.

**WAF-12 (Webshell в HTTP-ответе)** реализуется встроенным модулем webshell_detector.so — бинарным детектором PTAF Pro. В ModSecurity webshell-паттерны покрываются сигнатурными правилами из публичных наборов, но это не эквивалент модуля уровня детектора.

**WAF-17 / WAF-18 (Геофильтрация)** в ModSecurity требует подключения базы данных GeoIP и использования модуля `geoIP`. Логически эквивалентно, но синтаксически принципиально отличается.

Для всех остальных правил перенос сводится к трансляции синтаксиса при сохранении регулярного выражения и имени поля.

---

## Итог

Из 24 правил основного набора прямой трансляцией в ModSecurity покрываются правила, построенные на регулярных выражениях и стандартных полях запроса — это большинство адаптационных и все авторские правила кроме WAF-20. Системные настройки PTAF Pro и встроенные модули требуют либо ручного переписывания, либо подключения соответствующих модулей на стороне ModSecurity.
