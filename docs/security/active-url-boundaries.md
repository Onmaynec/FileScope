# Границы активной URL-проверки FileScope

## Модель угроз

Активная проверка принимает строку URL от пользователя и выполняет минимальное сетевое обращение. Без дополнительных ограничений такой механизм может использоваться для SSRF, обращения к локальным сервисам, cloud metadata, private networks или для обхода проверки через DNS rebinding и redirect.

## Разрешённый объём

- схемы: `http`, `https`;
- порты: `80`, `443`;
- host: публичный domain или публичный IP;
- метод: сначала `HEAD`, затем при необходимости `GET` с `Range: bytes=0-0`;
- redirect: не более настроенного лимита, максимум 10;
- body страницы не читается приложением;
- JavaScript не выполняется.

## Блокируемые цели

Блокируются:

- localhost и loopback;
- RFC1918 IPv4;
- CGNAT `100.64.0.0/10`;
- link-local и metadata ranges;
- unspecified, multicast, broadcast и reserved ranges;
- IPv4 documentation networks;
- IPv6 loopback, unspecified, multicast, ULA, link-local, site-local и documentation range;
- IPv4-mapped IPv6, если вложенный IPv4 запрещён;
- hostnames `localhost`, `*.localhost`, `*.local`, `*.internal`, `metadata.google.internal`;
- нестандартные порты;
- URL и redirect со встроенными credentials;
- redirect с HTTPS на HTTP;
- redirect на схемы, отличные от HTTP/HTTPS.

## DNS и соединение

1. Domain разрешается в IP перед запросом.
2. Если набор содержит запрещённый IP, весь hop отклоняется.
3. Из разрешённого набора выбирается публичный адрес.
4. HTTP client получает явное соответствие domain → проверенный socket address.
5. Автоматический redirect отключён.
6. Каждый новый Location проходит полный цикл повторно.

Такой порядок предотвращает ситуацию, когда проверяется один IP, а библиотека самостоятельно выполняет соединение с другим результатом DNS.

## Credentials и журналирование

- активный запрос с credentials не выполняется;
- password удаляется из target, evidence, истории и экспорта;
- normalized URL не содержит userinfo;
- вложенные redirect URL также проходят redaction.

## Cancellation и timeout

DNS и HTTP обёрнуты в cancel-aware ожидание. Пользовательская отмена меняет `JobToken`, а сетевое ожидание завершается с типизированным кодом `cancelled`. Общий deadline задания имеет код `timeout`.

## Остаточные ограничения

В v0.3.3 используется встроенный snapshot распространённых multi-label public suffix для определения registrable domain. Он нужен для корректного подсчёта поддоменов, но не является полной автоматически обновляемой копией Public Suffix List.
