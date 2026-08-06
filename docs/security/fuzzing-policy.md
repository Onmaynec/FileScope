
# Политика fuzzing FileScope

Разрешены только synthetic/random bytes, минимальные conformance fixtures с проверенной лицензией и минимизированные невредоносные crash inputs.

Запрещены malware samples, активные вредоносные URL, credentials, tokens, пользовательские файлы и большие бинарные corpus без review.

Fuzz targets не выполняют сеть, процессы, извлечение архивов или запись в пользовательские каталоги. Workflow работает с `contents: read`, без secrets и production Environment, с жёстким timeout. Crash artifacts хранятся не более трёх дней.

Потенциально security-sensitive crash не публикуется публичным Issue с exploit details. Он проходит private triage: минимизация, проверка отсутствия секретов, классификация panic/OOM/hang/invariant, безопасный regression fixture и исправление root cause.
