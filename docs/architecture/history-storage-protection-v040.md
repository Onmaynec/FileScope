# FileScope v0.4.0 — защита history storage на Windows

## Цель

Production history FileScope v0.4.0 хранится в Rust/Tauri app-data storage. На Windows каждая новая generation защищается штатным Windows Data Protection API (DPAPI) до записи на диск.

## Криптографическая граница

FileScope не реализует собственную криптосхему, не генерирует пользовательские ключи и не хранит ключи рядом с history.

Используются системные Windows API:

- `CryptProtectData` для защиты payload;
- `CryptUnprotectData` для чтения payload;
- `CRYPTPROTECT_UI_FORBIDDEN`, чтобы persistence не могла неожиданно открыть системный prompt;
- `LocalFree` для освобождения памяти, выделенной Windows API.

`CRYPTPROTECT_LOCAL_MACHINE` намеренно не используется. Защита остаётся в default current-user scope. Это означает, что persistent history предназначена для того же Windows-пользователя на том же компьютере, который создал данные.

## Формат generation

Новые generations имеют суффикс `.bin` и бинарный wrapper:

1. magic `FSDPAPI1`;
2. ciphertext, возвращённый `CryptProtectData`.

JSON history envelope сериализуется в памяти, проходит лимит размера и только после этого передаётся DPAPI. Plaintext JSON не записывается во временный или финальный `.bin` файл.

Публикация остаётся crash-safe:

1. создать новую temporary generation;
2. записать уже защищённые bytes;
3. `sync_all`;
4. закрыть handle;
5. atomic rename в финальную generation;
6. только после успешной DPAPI publication выполнять cleanup старых валидных plaintext generations и старых generations.

При ошибке `CryptProtectData` FileScope возвращает storage `unavailable`. Plaintext fallback на Windows запрещён.

## Совместимость и миграция plaintext v2

Ранние development builds v0.4.0 могли создать plaintext `reports-v2-*.json`. Они читаются только как migration source.

После загрузки валидного plaintext store frontend запрашивает фактический `history_protection_status`. Если статус `plaintext` или `mixed`, repository вызывает `history_rewrite_all`. Rust создаёт новую DPAPI generation и только после её успешной публикации удаляет старые **валидные** plaintext generations.

Future schema, corrupted, oversized и невалидные generations не удаляются автоматическим DPAPI cleanup. Они остаются для диагностики/восстановления и не должны быть тихо перезаписаны.

Если DPAPI generation нельзя расшифровать, generation считается corrupted. Обычный generation recovery может открыть предыдущую валидную копию. Данные, которые не удаётся расшифровать, не перезаписываются как пустая история.

## Protection status

Tauri command `history_protection_status` возвращает фактическое состояние:

- `dpapiCurrentUser` — все обнаруженные generations защищены DPAPI;
- `plaintext` — обнаружены только legacy plaintext generations;
- `mixed` — есть DPAPI и plaintext generations одновременно;
- `empty` — persistent history пуста;
- `unavailable` — состояние нельзя надёжно определить;
- `notSupported` — runtime не Windows.

Settings UI показывает этот статус пользователю. UI не должен утверждать, что история защищена, если Rust не подтвердил `dpapiCurrentUser` или пустой store, для которого следующая Windows-запись будет DPAPI-protected.

## Portable mode

Portable относится к исполняемому файлу, а не к persistent history.

В v0.4.0 portable EXE использует тот же per-user app-data history store. Persistent history:

- не хранится рядом с EXE;
- не предназначена для переносимости на USB вместе с EXE;
- защищается current-user DPAPI на Windows;
- не должна расшифровываться после простого копирования encrypted generation в другой Windows-профиль или на другой компьютер.

Если пользователю нужна переносимая информация, он использует явный JSON/HTML export отчёта. Export — отдельная пользовательская операция и не является частью encrypted history store.

## Privacy и retention до persistence

DPAPI не заменяет minimization. Перед persistence repository применяет privacy policy:

- credentials из URL удаляются всегда;
- query/fragment по умолчанию удаляются и сохраняются только по явной настройке;
- полный путь по умолчанию сокращается до имени файла;
- чувствительные response headers удаляются;
- retention 1/7/30 дней физически переписывает authoritative store без устаревших reports;
- режим `session` и выключенное сохранение не создают новую persistent копию отчёта.

## Failure policy

Безопасность важнее прозрачного fallback:

- DPAPI encrypt failure → не писать plaintext;
- write/sync/rename failure → не считать report persisted;
- decrypt/integrity failure → corrupted/recovery path, не `empty`;
- future schema → read-only/unsupported, без rewrite;
- storage unavailable → новый report может остаться только в памяти текущего session, UI должен сообщить об этом;
- clear считается успешным только если Rust generations и известные legacy report payload действительно удалены.

## Проверки

Windows CI обязан проверять:

- реальный DPAPI encrypt/decrypt round-trip;
- ciphertext не содержит контрольную plaintext строку;
- plaintext v2 migration создаёт DPAPI generation и удаляет валидный plaintext source только после успешной публикации;
- future/corrupted generation остаётся защищённой от overwrite;
- `cargo fmt --check`, `cargo test --locked`, `cargo check --locked`;
- Tauri production build, Windows x64 и NSIS;
- неизменность lock-файлов.

Перед релизом дополнительно выполняется ручной Windows QA из `docs/product/v0.4.0-manual-qa.md`.
