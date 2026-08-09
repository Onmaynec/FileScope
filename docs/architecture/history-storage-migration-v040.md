
# ADR: миграция истории FileScope к v0.4.0

## Решение

UI работает только с асинхронным `ReportHistoryRepository`. В v0.3.4 используется legacy adapter; в v0.4.0 он заменён Tauri/Rust adapter без изменения компонентов истории и анализа.

## Версии

`schemaVersion` описывает структуру одного отчёта. `storageVersion` описывает контейнер, транзакции и способ хранения набора отчётов. Эти версии изменяются независимо.

## Миграция

1. Прочитать versioned Tauri storage.
2. При отсутствии прочитать storage-v1 WebView envelope.
3. При отсутствии прочитать schema-v1 raw array и v0.2.0 keys.
4. Проверить размер до JSON parse.
5. Сохранить legacy source неизменным как rollback source; не выполнять destructive cleanup до отдельного подтверждённого периода отката.
6. Валидировать и мигрировать каждый отчёт.
7. Применить privacy minimization и retention до первой записи в Rust store.
8. Атомарно записать новый Rust storage через `history_replace_all`.
9. После подтверждённой publication Rust/Tauri становится единственным authoritative repository; новые reports больше не записываются в legacy WebView storage.

## Restart / retry semantics

Migration обязана быть безопасной при перезапуске процесса и неопределённом результате IPC:

- если publication завершилась ошибкой **до commit**, Rust store остаётся пустым, legacy source остаётся byte-for-byte неизменным, а следующий запуск может безопасно повторить migration;
- если Rust publication **успела commit'нуться, но IPC response был потерян**, текущий процесс может показать `unavailable/persisted=false`, однако следующий запуск сначала читает Rust store, находит committed generation и не выполняет второй `history_replace_all`;
- после обычной успешной migration следующий запуск читает authoritative Rust store и не повторяет migration;
- legacy source сохраняется неизменным и остаётся доступным для rollback/diagnostics в течение rollback-периода;
- повторный запуск не должен создавать duplicate reports или возвращать authoritative роль legacy storage.

Эти инварианты закреплены отдельным frontend regression suite `tauri-history-migration-restart.test.ts` и обязательны в `check:v040-readiness`.

## Ошибки

Future, corrupted и oversized storage никогда не перезаписывается автоматически. Пользователь получает read-only/diagnostic status. Ошибка одной записи не должна ломать запуск приложения.

Ошибка чтения legacy source не трактуется как пустая история. Ошибка первой Rust publication не разрешает удалять или изменять legacy source. Неопределённый IPC-ответ после потенциального commit разрешается повторным чтением authoritative Rust store на следующем запуске, а не слепым повторным overwrite.

## Rollback

Legacy source не удаляется сразу после migration и остаётся read-only rollback source. Двойная запись чувствительных данных запрещена: после переключения активен только Rust/Tauri repository.

Явное полное удаление истории — отдельная пользовательская операция: она должна очистить Rust generations, session history и известные legacy report payload/backups и не может сообщать success при частичном отказе удаления.
