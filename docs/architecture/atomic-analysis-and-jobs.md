# Атомарный анализ файлов и lifecycle заданий

## Цель

FileScope должен формировать SHA-256, тип файла, PE-структуру и другие признаки по одному и тому же файловому объекту, а также действительно прекращать работу после пользовательской отмены.

## Один открытый объект

Файловый анализ v0.3.3:

1. Проверяет путь через `symlink_metadata`.
2. Отклоняет каталоги, symbolic links, junction и reparse points.
3. Открывает обычный файл один раз в read-only режиме.
4. Получает metadata открытого handle.
5. Читает поток порциями по 64 КБ.
6. Одновременно обновляет SHA-256 и bounded parser buffer.
7. Проверяет cancel, deadline и read budget между порциями.
8. Повторно получает metadata того же handle.
9. Не формирует отчёт, если размер, modified time или количество прочитанных байт изменились.
10. Передаёт накопленный parser buffer в PE parser без повторного открытия исходного пути.

Это устраняет прежний разрыв, когда hash, prefix и PE могли читаться из разных состояний файла.

## Ограничения атомарности

Windows не предоставляет одинаковую семантику стабильного file identity для всех файловых систем и сетевых путей. В v0.3.3 применяются:

- один handle;
- сверка размера и modified time;
- сверка фактически прочитанных байт;
- запрет reparse points;
- явный код `fileChanged` вместо сохранения сомнительного отчёта.

Проверка не утверждает, что внешний процесс не пытался изменить содержимое; она гарантирует, что обнаруженное изменение не будет замаскировано под успешный полный результат.

## JobRegistry

Каждый frontend item использует свой UUID как `jobId`. Rust `JobRegistry` хранит `Arc<JobToken>` до завершения команды.

`JobToken` содержит:

- atomic cancellation flag;
- `Notify` для async DNS/HTTP;
- общий deadline;
- метод `checkpoint()` для sync loops.

## Состояния frontend

```text
pending → running → completed
                  → failed
                  → cancelling → cancelled
```

`running → cancelled` напрямую запрещён. После кнопки остановки frontend показывает `cancelling` и ждёт типизированный ответ backend.

## Cleanup

Registry очищается после:

- успешного отчёта;
- типизированной ошибки;
- отмены;
- timeout;
- ошибки `spawn_blocking`/panic.

Pending items отменяются без регистрации, поскольку backend к ним ещё не обращался.

## Ресурсные бюджеты

- maximum file size;
- maximum bytes read;
- maximum parser memory;
- job timeout;
- ZIP entry count;
- ZIP declared uncompressed size;
- ZIP depth;
- ZIP compression ratio;
- active URL timeout;
- redirect count.

Ограничения имеют безопасные минимумы и максимумы и не могут быть полностью отключены через UI или повреждённое localStorage.
