export const ru = {
  app: { name: 'FileScope', version: 'Версия 0.1.0 · Foundation' },
  navigation: {
    ariaLabel: 'Основная навигация',
    home: 'Главная', scan: 'Проверка', links: 'Ссылки', files: 'Файлы',
    archives: 'Архивы', programs: 'Программы', reports: 'Отчёты',
    quarantine: 'Карантин', settings: 'Настройки',
  },
  home: {
    eyebrow: 'ПРОВЕРЬТЕ ДО ЗАПУСКА',
    title: 'Проверка ссылок, файлов и архивов до запуска',
    subtitle: 'Выберите объект или перетащите его в окно FileScope.',
    dropzoneTitle: 'Перетащите файл, архив или папку',
    comingSoon: 'Функциональные модули анализа появятся в следующих версиях.',
    chooseFile: 'Выбрать файл',
    quickActions: 'Быстрые действия',
    privacy: 'FileScope не загружает файлы во внешние сервисы без разрешения пользователя.',
  },
  actions: {
    link: { title: 'Проверить ссылку', description: 'Разберите адрес до открытия страницы.' },
    file: { title: 'Проверить файл', description: 'Выберите объект на устройстве.' },
    archive: { title: 'Проверить архив', description: 'Просмотрите содержимое архива.' },
    program: { title: 'Проверить программу', description: 'Выберите установленное приложение.' },
  },
  dialogs: {
    unavailableTitle: 'Функция пока недоступна',
    unavailableText: 'Модуль анализа находится в разработке и будет доступен в следующей версии.',
    close: 'Понятно',
  },
} as const;

export type Localization = typeof ru;
