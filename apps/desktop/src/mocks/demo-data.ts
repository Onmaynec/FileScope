export type DemoRisk = 'noThreatsFound' | 'caution' | 'highRisk' | 'dangerous';

export interface DemoReport {
  id: string;
  name: string;
  kind: 'Файл' | 'Ссылка' | 'Архив' | 'Программа';
  risk: DemoRisk;
  summary: string;
  recommendation: string;
  indicators: string[];
  isDemo: true;
}

export const demoReports: DemoReport[] = [
  {
    id: 'safe-file', name: 'example-safe.exe', kind: 'Файл', risk: 'noThreatsFound',
    summary: 'Во время демонстрационной проверки не обнаружено известных признаков вредоносного поведения.',
    recommendation: 'Перед запуском всё равно убедитесь, что файл получен из доверенного источника.',
    indicators: ['Действительная цифровая подпись', 'Не обнаружены механизмы автозапуска'], isDemo: true,
  },
  {
    id: 'caution-file', name: 'unsigned-tool.exe', kind: 'Файл', risk: 'caution',
    summary: 'Обнаружены необычные характеристики, но их недостаточно для подтверждения угрозы.',
    recommendation: 'Уточните источник файла и не запускайте его с правами администратора.',
    indicators: ['Отсутствует цифровая подпись', 'Исполняемый файл упакован'], isDemo: true,
  },
  {
    id: 'high-risk-file', name: 'suspicious-loader.exe', kind: 'Файл', risk: 'highRisk',
    summary: 'Обнаружено несколько признаков потенциально опасного поведения.',
    recommendation: 'Не запускайте объект до дополнительной проверки.',
    indicators: ['Может закрепляться в автозапуске', 'Обнаружены признаки загрузчика', 'Подозрительные сетевые адреса'], isDemo: true,
  },
  {
    id: 'dangerous-file', name: 'demo-malware.exe', kind: 'Файл', risk: 'dangerous',
    summary: 'Объект содержит признаки вредоносного поведения и может представлять угрозу системе.',
    recommendation: 'Не запускайте объект. Демонстрационную запись можно поместить в mock-карантин.',
    indicators: ['Может обращаться к данным браузера', 'Обнаружены признаки кейлогера', 'Может устанавливать скрытое соединение'], isDemo: true,
  },
];

export const demoPrograms = [
  { id: 'p1', name: 'FileScope Demo Browser', publisher: 'FileScope Labs', version: '1.2.0', installed: '02.08.2026', isDemo: true },
  { id: 'p2', name: 'Example Editor', publisher: 'Example Software', version: '4.8.1', installed: '18.07.2026', isDemo: true },
];

export const demoArchiveTree = ['ExampleArchive.zip', '├── README.txt', '├── images/', '├── installer.exe', '└── screenshot.jpg.exe'];
