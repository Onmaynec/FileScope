import { CheckCircle2, Info, TriangleAlert, X, XCircle } from 'lucide-react';

export type ToastTone = 'success' | 'info' | 'warning' | 'error';

export interface ToastMessage {
  id: string;
  tone: ToastTone;
  title: string;
  text?: string;
}

interface ToastHostProps {
  messages: ToastMessage[];
  onDismiss: (id: string) => void;
}

const icons = {
  success: CheckCircle2,
  info: Info,
  warning: TriangleAlert,
  error: XCircle,
};

export function ToastHost({ messages, onDismiss }: ToastHostProps) {
  return (
    <section className="toast-host" aria-live="polite" aria-label="Уведомления">
      {messages.map((message) => {
        const Icon = icons[message.tone];
        return (
          <article className={`toast toast-${message.tone}`} key={message.id} role="status">
            <Icon aria-hidden="true" />
            <div><strong>{message.title}</strong>{message.text && <span>{message.text}</span>}</div>
            <button className="icon-button" onClick={() => onDismiss(message.id)} aria-label="Закрыть уведомление"><X /></button>
          </article>
        );
      })}
    </section>
  );
}
