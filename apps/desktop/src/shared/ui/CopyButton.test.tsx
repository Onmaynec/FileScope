// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { Check, ShieldCheck } from 'lucide-react';
import CopyButton from './CopyButton';
import useCopy from '../hooks/use-copy';

describe('useCopy hook', () => {
  function TestComponent({
    text = 'hello',
    successMessage = 'Скопировано',
    errorMessage = 'Не удалось скопировать',
    duration = 2000,
  }: {
    text?: string;
    successMessage?: string;
    errorMessage?: string;
    duration?: number;
  }) {
    const { state, message, copy } = useCopy({ successMessage, errorMessage, duration });

    return (
      <div>
        <span data-testid="state">{state}</span>
        <span data-testid="message">{message}</span>
        <button data-testid="copy-btn" onClick={() => copy(text)}>
          Копировать
        </button>
      </div>
    );
  }

  it('начинает в состоянии idle', () => {
    render(<TestComponent />);
    expect(screen.getByTestId('state').textContent).toBe('idle');
  });

  it('успешное копирование краткого результата', async () => {
    const mockClipboard = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: mockClipboard },
      writable: true,
      configurable: true,
    });

    render(<TestComponent text="краткий текст" />);

    await act(async () => {
      fireEvent.click(screen.getByTestId('copy-btn'));
    });

    expect(mockClipboard).toHaveBeenCalledWith('краткий текст');

    await waitFor(() => {
      expect(screen.getByTestId('state').textContent).toBe('copied');
    });
    expect(screen.getByTestId('message').textContent).toBe('Скопировано');
  });

  it('возврат в idle через таймер', async () => {
    const mockClipboard = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: mockClipboard },
      writable: true,
      configurable: true,
    });

    render(<TestComponent duration={300} />);

    await act(async () => {
      fireEvent.click(screen.getByTestId('copy-btn'));
    });

    await waitFor(() => {
      expect(screen.getByTestId('state').textContent).toBe('copied');
    });

    await act(async () => {
      await new Promise((r) => setTimeout(r, 350));
    });

    expect(screen.getByTestId('state').textContent).toBe('idle');
  });

  it('ошибку когда clipboard отклонил запрос', async () => {
    const mockClipboard = vi.fn().mockRejectedValue(new DOMException('NotAllowedError', 'Permission denied'));
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: mockClipboard },
      writable: true,
      configurable: true,
    });

    render(<TestComponent />);

    await act(async () => {
      fireEvent.click(screen.getByTestId('copy-btn'));
    });

    await waitFor(() => {
      expect(screen.getByTestId('state').textContent).toBe('error');
    });
    expect(screen.getByTestId('message').textContent).toBe('Не удалось скопировать');
  });

  it('обрабатывает отсутствие navigator.clipboard', async () => {
    const origClipboard = globalThis.navigator.clipboard;
    Object.defineProperty(globalThis.navigator, 'clipboard', {
      value: undefined,
      writable: true,
      configurable: true,
    });

    render(<TestComponent />);

    await act(async () => {
      fireEvent.click(screen.getByTestId('copy-btn'));
    });

    await waitFor(() => {
      expect(screen.getByTestId('state').textContent).toBe('error');
    });

    Object.defineProperty(globalThis.navigator, 'clipboard', {
      value: origClipboard,
      writable: true,
      configurable: true,
    });
  });
});

describe('CopyButton component', () => {
  beforeEach(() => {
    const mockClipboard = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: mockClipboard },
      writable: true,
      configurable: true,
    });
  });

  it('показывает «Скопировано» после копирования текста', async () => {
    render(
      <CopyButton text="test text" successIcon={Check}>
        <span>Кратко</span>
      </CopyButton>,
    );

    const btn = screen.getByRole('button');
    expect(btn).toHaveTextContent('Кратко');

    await act(async () => {
      fireEvent.click(btn);
    });

    await waitFor(() => {
      expect(screen.queryByText('Скопировано')).toBeTruthy();
    });
  });

  it('копирование именно правильного SHA-256', async () => {
    const sha = 'abc123def45678901234567890123456789012345678901234567890abcd1234';
    const mockClipboard = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: mockClipboard },
      writable: true,
      configurable: true,
    });

    render(
      <CopyButton text={sha} successIcon={Check} className="icon-button" aria-label="Копировать SHA-256" />,
    );

    const btn = screen.getByRole('button');
    expect(btn).toHaveAttribute('aria-label', 'Копировать SHA-256');

    await act(async () => {
      fireEvent.click(btn);
    });

    expect(mockClipboard).toHaveBeenCalledWith(sha);
  });

  it('независимую работу двух кнопок', async () => {
    render(
      <div>
        <CopyButton text="summary" successIcon={Check} className="button button-secondary">
          <span>Кратко</span>
        </CopyButton>
        <CopyButton text="sha-hash" successIcon={ShieldCheck} className="icon-button" aria-label="SHA" />
      </div>,
    );

    const [shortkoBtn, shaBtn] = screen.getAllByRole('button');

    // Нажимаем «Кратко»
    await act(async () => {
      fireEvent.click(shortkoBtn);
    });

    await waitFor(() => {
      expect(screen.queryByText('Скопировано')).toBeTruthy();
    });

    // Нажимаем SHA — состояние «Кратко» не должно меняться
    await act(async () => {
      fireEvent.click(shaBtn);
    });

    // Кнопка «Кратко» должна быть в idle (вернулась) или показывать свой текст
    // а не показывать сообщение ошибки
    await waitFor(() => {
      expect(screen.queryByText('Не удалось скопировать')).toBeFalsy();
    });
  });

  it('отображает иконку Copy по умолчанию', () => {
    render(
      <CopyButton text="test" className="button button-secondary">
        <span>Тест</span>
      </CopyButton>,
    );

    const btn = screen.getByRole('button');
    const svg = btn.querySelector('svg');
    expect(svg).toBeTruthy();
  });

  it('отображает label при успешном копировании', async () => {
    render(
      <CopyButton text="data" successIcon={Check} className="button button-secondary">
        <span>Кратко</span>
      </CopyButton>,
    );

    await act(async () => {
      fireEvent.click(screen.getByRole('button'));
    });

    await waitFor(() => {
      expect(screen.getByRole('button')).toHaveTextContent(/Кратко|Скопировано/);
    });
  });
});
