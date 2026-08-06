import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { Select } from './Select';

const options = [
  { value: 'system', label: 'Системная' },
  { value: 'dark', label: 'Тёмная' },
  { value: 'light', label: 'Светлая' },
] as const;

describe('Select', () => {
  it('открывается и выбирает option клавиатурой', () => {
    const onChange = vi.fn();
    render(<Select label="Тема приложения" value="system" options={options} onChange={onChange} />);
    const trigger = screen.getByRole('button', { name: 'Тема приложения' });
    fireEvent.keyDown(trigger, { key: 'Enter' });
    const option = screen.getByRole('option', { name: 'Тёмная' });
    option.focus();
    fireEvent.keyDown(option, { key: 'Enter' });
    expect(onChange).toHaveBeenCalledWith('dark');
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  });

  it('закрывается по Escape с возвратом фокуса', async () => {
    render(<Select label="Тема приложения" value="system" options={options} onChange={() => undefined} />);
    const trigger = screen.getByRole('button', { name: 'Тема приложения' });
    fireEvent.click(trigger);
    fireEvent.keyDown(screen.getByRole('option', { name: 'Системная' }), { key: 'Escape' });
    await Promise.resolve();
    expect(trigger).toHaveFocus();
  });
});
