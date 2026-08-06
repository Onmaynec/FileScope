import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { Check, ChevronDown } from 'lucide-react';

export interface SelectOption<Value extends string> {
  value: Value;
  label: string;
}

interface SelectProps<Value extends string> {
  label: string;
  value: Value;
  options: readonly SelectOption<Value>[];
  onChange: (value: Value) => void;
  disabled?: boolean;
}

export function Select<Value extends string>({ label, value, options, onChange, disabled = false }: SelectProps<Value>) {
  const id = useId();
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const optionRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const selectedIndex = Math.max(0, options.findIndex((option) => option.value === value));
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(selectedIndex);
  const [placement, setPlacement] = useState<'down' | 'up'>('down');

  const close = useCallback((restoreFocus: boolean) => {
    setOpen(false);
    if (restoreFocus) queueMicrotask(() => triggerRef.current?.focus());
  }, []);

  useEffect(() => setActiveIndex(selectedIndex), [selectedIndex]);
  useLayoutEffect(() => {
    if (!open || !triggerRef.current) return;
    const rect = triggerRef.current.getBoundingClientRect();
    const estimatedHeight = Math.min(280, options.length * 41 + 12);
    const spaceBelow = window.innerHeight - rect.bottom;
    const spaceAbove = rect.top;
    setPlacement(spaceBelow < estimatedHeight && spaceAbove > spaceBelow ? 'up' : 'down');
  }, [open, options.length]);
  useEffect(() => {
    if (!open) return;
    optionRefs.current[activeIndex]?.focus();
  }, [activeIndex, open]);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) close(true);
    };
    const onResize = () => close(false);
    document.addEventListener('pointerdown', onPointerDown);
    window.addEventListener('resize', onResize);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      window.removeEventListener('resize', onResize);
    };
  }, [close, open]);

  const choose = (index: number) => {
    const option = options[index];
    if (!option) return;
    onChange(option.value);
    setActiveIndex(index);
    close(true);
  };

  const move = (next: number) => {
    const normalized = (next + options.length) % options.length;
    setActiveIndex(normalized);
  };

  const onTriggerKeyDown = (event: React.KeyboardEvent<HTMLButtonElement>) => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp' || event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      setActiveIndex(event.key === 'ArrowUp' ? options.length - 1 : selectedIndex);
      setOpen(true);
    }
  };

  const onOptionKeyDown = (event: React.KeyboardEvent<HTMLButtonElement>, index: number) => {
    if (event.key === 'ArrowDown') { event.preventDefault(); move(index + 1); }
    if (event.key === 'ArrowUp') { event.preventDefault(); move(index - 1); }
    if (event.key === 'Home') { event.preventDefault(); setActiveIndex(0); }
    if (event.key === 'End') { event.preventDefault(); setActiveIndex(options.length - 1); }
    if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); choose(index); }
    if (event.key === 'Escape') { event.preventDefault(); close(true); }
    if (event.key === 'Tab') close(false);
  };

  const selected = options[selectedIndex];
  return <div className={`fs-select ${open ? 'open' : ''} placement-${placement}`} ref={rootRef}>
    <button
      ref={triggerRef}
      type="button"
      className="fs-select__trigger"
      aria-label={label}
      aria-haspopup="listbox"
      aria-expanded={open}
      aria-controls={`${id}-listbox`}
      disabled={disabled}
      onClick={() => { setActiveIndex(selectedIndex); setOpen((current) => !current); }}
      onKeyDown={onTriggerKeyDown}
    >
      <span>{selected?.label ?? value}</span><ChevronDown aria-hidden="true" />
    </button>
    {open && <div className="fs-select__popover" id={`${id}-listbox`} role="listbox" aria-label={label}>
      {options.map((option, index) => <button
        key={option.value}
        ref={(node) => { optionRefs.current[index] = node; }}
        type="button"
        role="option"
        aria-selected={option.value === value}
        className={`fs-select__option ${index === activeIndex ? 'active' : ''}`}
        tabIndex={index === activeIndex ? 0 : -1}
        onMouseEnter={() => setActiveIndex(index)}
        onClick={() => choose(index)}
        onKeyDown={(event) => onOptionKeyDown(event, index)}
      >
        <span>{option.label}</span>{option.value === value && <Check aria-hidden="true" />}
      </button>)}
    </div>}
  </div>;
}
