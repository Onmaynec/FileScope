import type { ComponentType, SVGProps } from 'react';
import { Copy } from 'lucide-react';
import useCopy from '../hooks/use-copy';

interface CopyButtonProps {
  text: string;
  children?: React.ReactNode;
  successIcon?: ComponentType<SVGProps<SVGSVGElement>>;
  idleIcon?: ComponentType<SVGProps<SVGSVGElement>>;
  className?: string;
  'aria-label'?: string;
}

function CopyButton({
  text,
  children,
  successIcon,
  idleIcon = Copy,
  className = 'button button-secondary',
  'aria-label': ariaLabel,
}: CopyButtonProps) {
  const { state, message, copy } = useCopy();

  const Icon = state === 'copying' ? idleIcon
    : state === 'copied' || state === 'error' ? (successIcon ?? idleIcon)
    : idleIcon;

  const label = state === 'copying' ? 'Копируется…'
    : state === 'error' ? 'Не удалось скопировать'
    : typeof children === 'string' ? children
    : '';

  return (
    <button
      className={className}
      onClick={() => void copy(text)}
      aria-label={ariaLabel}
    >
      {Icon && <Icon />}
      {children}
      {label && <span>{label}</span>}
      {message && <span className="helper-text" role="status" aria-live="polite">{message}</span>}
    </button>
  );
}

export default CopyButton;
