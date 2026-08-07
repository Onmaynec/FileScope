import { useCallback, useEffect, useRef, useState } from 'react';

export type CopyState = 'idle' | 'copying' | 'copied' | 'error';

export interface UseCopyOptions {
  successMessage?: string;
  errorMessage?: string;
  duration?: number;
}

const DEFAULT_DURATION = 2000;

function useCopy(options: UseCopyOptions = {}) {
  const {
    successMessage = 'Скопировано',
    errorMessage = 'Не удалось скопировать',
    duration = DEFAULT_DURATION,
  } = options;

  const [state, setState] = useState<CopyState>('idle');
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isActiveRef = useRef<boolean>(true);

  const clearTimer = useCallback(() => {
    if (timerRef.current !== null) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  useEffect(() => {
    return () => {
      isActiveRef.current = false;
      clearTimer();
    };
  }, [clearTimer]);

  const copy = useCallback(async (text: string) => {
    clearTimer();

    if (!navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') {
      setState('error');
      return;
    }

    setState('copying');

    try {
      await navigator.clipboard.writeText(text);

      if (!isActiveRef.current) return;

      setState('copied');

      timerRef.current = setTimeout(() => {
        if (isActiveRef.current) {
          setState('idle');
        }
        timerRef.current = null;
      }, duration);
    } catch {
      if (!isActiveRef.current) return;
      setState('error');

      timerRef.current = setTimeout(() => {
        if (isActiveRef.current) {
          setState('idle');
        }
        timerRef.current = null;
      }, duration);
    }
  }, [clearTimer, duration]);

  return { state, message: state === 'copied' ? successMessage : state === 'error' ? errorMessage : '', copy };
}

export default useCopy;
