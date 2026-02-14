import { useState, useEffect } from 'react';

/**
 * Hook for debounced search functionality
 * @param initialValue - Initial search query
 * @param delay - Debounce delay in milliseconds (default: 300ms)
 * @returns [searchQuery, debouncedValue, setSearchQuery]
 */
export function useSearch(initialValue: string = '', delay: number = 300) {
  const [searchQuery, setSearchQuery] = useState(initialValue);
  const [debouncedValue, setDebouncedValue] = useState(initialValue);

  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedValue(searchQuery);
    }, delay);

    return () => {
      clearTimeout(handler);
    };
  }, [searchQuery, delay]);

  return [searchQuery, debouncedValue, setSearchQuery] as const;
}
