'use client';

import { Search } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { useSearch } from '@/hooks/useSearch';
import { useEffect } from 'react';

interface SearchBarProps {
  placeholder?: string;
  onChange: (value: string) => void;
  defaultValue?: string;
  className?: string;
}

/**
 * Reusable search bar with debounced input
 * Triggers onChange callback after 300ms of inactivity
 */
export function SearchBar({
  placeholder = '검색...',
  onChange,
  defaultValue = '',
  className = '',
}: SearchBarProps) {
  const [searchQuery, debouncedValue, setSearchQuery] = useSearch(defaultValue, 300);

  useEffect(() => {
    onChange(debouncedValue);
  }, [debouncedValue, onChange]);

  return (
    <div className={`relative ${className}`}>
      <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
      <Input
        type="text"
        placeholder={placeholder}
        value={searchQuery}
        onChange={(e) => setSearchQuery(e.target.value)}
        className="pl-10"
      />
    </div>
  );
}
