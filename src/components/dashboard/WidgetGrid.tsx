'use client';

import { ReactNode } from 'react';

interface WidgetGridProps {
  children: ReactNode;
  className?: string;
}

/**
 * Responsive grid layout for dashboard widgets
 * Adapts from 1 column on mobile to 3 columns on desktop
 */
export function WidgetGrid({ children, className = '' }: WidgetGridProps) {
  return (
    <div
      className={`grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 md:gap-6 ${className}`}
    >
      {children}
    </div>
  );
}
