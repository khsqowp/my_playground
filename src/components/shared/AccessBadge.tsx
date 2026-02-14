import { Badge } from '@/components/ui/badge';
import { Globe, Lock, Users } from 'lucide-react';

interface AccessBadgeProps {
  visibility: 'PUBLIC' | 'PRIVATE' | 'SHARED';
  className?: string;
}

export function AccessBadge({ visibility, className }: AccessBadgeProps) {
  const variants = {
    PUBLIC: {
      variant: 'default' as const,
      className: 'bg-green-100 text-green-800 hover:bg-green-200 dark:bg-green-900 dark:text-green-200',
      icon: Globe,
      label: 'Public',
    },
    PRIVATE: {
      variant: 'default' as const,
      className: 'bg-red-100 text-red-800 hover:bg-red-200 dark:bg-red-900 dark:text-red-200',
      icon: Lock,
      label: 'Private',
    },
    SHARED: {
      variant: 'default' as const,
      className: 'bg-yellow-100 text-yellow-800 hover:bg-yellow-200 dark:bg-yellow-900 dark:text-yellow-200',
      icon: Users,
      label: 'Shared',
    },
  };

  const config = variants[visibility];
  const Icon = config.icon;

  return (
    <Badge variant={config.variant} className={`${config.className} ${className || ''}`}>
      <Icon className="w-3 h-3 mr-1" />
      {config.label}
    </Badge>
  );
}
