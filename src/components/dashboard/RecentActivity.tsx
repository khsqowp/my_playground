'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  FileText,
  BookOpen,
  StickyNote,
  Link as LinkIcon,
  Settings,
  Trash2,
  Edit,
  Plus,
  Eye,
  Share2,
  Loader2,
} from 'lucide-react';
import { format } from 'date-fns';
import { toast } from 'sonner';

interface Activity {
  id: string;
  action: string;
  target: string;
  targetId: string | null;
  createdAt: string;
}

// Map action types to icons
const getActivityIcon = (action: string) => {
  const lowerAction = action.toLowerCase();

  if (lowerAction.includes('create') || lowerAction.includes('add')) return Plus;
  if (lowerAction.includes('update') || lowerAction.includes('edit')) return Edit;
  if (lowerAction.includes('delete') || lowerAction.includes('remove')) return Trash2;
  if (lowerAction.includes('view') || lowerAction.includes('read')) return Eye;
  if (lowerAction.includes('share')) return Share2;

  return Settings;
};

// Map target types to icons
const getTargetIcon = (target: string) => {
  const lowerTarget = target.toLowerCase();

  if (lowerTarget.includes('post') || lowerTarget.includes('blog')) return FileText;
  if (lowerTarget.includes('note') || lowerTarget.includes('archive')) return BookOpen;
  if (lowerTarget.includes('memo')) return StickyNote;
  if (lowerTarget.includes('link')) return LinkIcon;

  return FileText;
};

// Format action text for better readability
const formatAction = (action: string, target: string) => {
  return `${action} ${target}`;
};

export function RecentActivity() {
  const [activities, setActivities] = useState<Activity[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetchActivities();
  }, []);

  const fetchActivities = async () => {
    try {
      setIsLoading(true);
      const response = await fetch('/api/activity?limit=10');
      if (!response.ok) throw new Error('Failed to fetch activities');

      const data = await response.json();
      setActivities(data.activities || []);
    } catch (error) {
      console.error('Failed to fetch activities:', error);
      toast.error('Failed to load recent activities');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Card className="h-full flex flex-col">
      <CardHeader>
        <CardTitle className="text-lg font-semibold">최근 활동</CardTitle>
      </CardHeader>
      <CardContent className="flex-1">
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : activities.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <Settings className="w-12 h-12 text-muted-foreground/50 mb-3" />
            <p className="text-sm text-muted-foreground">최근 활동이 없습니다</p>
          </div>
        ) : (
          <ScrollArea className="h-[300px]">
            <div className="space-y-3">
              {activities.map((activity) => {
                const ActionIcon = getActivityIcon(activity.action);
                const TargetIcon = getTargetIcon(activity.target);

                return (
                  <div
                    key={activity.id}
                    className="flex items-start gap-3 p-3 rounded-lg border bg-card hover:bg-accent/50 transition-colors"
                  >
                    <div className="relative">
                      <div className="w-9 h-9 rounded-full bg-primary/10 flex items-center justify-center">
                        <TargetIcon className="w-4 h-4 text-primary" />
                      </div>
                      <div className="absolute -bottom-1 -right-1 w-5 h-5 rounded-full bg-background border-2 border-background flex items-center justify-center">
                        <ActionIcon className="w-3 h-3 text-muted-foreground" />
                      </div>
                    </div>

                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium">
                        {formatAction(activity.action, activity.target)}
                      </p>
                      <p className="text-xs text-muted-foreground mt-0.5">
                        {format(new Date(activity.createdAt), 'MMM d, yyyy • h:mm a')}
                      </p>
                    </div>
                  </div>
                );
              })}
            </div>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  );
}
