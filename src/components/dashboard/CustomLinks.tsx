'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  ExternalLink,
  Plus,
  Trash2,
  GripVertical,
  Loader2,
  Globe,
  Github,
  Twitter,
  Linkedin,
  Mail,
} from 'lucide-react';
import { toast } from 'sonner';

interface ExternalLinkType {
  id: string;
  title: string;
  url: string;
  icon: string | null;
  order: number;
}

// Icon mapping for common platforms
const iconMap: Record<string, any> = {
  globe: Globe,
  github: Github,
  twitter: Twitter,
  linkedin: Linkedin,
  mail: Mail,
  external: ExternalLink,
};

export function CustomLinks() {
  const [links, setLinks] = useState<ExternalLinkType[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [newLink, setNewLink] = useState({ title: '', url: '', icon: 'globe' });

  useEffect(() => {
    fetchLinks();
  }, []);

  const fetchLinks = async () => {
    try {
      setIsLoading(true);
      const response = await fetch('/api/links');
      if (!response.ok) throw new Error('Failed to fetch links');

      const data = await response.json();
      setLinks(data.links || []);
    } catch (error) {
      console.error('Failed to fetch links:', error);
      toast.error('링크를 불러오지 못했습니다');
    } finally {
      setIsLoading(false);
    }
  };

  const handleAddLink = async () => {
    if (!newLink.title.trim() || !newLink.url.trim()) {
      toast.error('제목과 URL은 필수입니다');
      return;
    }

    try {
      const response = await fetch('/api/links', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newLink),
      });

      if (!response.ok) throw new Error('Failed to add link');

      const data = await response.json();
      setLinks((prev) => [...prev, data.link]);
      setNewLink({ title: '', url: '', icon: 'globe' });
      setIsDialogOpen(false);
      toast.success('링크가 추가되었습니다!');
    } catch (error) {
      console.error('Failed to add link:', error);
      toast.error('링크 추가에 실패했습니다');
    }
  };

  const handleDeleteLink = async (linkId: string) => {
    try {
      const response = await fetch(`/api/links/${linkId}`, {
        method: 'DELETE',
      });

      if (!response.ok) throw new Error('Failed to delete link');

      setLinks((prev) => prev.filter((link) => link.id !== linkId));
      toast.success('링크가 삭제되었습니다');
    } catch (error) {
      console.error('Failed to delete link:', error);
      toast.error('링크 삭제에 실패했습니다');
    }
  };

  const getIconComponent = (iconName: string | null) => {
    const Icon = iconMap[iconName || 'globe'] || Globe;
    return Icon;
  };

  return (
    <Card className="h-full flex flex-col">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg font-semibold">맞춤 링크</CardTitle>
          <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
            <DialogTrigger asChild>
              <Button size="sm" variant="ghost">
                <Plus className="w-4 h-4" />
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>외부 링크 추가</DialogTitle>
              </DialogHeader>
              <div className="space-y-4 mt-4">
                <div className="space-y-2">
                  <Label htmlFor="title">제목</Label>
                  <Input
                    id="title"
                    placeholder="즐겨찾는 사이트"
                    value={newLink.title}
                    onChange={(e) => setNewLink({ ...newLink, title: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="url">URL</Label>
                  <Input
                    id="url"
                    type="url"
                    placeholder="https://example.com"
                    value={newLink.url}
                    onChange={(e) => setNewLink({ ...newLink, url: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="icon">아이콘</Label>
                  <select
                    id="icon"
                    className="w-full px-3 py-2 rounded-md border bg-background"
                    value={newLink.icon}
                    onChange={(e) => setNewLink({ ...newLink, icon: e.target.value })}
                  >
                    <option value="globe">Globe</option>
                    <option value="github">GitHub</option>
                    <option value="twitter">Twitter</option>
                    <option value="linkedin">LinkedIn</option>
                    <option value="mail">Mail</option>
                    <option value="external">외부 링크</option>
                  </select>
                </div>
                <Button onClick={handleAddLink} className="w-full">
                  링크 추가
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </CardHeader>
      <CardContent className="flex-1">
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : links.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <ExternalLink className="w-12 h-12 text-muted-foreground/50 mb-3" />
            <p className="text-sm text-muted-foreground mb-4">아직 링크가 없습니다</p>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setIsDialogOpen(true)}
            >
              <Plus className="w-4 h-4 mr-2" />
              첫 번째 링크 추가하기
            </Button>
          </div>
        ) : (
          <ScrollArea className="h-[300px]">
            <div className="grid grid-cols-1 gap-2">
              {links.map((link) => {
                const Icon = getIconComponent(link.icon);

                return (
                  <div
                    key={link.id}
                    className="flex items-center gap-3 p-3 rounded-lg border bg-card hover:bg-accent/50 transition-colors group"
                  >
                    <GripVertical className="w-4 h-4 text-muted-foreground cursor-grab" />
                    <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
                      <Icon className="w-4 h-4 text-primary" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <a
                        href={link.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm font-medium hover:underline line-clamp-1"
                      >
                        {link.title}
                      </a>
                      <p className="text-xs text-muted-foreground line-clamp-1">
                        {link.url}
                      </p>
                    </div>
                    <Button
                      size="icon"
                      variant="ghost"
                      className="h-8 w-8 opacity-0 group-hover:opacity-100 transition-opacity text-destructive"
                      onClick={() => handleDeleteLink(link.id)}
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
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
