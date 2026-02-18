"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  PenSquare,
  BookOpen,
  Database,
  Zap,
  Wrench,
  Link2,
  Settings,
  ChevronLeft,
  ChevronRight,
  Bike,
  Bot,
  Users,
  Activity,
  ShieldAlert,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
  TooltipProvider,
} from "@/components/ui/tooltip";
import { useState } from "react";

const navItems = [
  {
    title: "대시보드",
    href: "/dashboard",
    icon: LayoutDashboard,
  },
  {
    title: "블로그",
    href: "/manage/blog",
    icon: PenSquare,
  },
  {
    title: "포트폴리오",
    href: "/manage/portfolio",
    icon: BookOpen,
  },
  {
    title: "아카이브",
    href: "/archive",
    icon: BookOpen,
  },
  {
    title: "데이터",
    href: "/data",
    icon: Database,
  },
  {
    title: "사용자 관리",
    href: "/manage/users",
    icon: Users,
  },
  {
    title: "자동화",
    href: "/automation",
    icon: Zap,
  },
  {
    title: "활동 로그",
    href: "/automation/logs",
    icon: Activity,
  },
  {
    title: "페르소나 AI",
    href: "/persona",
    icon: Bot,
  },
  {
    title: "도구",
    href: "/tools",
    icon: Wrench,
  },
  {
    title: "스캐너",
    href: "/tools/scanner",
    icon: ShieldAlert,
  },
  {
    title: "링크",
    href: "/links",
    icon: Link2,
  },
];

const bottomItems = [
  {
    title: "설정",
    href: "/settings",
    icon: Settings,
  },
];

interface SidebarProps {
  className?: string;
}

export function Sidebar({ className }: SidebarProps) {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <TooltipProvider delayDuration={0}>
      <div
        className={cn(
          "relative hidden border-r bg-background z-20 md:flex md:flex-col transition-all duration-300",
          collapsed ? "w-16" : "w-64",
          className
        )}
      >
        {/* Logo */}
        <div className="flex h-14 items-center border-b px-4">
          <Link href="/dashboard" className="flex items-center gap-2">
            <Bot className="h-6 w-6 text-primary" />
            {!collapsed && (
              <span className="font-bold text-primary">보안으로 리다이렉트 중</span>
            )}
          </Link>
        </div>

        {/* Nav Items */}
        <ScrollArea className="flex-1 px-2 py-4">
          <nav className="flex flex-col gap-1">
            {navItems.map((item) => {
              const isActive = pathname.startsWith(item.href);
              const linkContent = (
                <Link
                  href={item.href}
                  className={cn(
                    "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                    isActive
                      ? "bg-sidebar-accent text-sidebar-accent-foreground"
                      : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                  )}
                >
                  <item.icon className="h-4 w-4 shrink-0" />
                  {!collapsed && <span>{item.title}</span>}
                </Link>
              );

              if (collapsed) {
                return (
                  <Tooltip key={item.href}>
                    <TooltipTrigger asChild>{linkContent}</TooltipTrigger>
                    <TooltipContent side="right">{item.title}</TooltipContent>
                  </Tooltip>
                );
              }

              return <div key={item.href}>{linkContent}</div>;
            })}
          </nav>
        </ScrollArea>

        {/* Bottom Items */}
        <div className="border-t px-2 py-4">
          <Separator className="mb-4" />
          {bottomItems.map((item) => {
            const isActive = pathname.startsWith(item.href);
            const linkContent = (
              <Link
                href={item.href}
                className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  isActive
                    ? "bg-sidebar-accent text-sidebar-accent-foreground"
                    : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                )}
              >
                <item.icon className="h-4 w-4 shrink-0" />
                {!collapsed && <span>{item.title}</span>}
              </Link>
            );

            if (collapsed) {
              return (
                <Tooltip key={item.href}>
                  <TooltipTrigger asChild>{linkContent}</TooltipTrigger>
                  <TooltipContent side="right">{item.title}</TooltipContent>
                </Tooltip>
              );
            }

            return <div key={item.href}>{linkContent}</div>;
          })}
        </div>

        {/* Collapse Toggle */}
        <Button
          variant="ghost"
          size="icon"
          className="absolute -right-3 top-16 z-10 h-6 w-6 rounded-full border bg-background"
          onClick={() => setCollapsed(!collapsed)}
        >
          {collapsed ? (
            <ChevronRight className="h-3 w-3" />
          ) : (
            <ChevronLeft className="h-3 w-3" />
          )}
        </Button>
      </div>
    </TooltipProvider>
  );
}
