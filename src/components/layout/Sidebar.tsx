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
  ChevronDown,
  Bot,
  Users,
  Activity,
  ShieldAlert,
  FileArchive,
  GitPullRequest,
  Webhook,
  Sparkles,
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

interface NavChild {
  title: string;
  href: string;
  icon: React.ElementType;
}

interface NavItem {
  title: string;
  href: string;
  icon: React.ElementType;
  children?: NavChild[];
}

const navItems: NavItem[] = [
  { title: "대시보드", href: "/dashboard", icon: LayoutDashboard },
  { title: "블로그", href: "/manage/blog", icon: PenSquare },
  { title: "포트폴리오", href: "/manage/portfolio", icon: BookOpen },
  {
    title: "아카이브",
    href: "/archive",
    icon: BookOpen,
    children: [
      { title: "파일 아카이브", href: "/archive/files", icon: FileArchive },
    ],
  },
  { title: "데이터", href: "/data", icon: Database },
  { title: "사용자 관리", href: "/manage/users", icon: Users },
  {
    title: "자동화",
    href: "/automation",
    icon: Zap,
    children: [
      { title: "웹훅", href: "/automation/webhooks", icon: Webhook },
      { title: "활동 로그", href: "/automation/logs", icon: Activity },
      { title: "AI 자동화", href: "/automation/ai", icon: Sparkles },
      { title: "코드 리뷰", href: "/automation/code-review", icon: GitPullRequest },
    ],
  },
  { title: "페르소나 AI", href: "/persona", icon: Bot },
  {
    title: "도구",
    href: "/tools",
    icon: Wrench,
    children: [
      { title: "스캐너", href: "/tools/scanner", icon: ShieldAlert },
    ],
  },
  { title: "링크", href: "/links", icon: Link2 },
];

const bottomItems: NavItem[] = [
  { title: "설정", href: "/settings", icon: Settings },
];

interface SidebarProps {
  className?: string;
}

function NavGroup({
  item,
  pathname,
  collapsed,
}: {
  item: NavItem;
  pathname: string;
  collapsed: boolean;
}) {
  const hasChildren = item.children && item.children.length > 0;
  const isParentActive = pathname.startsWith(item.href);
  const isChildActive = item.children?.some((c) => pathname.startsWith(c.href)) ?? false;
  const [open, setOpen] = useState(isParentActive || isChildActive);

  if (!hasChildren) {
    const linkContent = (
      <Link
        href={item.href}
        className={cn(
          "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
          isParentActive
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
        <Tooltip>
          <TooltipTrigger asChild>{linkContent}</TooltipTrigger>
          <TooltipContent side="right">{item.title}</TooltipContent>
        </Tooltip>
      );
    }
    return <div>{linkContent}</div>;
  }

  // Has children
  if (collapsed) {
    // In collapsed mode, show children as individual tooltip items
    return (
      <>
        <Tooltip>
          <TooltipTrigger asChild>
            <Link
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                isParentActive
                  ? "bg-sidebar-accent text-sidebar-accent-foreground"
                  : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
              )}
            >
              <item.icon className="h-4 w-4 shrink-0" />
            </Link>
          </TooltipTrigger>
          <TooltipContent side="right">{item.title}</TooltipContent>
        </Tooltip>
        {item.children?.map((child) => (
          <Tooltip key={child.href}>
            <TooltipTrigger asChild>
              <Link
                href={child.href}
                className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  pathname.startsWith(child.href)
                    ? "bg-sidebar-accent text-sidebar-accent-foreground"
                    : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                )}
              >
                <child.icon className="h-4 w-4 shrink-0" />
              </Link>
            </TooltipTrigger>
            <TooltipContent side="right">{child.title}</TooltipContent>
          </Tooltip>
        ))}
      </>
    );
  }

  // Expanded mode with collapsible children
  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        className={cn(
          "flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
          (isParentActive || isChildActive)
            ? "bg-sidebar-accent text-sidebar-accent-foreground"
            : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
        )}
      >
        <item.icon className="h-4 w-4 shrink-0" />
        <span className="flex-1 text-left">{item.title}</span>
        <ChevronDown
          className={cn("h-3 w-3 shrink-0 transition-transform", open && "rotate-180")}
        />
      </button>

      {open && (
        <div className="ml-3 mt-1 flex flex-col gap-1 border-l pl-3">
          {item.children?.map((child) => {
            const isActive = pathname.startsWith(child.href);
            return (
              <Link
                key={child.href}
                href={child.href}
                className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  isActive
                    ? "bg-sidebar-accent text-sidebar-accent-foreground"
                    : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                )}
              >
                <child.icon className="h-4 w-4 shrink-0" />
                <span>{child.title}</span>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
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
            {navItems.map((item) => (
              <NavGroup
                key={item.href}
                item={item}
                pathname={pathname}
                collapsed={collapsed}
              />
            ))}
          </nav>
        </ScrollArea>

        {/* Bottom Items */}
        <div className="border-t px-2 py-4">
          <Separator className="mb-4" />
          {bottomItems.map((item) => (
            <NavGroup
              key={item.href}
              item={item}
              pathname={pathname}
              collapsed={collapsed}
            />
          ))}
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
