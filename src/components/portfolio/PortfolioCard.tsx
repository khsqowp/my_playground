import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Calendar, Globe, Github } from "lucide-react";
import { formatDate } from "@/lib/utils";

interface PortfolioCardProps {
    portfolio: {
        id: string;
        title: string;
        description: string | null;
        coverImage: string | null;
        techStack: string | null;
        links: any;
        createdAt: string;
    };
    basePath?: string;
}

export function PortfolioCard({ portfolio, basePath = "/portfolio" }: PortfolioCardProps) {
    const links = Array.isArray(portfolio.links) ? portfolio.links : [];
    const demoLink = links.find((l: any) => l.type === 'demo' || l.url?.includes('demo') || l.title?.toLowerCase().includes('demo'));
    const githubLink = links.find((l: any) => l.type === 'github' || l.url?.includes('github') || l.title?.toLowerCase().includes('github'));

    return (
        <Card className="h-full flex flex-col transition-shadow hover:shadow-md overflow-hidden group">
            <Link href={`${basePath}/${portfolio.id}`} className="block">
                <div className="aspect-video overflow-hidden bg-muted relative">
                    {portfolio.coverImage ? (
                        <img
                            src={portfolio.coverImage}
                            alt={portfolio.title}
                            className="h-full w-full object-cover transition-transform group-hover:scale-105"
                            loading="lazy"
                        />
                    ) : (
                        <div className="flex h-full items-center justify-center text-muted-foreground">
                            No Image
                        </div>
                    )}
                </div>
            </Link>

            <div className="flex flex-1 flex-col">
                <CardHeader className="p-4 pb-2">
                    <Link href={`${basePath}/${portfolio.id}`} className="hover:underline">
                        <h3 className="font-semibold text-lg line-clamp-1">{portfolio.title}</h3>
                    </Link>
                </CardHeader>

                <CardContent className="p-4 pt-0 flex flex-1 flex-col">
                    {portfolio.description && (
                        <p className="text-sm text-muted-foreground line-clamp-2 mb-3">
                            {portfolio.description}
                        </p>
                    )}

                    <div className="mt-auto space-y-3">
                        {portfolio.techStack && (
                            <div className="flex flex-wrap gap-1">
                                {portfolio.techStack.split(',').slice(0, 3).map((tech) => (
                                    <Badge key={tech} variant="secondary" className="text-xs">
                                        {tech.trim()}
                                    </Badge>
                                ))}
                                {portfolio.techStack.split(',').length > 3 && (
                                    <Badge variant="secondary" className="text-xs">+{portfolio.techStack.split(',').length - 3}</Badge>
                                )}
                            </div>
                        )}

                        <div className="flex items-center justify-between pt-2 border-t">
                            <div className="flex gap-2">
                                {demoLink && (
                                    <a
                                        href={demoLink.url}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="text-muted-foreground hover:text-primary transition-colors"
                                        title="Live Demo"
                                    >
                                        <Globe className="h-4 w-4" />
                                    </a>
                                )}
                                {githubLink && (
                                    <a
                                        href={githubLink.url}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="text-muted-foreground hover:text-primary transition-colors"
                                        title="GitHub Repository"
                                    >
                                        <Github className="h-4 w-4" />
                                    </a>
                                )}
                            </div>
                            <span className="text-xs text-muted-foreground">
                                {formatDate(portfolio.createdAt)}
                            </span>
                        </div>
                    </div>
                </CardContent>
            </div>
        </Card>
    );
}
