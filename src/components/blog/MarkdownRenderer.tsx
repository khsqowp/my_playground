"use client";

import React from "react";

interface MarkdownRendererProps {
  content: string;
  className?: string;
}

// Simple markdown renderer with basic syntax support
export function MarkdownRenderer({ content, className = "" }: MarkdownRendererProps) {
  const renderMarkdown = (text: string) => {
    if (!text) return "";

    let html = text;

    // Code blocks (```)
    html = html.replace(/```(\w+)?\n([\s\S]*?)```/g, (_, lang, code) => {
      return `<pre><code class="language-${lang || "plaintext"}">${escapeHtml(code.trim())}</code></pre>`;
    });

    // Inline code
    html = html.replace(/`([^`]+)`/g, "<code>$1</code>");

    // Headers
    html = html.replace(/^### (.*$)/gim, "<h3>$1</h3>");
    html = html.replace(/^## (.*$)/gim, "<h2>$1</h2>");
    html = html.replace(/^# (.*$)/gim, "<h1>$1</h1>");

    // Bold
    html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    html = html.replace(/__([^_]+)__/g, "<strong>$1</strong>");

    // Italic
    html = html.replace(/\*([^*]+)\*/g, "<em>$1</em>");
    html = html.replace(/_([^_]+)_/g, "<em>$1</em>");

    // Links
    html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');

    // Images
    html = html.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '<img src="$2" alt="$1" />');

    // Lists (unordered)
    html = html.replace(/^\* (.+)$/gim, "<li>$1</li>");
    html = html.replace(/^- (.+)$/gim, "<li>$1</li>");
    html = html.replace(/(<li>[\s\S]*?<\/li>)/, "<ul>$1</ul>");

    // Lists (ordered)
    html = html.replace(/^\d+\. (.+)$/gim, "<li>$1</li>");

    // Blockquotes
    html = html.replace(/^> (.+)$/gim, "<blockquote>$1</blockquote>");

    // Horizontal rules
    html = html.replace(/^---$/gim, "<hr />");
    html = html.replace(/^\*\*\*$/gim, "<hr />");

    // Line breaks
    html = html.replace(/\n/g, "<br />");

    return html;
  };

  const escapeHtml = (text: string) => {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
  };

  return (
    <div
      className={`prose prose-slate dark:prose-invert max-w-none ${className}`}
      dangerouslySetInnerHTML={{ __html: renderMarkdown(content) }}
      style={{
        lineHeight: "1.8",
      }}
    />
  );
}

export default MarkdownRenderer;
