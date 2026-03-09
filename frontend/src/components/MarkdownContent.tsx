import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { cn } from '@/utils/cn';

interface Props {
  content: string;
  className?: string;
  size?: 'sm' | 'xs';
}

export function MarkdownContent({ content, className, size = 'sm' }: Props) {
  return (
    <div className={cn(
      'prose dark:prose-invert max-w-none',
      size === 'xs'
        ? 'prose-xs [&_p]:mb-1.5 [&_ul]:mb-1.5 [&_ol]:mb-1.5 [&_li]:mb-0.5 [&_h1]:text-sm [&_h2]:text-xs [&_h3]:text-xs text-xs leading-relaxed'
        : 'prose-sm [&_p]:mb-2 [&_ul]:mb-2 [&_ol]:mb-2 [&_li]:mb-0.5 [&_h1]:text-base [&_h2]:text-sm [&_h3]:text-sm text-sm leading-relaxed',
      className,
    )}>
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        code({ className: codeClass, children, ...rest }) {
          const isInline = !codeClass;
          if (isInline) {
            return (
              <code className={cn('text-[0.85em] bg-muted px-1.5 py-0.5 rounded font-mono', codeClass)} {...rest}>
                {children}
              </code>
            );
          }
          const lang = codeClass?.replace('language-', '') || '';
          return (
            <div className="relative group my-2">
              {lang && (
                <div className="absolute top-0 right-0 px-2 py-0.5 text-[9px] text-muted-foreground bg-muted/80 rounded-bl rounded-tr font-mono">
                  {lang}
                </div>
              )}
              <pre className="bg-[#1a1a2e] border border-border/50 rounded-lg p-3 overflow-x-auto">
                <code className={cn('font-mono text-[0.85em] leading-relaxed', codeClass)} {...rest}>
                  {children}
                </code>
              </pre>
            </div>
          );
        },
        table({ children }) {
          return (
            <div className="overflow-x-auto my-2">
              <table className="text-xs border-collapse w-full">{children}</table>
            </div>
          );
        },
        th({ children }) {
          return <th className="border border-border/50 bg-muted/30 px-2 py-1 text-left font-semibold">{children}</th>;
        },
        td({ children }) {
          return <td className="border border-border/50 px-2 py-1">{children}</td>;
        },
        a({ href, children }) {
          return <a href={href} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">{children}</a>;
        },
        blockquote({ children }) {
          return <blockquote className="border-l-2 border-primary/50 pl-3 italic text-muted-foreground my-2">{children}</blockquote>;
        },
      }}
    >
      {content}
    </ReactMarkdown>
    </div>
  );
}
