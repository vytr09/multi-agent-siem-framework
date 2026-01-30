"""
Web Report Crawler Tool
Crawl security reports from web pages and save as formatted Markdown.

Usage:
    python scripts/crawl_report.py <url> [--output-dir <dir>] [--filename <name>]

Examples:
    python scripts/crawl_report.py https://securelist.com/honeymyte-kernel-mode-rootkit/118590/
    python scripts/crawl_report.py https://securelist.com/honeymyte-kernel-mode-rootkit/118590/ --output-dir data/2025
    python scripts/crawl_report.py https://securelist.com/honeymyte-kernel-mode-rootkit/118590/ --filename honeymyte-rootkit
"""

import argparse
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
import html2text


def sanitize_filename(name: str) -> str:
    """Sanitize string to be used as filename."""
    # Remove invalid characters
    name = re.sub(r'[<>:"/\\|?*]', '', name)
    # Replace spaces with hyphens
    name = re.sub(r'\s+', '-', name)
    # Remove multiple hyphens
    name = re.sub(r'-+', '-', name)
    # Trim and lowercase
    return name.strip('-').lower()[:100]


def extract_article_content(soup: BeautifulSoup, url: str) -> dict:
    """
    Extract article content from various security report websites.
    Returns dict with title, author, date, and content.
    """
    result = {
        'title': '',
        'author': '',
        'date': '',
        'url': url,
        'content': ''
    }
    
    # Try to find title
    title_selectors = [
        'h1.entry-title',
        'h1.article-title', 
        'h1.post-title',
        'article h1',
        '.article-header h1',
        'h1'
    ]
    for selector in title_selectors:
        title_elem = soup.select_one(selector)
        if title_elem:
            result['title'] = title_elem.get_text(strip=True)
            break
    
    # Try to find author
    author_selectors = [
        '.author-name',
        '.entry-author',
        '.post-author',
        '[rel="author"]',
        '.byline a',
        '.author a'
    ]
    for selector in author_selectors:
        author_elem = soup.select_one(selector)
        if author_elem:
            result['author'] = author_elem.get_text(strip=True)
            break
    
    # Try to find date
    date_selectors = [
        'time[datetime]',
        '.entry-date',
        '.post-date',
        '.publish-date',
        '.article-date',
        '.date'
    ]
    for selector in date_selectors:
        date_elem = soup.select_one(selector)
        if date_elem:
            if date_elem.has_attr('datetime'):
                result['date'] = date_elem['datetime']
            else:
                result['date'] = date_elem.get_text(strip=True)
            break
    
    # Find main content
    content_selectors = [
        'article .entry-content',
        'article .post-content',
        'article .article-content',
        '.entry-content',
        '.post-content',
        '.article-body',
        'article',
        '.content',
        'main'
    ]
    
    content_elem = None
    for selector in content_selectors:
        content_elem = soup.select_one(selector)
        if content_elem:
            break
    
    if content_elem:
        # Remove unwanted elements
        for unwanted in content_elem.select('script, style, nav, footer, .sidebar, .comments, .related, .share, .social, .advertisement, .ad'):
            unwanted.decompose()
        
        result['content'] = content_elem
    
    return result


def html_to_markdown(html_content, base_url: str = '') -> str:
    """Convert HTML content to formatted Markdown."""
    h = html2text.HTML2Text()
    h.ignore_links = False
    h.ignore_images = False
    h.ignore_emphasis = False
    h.body_width = 0  # No wrapping
    h.unicode_snob = True
    h.skip_internal_links = True
    h.inline_links = True
    h.protect_links = True
    h.images_to_alt = False
    h.default_image_alt = "image"
    
    if base_url:
        h.baseurl = base_url
    
    if hasattr(html_content, 'prettify'):
        html_str = str(html_content)
    else:
        html_str = html_content
    
    markdown = h.handle(html_str)
    
    # Clean up excessive newlines
    markdown = re.sub(r'\n{3,}', '\n\n', markdown)
    
    return markdown.strip()


def crawl_report(url: str) -> str:
    """
    Crawl a web report and return formatted Markdown content.
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    }
    
    print(f"Fetching URL: {url}")
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Extract base URL for resolving relative links
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    # Extract article content
    article = extract_article_content(soup, url)
    
    # Convert content to markdown
    if article['content']:
        content_md = html_to_markdown(article['content'], base_url)
    else:
        # Fallback: convert entire body
        body = soup.find('body')
        if body:
            # Remove navigation, headers, footers
            for unwanted in body.select('script, style, nav, header, footer, .sidebar, .comments'):
                unwanted.decompose()
            content_md = html_to_markdown(body, base_url)
        else:
            content_md = html_to_markdown(str(soup), base_url)
    
    # Build final markdown document
    md_parts = []
    
    # Metadata header
    md_parts.append("---")
    md_parts.append(f"title: \"{article['title']}\"")
    if article['author']:
        md_parts.append(f"author: \"{article['author']}\"")
    if article['date']:
        md_parts.append(f"date: \"{article['date']}\"")
    md_parts.append(f"source: \"{url}\"")
    md_parts.append(f"crawled_at: \"{datetime.now().isoformat()}\"")
    md_parts.append("---")
    md_parts.append("")
    
    # Title
    if article['title']:
        md_parts.append(f"# {article['title']}")
        md_parts.append("")
    
    # Metadata section
    meta_info = []
    if article['author']:
        meta_info.append(f"**Author:** {article['author']}")
    if article['date']:
        meta_info.append(f"**Date:** {article['date']}")
    meta_info.append(f"**Source:** [{url}]({url})")
    
    if meta_info:
        md_parts.extend(meta_info)
        md_parts.append("")
        md_parts.append("---")
        md_parts.append("")
    
    # Content
    md_parts.append(content_md)
    
    return '\n'.join(md_parts)


def main():
    parser = argparse.ArgumentParser(
        description='Crawl security reports from web pages and save as Markdown',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/crawl_report.py https://securelist.com/honeymyte-kernel-mode-rootkit/118590/
  python scripts/crawl_report.py https://example.com/report --output-dir data/2025
  python scripts/crawl_report.py https://example.com/report --filename my-report
        """
    )
    parser.add_argument('url', help='URL of the report to crawl')
    parser.add_argument(
        '--output-dir', '-o',
        default='data/2025',
        help='Output directory (default: data/2025)'
    )
    parser.add_argument(
        '--filename', '-f',
        help='Output filename (without extension). If not specified, derived from URL/title'
    )
    
    args = parser.parse_args()
    
    try:
        # Crawl the report
        markdown_content = crawl_report(args.url)
        
        # Determine output filename
        if args.filename:
            filename = sanitize_filename(args.filename)
        else:
            # Try to extract from URL
            parsed = urlparse(args.url)
            path_parts = [p for p in parsed.path.split('/') if p]
            if path_parts:
                # Use last meaningful part of URL
                filename = sanitize_filename(path_parts[-1] if path_parts[-1] else path_parts[-2])
            else:
                filename = sanitize_filename(parsed.netloc)
        
        if not filename.endswith('.md'):
            filename = f"{filename}.md"
        
        # Ensure output directory exists
        # Handle relative paths from project root
        script_dir = Path(__file__).parent
        project_root = script_dir.parent
        
        if os.path.isabs(args.output_dir):
            output_dir = Path(args.output_dir)
        else:
            output_dir = project_root / args.output_dir
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Write to file
        output_path = output_dir / filename
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        print(f"\n✓ Report saved to: {output_path}")
        print(f"  File size: {output_path.stat().st_size:,} bytes")
        
    except requests.RequestException as e:
        print(f"Error fetching URL: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
