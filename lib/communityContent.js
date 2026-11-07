import sanitizeHtml from 'sanitize-html'

const COMMUNITY_CONTENT_SANITIZE_OPTIONS = {
  allowedTags: [
    'p', 'br', 'strong', 'b', 'em', 'i', 'u',
    'h1', 'h2', 'h3', 'ul', 'ol', 'li', 'span',
  ],
  allowedAttributes: {
    p: ['class'],
    ul: ['style'],
    ol: ['style'],
    span: ['style'],
  },
  allowedStyles: {
    '*': {
      color: [/^#[0-9a-fA-F]{3,8}$/, /^rgb\([\d\s,]+\)$/],
      'font-size': [/^\d{1,2}px$/],
      'list-style-type': [
        /^(disc|circle|square|decimal|lower-alpha|upper-alpha|lower-roman|upper-roman)$/,
      ],
    },
  },
  allowedClasses: {
    p: ['no-spacing'],
  },
}

export function sanitizeCommunityContent(value) {
  return sanitizeHtml(String(value || ''), COMMUNITY_CONTENT_SANITIZE_OPTIONS)
}

export function hasCommunityContent(value) {
  return sanitizeHtml(String(value || ''), { allowedTags: [], allowedAttributes: {} })
    .replace(/&nbsp;/gi, ' ')
    .trim().length > 0
}

export function communityContentExcerpt(value, maxLength = 120) {
  const textOnly = sanitizeHtml(
    String(value || '').replace(/<\/(?:p|h[1-6]|li)>|<br\s*\/?\s*>/gi, ' '),
    { allowedTags: [], allowedAttributes: {} },
  )
  return textOnly
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#(?:39|x27);/gi, "'")
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength)
}
