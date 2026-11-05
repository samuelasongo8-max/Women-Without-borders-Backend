export function convertGoogleDriveUrl(url) {
  if (!url) return url
  const trimmed = String(url).trim()
  if (!trimmed.includes('drive.google.com')) return trimmed
  const match =
    trimmed.match(/\/file\/d\/([a-zA-Z0-9_-]+)/) ||
    trimmed.match(/[?&]id=([a-zA-Z0-9_-]+)/)
  if (!match) return trimmed
  return `https://drive.google.com/thumbnail?id=${match[1]}&sz=w1200`
}
