// Shared Google Drive URL converter used by frontend and backend.
// Extracts the file ID from every Drive share format and converts to a
// reliable thumbnail URL. Non-Drive URLs pass through unchanged.

const DRIVE_ID_PATTERNS = [
  // https://drive.google.com/file/d/ID/view
  // https://drive.google.com/file/d/ID/edit
  // https://drive.google.com/file/d/ID
  /\/file\/d\/([a-zA-Z0-9_-]+)/,
  // https://drive.google.com/open?id=ID
  // https://drive.google.com/uc?id=ID
  // https://drive.google.com/uc?export=view&id=ID
  // https://drive.google.com/uc?export=download&id=ID
  /[?&]id=([a-zA-Z0-9_-]+)/,
]

export function extractDriveFileId(url) {
  if (!url) return null
  const trimmed = String(url).trim()
  if (!trimmed.includes('drive.google.com')) return null
  for (const pattern of DRIVE_ID_PATTERNS) {
    const match = trimmed.match(pattern)
    if (match) return match[1]
  }
  return null
}

export function convertGoogleDriveUrl(url) {
  if (!url) return url
  const trimmed = String(url).trim()
  if (!trimmed.includes('drive.google.com')) return trimmed
  const fileId = extractDriveFileId(trimmed)
  if (!fileId) return trimmed
  return `https://drive.google.com/thumbnail?id=${fileId}&sz=w1600`
}

export default { convertGoogleDriveUrl, extractDriveFileId }
