/**
 * Downloads files from Google Drive in the browser, for importing them into encrypted documents
 * (the server mustn't see their content: it only turns the user's authorization into an access
 * token, see EncryptionRelay.getGoogleDriveToken()). Google Sheets are downloaded as Excel files.
 */
const DRIVE_API = "https://www.googleapis.com/drive/v3/files";
const SPREADSHEETS_MIMETYPE = "application/vnd.google-apps.spreadsheet";
const XLSX_MIMETYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

/** The id of a Google Drive file, from its URL (null if it isn't one). */
export function driveFileIdFromUrl(url: string): string | null {
  const match = /^https:\/\/(docs|drive)\.google\.com\/(spreadsheets|file)\/d\/([^/?#]+)/i.exec(url.trim());
  return match ? match[3] : null;
}

export async function downloadFromDrive(fileId: string,
  accessToken: string): Promise<{ name: string, data: Uint8Array }> {
  const headers = { Authorization: `Bearer ${accessToken}` };
  const id = encodeURIComponent(fileId);
  const meta = await fetchOk(`${DRIVE_API}/${id}?fields=name,mimeType&supportsAllDrives=true`, headers);
  const { name, mimeType } = await meta.json() as { name: string, mimeType: string };
  if (mimeType === SPREADSHEETS_MIMETYPE) {
    const response = await fetchOk(`${DRIVE_API}/${id}/export?mimeType=${encodeURIComponent(XLSX_MIMETYPE)}`, headers);
    return { name: name.includes(".") ? name : `${name}.xlsx`, data: new Uint8Array(await response.arrayBuffer()) };
  }
  const response = await fetchOk(`${DRIVE_API}/${id}?alt=media&supportsAllDrives=true`, headers);
  return { name, data: new Uint8Array(await response.arrayBuffer()) };
}

async function fetchOk(url: string, headers: Record<string, string>): Promise<Response> {
  const response = await fetch(url, { headers });
  if (response.status === 404 || response.status === 403) {
    throw new Error("Google Drive didn't let Grist read this file: check that you can open it, and that " +
      "Grist is allowed to read it");
  }
  if (!response.ok) { throw new Error(`Google Drive returned an error (${response.status})`); }
  return response;
}
