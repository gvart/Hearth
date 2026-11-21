// Where the docs live, for the links the UI makes to them.

/** The link to a page of the docs, by its file name under docs/. */
export function docsURL(page: string): string {
  return `https://github.com/gvart/hearth/blob/main/docs/${page}`;
}
