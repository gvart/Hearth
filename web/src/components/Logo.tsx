/** The Hearth mark: the flame on an ember tile. Its colours come from the theme (.logo in styles/blueprint.css). */
export function Logo({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" className="logo">
      <rect width="32" height="32" />
      <path
        transform="translate(5.6 6.2) scale(0.65)"
        d="M16 3c3 5 9 8 9 15a9 9 0 0 1-18 0c0-4 2-7 4-9 0 3 1 5 3 6-1-5 0-9 2-12z"
      />
    </svg>
  );
}
