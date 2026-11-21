import { useMemo } from 'react';
import { encode } from 'uqr';

/** A QR code drawn as one SVG path, dark on light whatever the theme. */
export function QrCode({ value, label }: { value: string; label: string }) {
  const { size, path } = useMemo(() => {
    const qr = encode(value, { border: 2, ecc: 'L' });
    let d = '';
    qr.data.forEach((row, y) => {
      row.forEach((on, x) => {
        if (on) {
          d += `M${String(x)} ${String(y)}h1v1h-1z`;
        }
      });
    });
    return { size: qr.size, path: d };
  }, [value]);

  return (
    <svg className="qr" viewBox={`0 0 ${String(size)} ${String(size)}`} role="img" aria-label={label} shapeRendering="crispEdges">
      {/* Black on white whatever the theme: a scanner needs the contrast. */}
      <rect width={size} height={size} fill="#fff" />
      <path d={path} fill="#000" />
    </svg>
  );
}
