// 5×5 mirrored identicon derived from SHA-256 of a public key (GitHub-style). Doubles as an avatar
// and as a visual check: a server that substitutes someone's key produces a different pattern.

import { b64, sha256 } from '@keyvault/crypto';
import { useMemo } from 'react';

interface Props {
  publicKey?: string;
  seed?: string;
  size?: number;
  title?: string;
  className?: string;
}

function digest(publicKey?: string, seed?: string): Uint8Array {
  if (publicKey) {
    try {
      return sha256(b64.decode(publicKey));
    } catch {
      /* fall through */
    }
  }
  return sha256(new TextEncoder().encode(seed ?? 'keyvault'));
}

export function Identicon({ publicKey, seed, size = 28, title, className }: Props) {
  const { cells, color } = useMemo(() => {
    const h = digest(publicKey, seed);
    const hue = Math.round((((h[0]! << 8) | h[1]!) / 65535) * 360);
    const cells: [number, number][] = [];
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 3; x++) {
        if ((h[2 + y * 3 + x]! & 1) === 1) {
          cells.push([x, y]);
          if (x < 2) cells.push([4 - x, y]);
        }
      }
    }
    return { cells, color: `hsl(${hue} 62% 56%)` };
  }, [publicKey, seed]);

  return (
    <svg className={`identicon ${className ?? ''}`} width={size} height={size} viewBox="0 0 7 7" shapeRendering="crispEdges"
      role={title ? 'img' : undefined} aria-label={title} aria-hidden={title ? undefined : true}>
      {title && <title>{title}</title>}
      <rect width="7" height="7" className="identicon-bg" />
      {cells.map(([x, y]) => <rect key={`${x}-${y}`} x={x + 1} y={y + 1} width="1" height="1" fill={color} />)}
    </svg>
  );
}
