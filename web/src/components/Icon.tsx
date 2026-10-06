import type { ReactNode } from "react";

// One set of line icons, drawn here as inline SVG so there is nothing to download and no
// glyph that depends on a font or on how a file was saved. Every icon uses the same stroke.
export const ICON_STROKE = 1.75;

const PATHS: Record<string, ReactNode> = {
  arrow: <path d="M5 12h14M13 6l6 6-6 6" />,
  "arrow-up": <path d="M12 19V5M5 12l7-7 7 7" />,
  "arrow-down": <path d="M12 5v14M19 12l-7 7-7-7" />,
  chevron: <path d="M6 9l6 6 6-6" />,
  check: <path d="M4 12.5l6 6L20 6" />,
  copy: (
    <>
      <rect x="9" y="9" width="12" height="12" rx="2" />
      <path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1" />
    </>
  ),
  bucket: (
    <>
      <ellipse cx="12" cy="5.5" rx="8" ry="2.5" />
      <path d="M4 5.5v13c0 1.4 3.6 2.5 8 2.5s8-1.1 8-2.5v-13" />
      <path d="M4 12c0 1.4 3.6 2.5 8 2.5s8-1.1 8-2.5" />
    </>
  ),
  shield: <path d="M12 3l8 3v6c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V6l8-3z" />,
  server: (
    <>
      <rect x="3" y="4" width="18" height="7" rx="2" />
      <rect x="3" y="13" width="18" height="7" rx="2" />
      <path d="M7 7.5h.01M7 16.5h.01" />
    </>
  ),
  policy: (
    <>
      <path d="M6 3h8l4 4v14H6V3z" />
      <path d="M14 3v4h4M9 12h6M9 16h6" />
    </>
  ),
  key: (
    <>
      <circle cx="8" cy="15" r="4" />
      <path d="M11 12l9-9M16 7l3 3" />
    </>
  ),
  box: (
    <>
      <path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z" />
      <path d="M4 7.5l8 4.5 8-4.5M12 12v9" />
    </>
  ),
};

export type IconName = keyof typeof PATHS;

export function Icon({
  name,
  size = 20,
  className = "",
}: {
  name: IconName;
  size?: number;
  className?: string;
}) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeWidth={ICON_STROKE}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      className={className}
      data-icon={name}
    >
      {PATHS[name]}
    </svg>
  );
}

const TYPE_ICONS: Record<string, IconName> = {
  S3: "bucket",
  "Security Group": "shield",
  EC2: "server",
  "IAM Policy": "policy",
  "IAM Role": "key",
};

export function iconForResource(resourceType: string): IconName {
  return TYPE_ICONS[resourceType] ?? "box";
}
