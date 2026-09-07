# Command Centre artwork

`AppIcon.svg` uses the SafeYolo rails-and-switch artwork published at:

<https://safeyolo.com/assets/images/image02.svg>

and the square composition published at:

<https://safeyolo.com/assets/images/apple-touch-icon.png>

The published SVG's SHA-256 when inspected was:

`f488e0449d0a37cdd9f13a5339760bbd86c393c631d290603a6dcffff6df1823`

The local vector preserves the published motif and `#373737` / `#FCE139`
colors, using a square 1024×1024 canvas and safe margin so macOS, rather than
the artwork, can apply the platform's current icon mask. The canvas is
genuinely transparent; the site's Apple touch PNG contains a baked checkerboard
and is therefore a visual reference rather than the bundled source.

`build-app.sh` uses the macOS system image tools to render the vector at each
standard size and create the standard icon
representations and package them as `AppIcon.icns`; generated files remain
under `.build`.

`MenuBarTemplate.svg` is the monochrome form of the same rails-and-switch mark.
The build creates 18-point and Retina representations. The native menu-bar
label uses template rendering so macOS supplies the light/dark appearance.
The separate attention mark retains pending-approval and security-event state;
the logo does not replace those signals.
