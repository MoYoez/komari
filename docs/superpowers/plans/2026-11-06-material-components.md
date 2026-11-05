# Material components and reachable consent actions

The user requested a component library and reported that the consent page cannot scroll. Live inspection found a 1103px document in an 827px viewport; wheel and keyboard scrolling left scrollTop at zero and the approval button below the viewport at y=906. The existing controls are native inputs with custom CSS.

- Replace visible controls with MDUI 2.1.5: checkboxes, segmented buttons, text fields, buttons and collapsible connection details. Import only these components and bundle them locally with esbuild. The server serves static JS/CSS; no new service or frontend runtime is added to the server.
- Use a viewport-sized shell with an explicit scrollable form-content region and a separate action footer. On desktop, place application/purpose information beside the permission form; stack on narrow screens. Approval/cancel actions remain reachable without scrolling the whole document.
- Preserve the existing OAuth POST names, scopes, host selections, duration choices and user-only approval. Build form submission through MDUI's documented form controls. Query and PTY credentials are unaffected.
- Back up the live plugin before installing the built assets and reloading it. Inspect real desktop and narrow-screen rendering, actual wheel/keyboard scrolling, component selection and form serialization without granting OAuth. Use syntax/build checks and manual browser verification; do not add tests or checksums.
