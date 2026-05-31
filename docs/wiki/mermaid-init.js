// Load ELK layout engine, then Mermaid.
// ELK must be present on window before Mermaid initialises so that diagrams
// annotated with %%{init: {"layout": "elk"}}%% can use it.
(function () {
    function loadScript(src, cb) {
        var s = document.createElement('script');
        s.src = src;
        s.onload = cb;
        document.head.appendChild(s);
    }

    loadScript(
        'https://cdn.jsdelivr.net/npm/elkjs@0.9/lib/elk.bundled.js',
        function () {
            loadScript(
                'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js',
                function () {
                    var blocks = document.querySelectorAll('code.language-mermaid');
                    blocks.forEach(function (block) {
                        var pre = block.parentElement;
                        var div = document.createElement('div');
                        div.className = 'mermaid';
                        div.textContent = block.textContent;
                        pre.parentElement.replaceChild(div, pre);
                    });
                    // Carbon palette — pick dark/light from the active
                    // mdBook theme class so diagrams match the dashboard
                    // tokens (crates/tooling/ndn-dashboard/src/styles.rs).
                    var cls = document.documentElement.className;
                    var dark = /\b(navy|coal)\b/.test(cls);
                    var c = dark
                        ? { bg: '#262626', bg2: '#393939', border: '#525252',
                            text: '#f4f4f4', line: '#78a9ff', accent: '#001d6c' }
                        : { bg: '#f4f4f4', bg2: '#e0e0e0', border: '#c6c6c6',
                            text: '#161616', line: '#0f62fe', accent: '#d0e2ff' };
                    mermaid.initialize({
                        startOnLoad: true,
                        theme: 'base',
                        themeVariables: {
                            fontFamily: "'IBM Plex Sans', system-ui, sans-serif",
                            primaryColor: c.bg,
                            primaryTextColor: c.text,
                            primaryBorderColor: c.border,
                            secondaryColor: c.bg2,
                            tertiaryColor: c.accent,
                            lineColor: c.line,
                            textColor: c.text,
                            background: 'transparent',
                        },
                        // ELK is available globally; diagrams opt-in with
                        // %%{init: {"layout": "elk"}}%% on their first line.
                        flowchart: { htmlLabels: true },
                        er:        { diagramPadding: 20 },
                    });
                }
            );
        }
    );
})();
