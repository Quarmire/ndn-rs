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
                    mermaid.initialize({
                        startOnLoad: true,
                        theme: 'default',
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
