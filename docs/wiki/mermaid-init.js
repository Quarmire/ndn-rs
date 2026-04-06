// Load mermaid from CDN and render diagrams.
// mdbook-mermaid preprocessor converts ```mermaid blocks into
// <pre><code class="language-mermaid">...</code></pre>.
(function () {
    var script = document.createElement('script');
    script.src = 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js';
    script.onload = function () {
        // Collect all mermaid code blocks and convert them for rendering.
        var blocks = document.querySelectorAll('code.language-mermaid');
        blocks.forEach(function (block) {
            var pre = block.parentElement;
            var div = document.createElement('div');
            div.className = 'mermaid';
            div.textContent = block.textContent;
            pre.parentElement.replaceChild(div, pre);
        });
        mermaid.initialize({ startOnLoad: true, theme: 'default' });
    };
    document.head.appendChild(script);
})();
