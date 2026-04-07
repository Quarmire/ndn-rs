// D3 interactive layered-graph renderer for ```d3graph``` code blocks.
//
// Block format (JSON):
// {
//   "columns": [
//     { "label": "Foundation", "nodes": [{"id": "ndn-tlv"}, ...] },
//     ...
//   ],
//   "satellites": {                       // optional bottom row
//     "label": "Research",
//     "nodes": [{"id": "ndn-sim"}, ...]
//   },
//   "edges": [["src", "dst"], ...],       // main forward edges
//   "satellite_edges": [["src","dst"],...]// dashed; connect satellites to columns
// }
//
// Rendered as an SVG with zoom/pan via d3-zoom.
(function () {
    function loadScript(src, cb) {
        var s = document.createElement('script');
        s.src = src;
        s.onload = cb;
        document.head.appendChild(s);
    }

    loadScript('https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js', function () {
        document.querySelectorAll('code.language-d3graph').forEach(renderBlock);
    });

    // ── theme ──────────────────────────────────────────────────────────────
    function palette() {
        var stored = localStorage.getItem('mdbook-theme') || '';
        var cls    = document.documentElement.className || '';
        var dark   = /navy|coal|ayu/.test(stored + cls);
        return dark ? {
            bg:          '#1a2332',
            colBg:       '#243447',
            colText:     '#94a3b8',
            nodeFill:    '#1e3a5f',
            nodeStroke:  '#3b82f6',
            nodeText:    '#93c5fd',
            satFill:     '#2d1b4e',
            satStroke:   '#7c3aed',
            satText:     '#c4b5fd',
            satBg:       '#1e1340',
            satLabel:    '#94a3b8',
            edge:        '#475569',
            edgeDash:    '#6366f1',
            border:      '#334155',
        } : {
            bg:          '#ffffff',
            colBg:       '#f1f5f9',
            colText:     '#475569',
            nodeFill:    '#dbeafe',
            nodeStroke:  '#2563eb',
            nodeText:    '#1e3a5f',
            satFill:     '#ede9fe',
            satStroke:   '#7c3aed',
            satText:     '#4c1d95',
            satBg:       '#f5f3ff',
            satLabel:    '#6b7280',
            edge:        '#94a3b8',
            edgeDash:    '#818cf8',
            border:      '#e2e8f0',
        };
    }

    // ── main render ────────────────────────────────────────────────────────
    function renderBlock(block) {
        var pre = block.parentElement;
        var data;
        try { data = JSON.parse(block.textContent); }
        catch (e) { console.error('d3graph parse error:', e); return; }

        var c      = palette();
        var cols   = data.columns   || [];
        var sats   = data.satellites;
        var edges  = data.edges          || [];
        var sEdges = data.satellite_edges || [];

        // ── geometry ───────────────────────────────────────────────────────
        var W       = 940;
        var pad     = 14;
        var colW    = (W - 2 * pad) / cols.length;
        var nodeW   = Math.min(colW - 20, 138);
        var nodeH   = 30;
        var hdrH    = 22;        // column label height
        var rowGap  = 10;

        var maxNodes = Math.max.apply(null, cols.map(function (c) { return c.nodes.length; }));
        var mainH    = hdrH + maxNodes * (nodeH + rowGap) + rowGap + 8;

        var satNodes = sats ? sats.nodes.length : 0;
        var satH     = sats ? hdrH + nodeH + 24 : 0;
        var H        = mainH + (sats ? satH + 16 : 0) + 8;

        // ── position map ───────────────────────────────────────────────────
        var pos = {};

        cols.forEach(function (col, ci) {
            var cx = pad + ci * colW + colW / 2;
            col.nodes.forEach(function (n, ni) {
                pos[n.id] = {
                    x: cx,
                    y: hdrH + rowGap + ni * (nodeH + rowGap) + nodeH / 2 + 4,
                    sat: false,
                };
            });
        });

        if (sats) {
            var satY0 = mainH + 16;
            var perCell = (W - 2 * pad) / satNodes;
            sats.nodes.forEach(function (n, ni) {
                pos[n.id] = {
                    x: pad + (ni + 0.5) * perCell,
                    y: satY0 + hdrH + nodeH / 2 + 4,
                    sat: true,
                };
            });
        }

        // ── build SVG ──────────────────────────────────────────────────────
        var wrap = document.createElement('div');
        wrap.style.cssText = 'overflow:hidden;border-radius:8px;border:1px solid ' +
                             c.border + ';margin:1.2em 0;';

        var svgEl = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        var svg = d3.select(svgEl)
            .attr('viewBox', '0 0 ' + W + ' ' + H)
            .attr('style', 'width:100%;height:auto;display:block;background:' + c.bg);

        // zoom/pan group
        var root = svg.append('g');
        svg.call(
            d3.zoom().scaleExtent([0.3, 5]).on('zoom', function (ev) {
                root.attr('transform', ev.transform);
            })
        );

        // hint
        svg.append('text')
            .attr('x', W - 6).attr('y', H - 4)
            .attr('text-anchor', 'end')
            .attr('font-size', '9px')
            .attr('font-family', 'sans-serif')
            .attr('fill', c.colText)
            .attr('opacity', 0.5)
            .text('scroll/pinch to zoom · drag to pan');

        // ── column backgrounds + labels ────────────────────────────────────
        cols.forEach(function (col, ci) {
            var x = pad + ci * colW;
            root.append('rect')
                .attr('x', x + 3).attr('y', 2)
                .attr('width', colW - 6).attr('height', mainH - 2)
                .attr('rx', 6).attr('fill', c.colBg).attr('opacity', 0.55);
            root.append('text')
                .attr('x', x + colW / 2).attr('y', 14)
                .attr('text-anchor', 'middle')
                .attr('font-size', '10px').attr('font-weight', 'bold')
                .attr('font-family', 'sans-serif')
                .attr('fill', c.colText)
                .text(col.label);
        });

        // ── satellite row background + label ──────────────────────────────
        if (sats) {
            var sy = mainH + 8;
            root.append('rect')
                .attr('x', pad).attr('y', sy)
                .attr('width', W - 2 * pad).attr('height', satH)
                .attr('rx', 6).attr('fill', c.satBg).attr('opacity', 0.55);
            root.append('text')
                .attr('x', W / 2).attr('y', sy + 14)
                .attr('text-anchor', 'middle')
                .attr('font-size', '10px').attr('font-weight', 'bold')
                .attr('font-family', 'sans-serif')
                .attr('fill', c.satLabel)
                .text(sats.label);
        }

        // ── arrowhead markers ──────────────────────────────────────────────
        var defs = svg.append('defs');
        function arrowMarker(id, color) {
            defs.append('marker')
                .attr('id', id)
                .attr('viewBox', '0 -4 8 8')
                .attr('refX', 7).attr('refY', 0)
                .attr('markerWidth', 5).attr('markerHeight', 5)
                .attr('orient', 'auto')
                .append('path').attr('d', 'M0,-4L8,0L0,4Z').attr('fill', color);
        }
        arrowMarker('arr',     c.edge);
        arrowMarker('arrDash', c.edgeDash);

        // ── edge drawing ───────────────────────────────────────────────────
        function drawEdge(srcId, tgtId, dashed) {
            var s = pos[srcId], t = pos[tgtId];
            if (!s || !t) return;
            // offset to right/left edge of node
            var sx = s.x + nodeW / 2;
            var tx = t.x - nodeW / 2;
            var mx = (sx + tx) / 2;
            // vertical offset when source and target are in same column
            var path = 'M' + sx + ',' + s.y +
                       'C' + mx + ',' + s.y + ',' + mx + ',' + t.y +
                       ',' + tx + ',' + t.y;
            root.append('path').attr('d', path)
                .attr('fill', 'none')
                .attr('stroke', dashed ? c.edgeDash : c.edge)
                .attr('stroke-width', dashed ? 1.2 : 1.5)
                .attr('stroke-dasharray', dashed ? '5,3' : null)
                .attr('opacity', 0.75)
                .attr('marker-end', 'url(#' + (dashed ? 'arrDash' : 'arr') + ')');
        }

        edges.forEach(function (e)  { drawEdge(e[0], e[1], false); });
        sEdges.forEach(function (e) { drawEdge(e[0], e[1], true);  });

        // ── node drawing ───────────────────────────────────────────────────
        function drawNode(id) {
            var p = pos[id];
            if (!p) return;
            var fill   = p.sat ? c.satFill   : c.nodeFill;
            var stroke = p.sat ? c.satStroke : c.nodeStroke;
            var text   = p.sat ? c.satText   : c.nodeText;
            var ng = root.append('g')
                .attr('transform', 'translate(' + p.x + ',' + p.y + ')');
            ng.append('rect')
                .attr('x', -nodeW / 2).attr('y', -nodeH / 2)
                .attr('width', nodeW).attr('height', nodeH)
                .attr('rx', 5)
                .attr('fill', fill).attr('stroke', stroke).attr('stroke-width', 1.5);
            ng.append('text')
                .attr('text-anchor', 'middle').attr('dy', '0.35em')
                .attr('fill', text).attr('font-size', '10.5px')
                .attr('font-family', 'monospace')
                .text(id);
        }

        cols.forEach(function (col) { col.nodes.forEach(function (n) { drawNode(n.id); }); });
        if (sats) { sats.nodes.forEach(function (n) { drawNode(n.id); }); }

        wrap.appendChild(svgEl);
        pre.parentElement.replaceChild(wrap, pre);
    }
})();
