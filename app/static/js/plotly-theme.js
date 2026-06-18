(function () {
  function css(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
  function relayoutPlots() {
    if (!window.Plotly) return;
    const dark = document.documentElement.getAttribute('data-theme') === 'dark';
    const text = css('--plot-text') || (dark ? '#dbeafe' : '#334155');
    const grid = css('--plot-grid') || (dark ? '#2a3b55' : '#e5edf5');
    const paper = 'rgba(0,0,0,0)';
    document.querySelectorAll('.js-plotly-plot').forEach(function (plot) {
      try {
        window.Plotly.relayout(plot, {
          paper_bgcolor: paper,
          plot_bgcolor: paper,
          font: { color: text, family: 'Inter, Arial, sans-serif' },
          'xaxis.color': text,
          'yaxis.color': text,
          'xaxis.gridcolor': grid,
          'yaxis.gridcolor': grid,
          'legend.font.color': text
        });
        window.Plotly.Plots.resize(plot);
      } catch (e) {}
    });
  }
  window.addEventListener('load', function () { setTimeout(relayoutPlots, 350); });
  window.addEventListener('resize', function () { clearTimeout(window.__plotlyThemeResize); window.__plotlyThemeResize = setTimeout(relayoutPlots, 150); });
  const observer = new MutationObserver(function (mutations) {
    for (const m of mutations) {
      if (m.attributeName === 'data-theme') setTimeout(relayoutPlots, 80);
    }
  });
  observer.observe(document.documentElement, { attributes: true });
})();
