const assert = require('node:assert/strict');

// Chromium measures the shipped concatenated bundle. Keep every V8 function
// and block range intersecting the exact editable source, including zero-hit
// nested functions. Istanbul, rather than this mapper, interprets line hits.
function sourceCoverage(entry, source) {
  assert.equal(typeof entry.source, 'string', 'Chromium returned bundle source');
  const start = entry.source.indexOf(source);
  assert.ok(source.length && start >= 0, 'bundle contains the exact editable globe source');
  assert.equal(entry.source.lastIndexOf(source), start, 'editable globe source occurs once');
  const end = start + source.length;
  const functions = entry.functions.flatMap(fn => {
    const ranges = fn.ranges.filter(range => range.startOffset < end && range.endOffset > start)
      .map(range => ({startOffset: Math.max(range.startOffset, start) - start,
        endOffset: Math.min(range.endOffset, end) - start, count: range.count}));
    return ranges.length ? [{...fn, ranges}] : [];
  });
  assert.ok(functions.length, 'Chromium measured the editable source');
  return functions;
}

module.exports = {sourceCoverage};
