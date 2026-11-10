const test = require('node:test');
const assert = require('node:assert/strict');
const {sourceCoverage} = require('./helpers/globe-coverage.cjs');

test('bundle mapping retains zero-hit nested functions and rebases UTF-16 offsets exactly', () => {
  const source = 'function globe() { unused(); }';
  const prefix = '// vendor 🌎\n';
  const text = prefix + source + '\n// trailing vendor';
  const entry = {source: text, functions: [
    {functionName: '', isBlockCoverage: true, ranges: [{startOffset: 0, endOffset: text.length, count: 1}]},
    {functionName: 'vendor', isBlockCoverage: false, ranges: [{startOffset: 0, endOffset: 4, count: 40}]},
    {functionName: 'globe', isBlockCoverage: false, ranges: [{startOffset: prefix.length, endOffset: prefix.length + source.length, count: 0}]}
  ]};
  assert.deepEqual(sourceCoverage(entry, source), [
    {functionName: '', isBlockCoverage: true, ranges: [{startOffset: 0, endOffset: source.length, count: 1}]},
    {functionName: 'globe', isBlockCoverage: false, ranges: [{startOffset: 0, endOffset: source.length, count: 0}]}
  ]);
});

test('bundle mapping rejects stale or ambiguous editable sources', () => {
  assert.throws(() => sourceCoverage({source: 'old source', functions: []}, 'new source'), /exact editable/);
  assert.throws(() => sourceCoverage({source: 'source source', functions: []}, 'source'), /occurs once/);
});
