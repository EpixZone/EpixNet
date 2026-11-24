const assert = require('node:assert/strict');
const path = require('node:path');
const {test} = require('node:test');
const {chromium} = require('../../../ui/tests/coverage-tools/node_modules/playwright');

async function sampleChange(button, hidden) {
    return button.evaluate((element, hidden) => {
        if (hidden) document.documentElement.setAttribute('data-epix-native-chrome-hidden', 'true');
        else document.documentElement.removeAttribute('data-epix-native-chrome-hidden');

        const style = getComputedStyle(element);
        const read = () => ({
            opacity: Number(style.opacity), visibility: style.visibility, pointerEvents: style.pointerEvents,
        });
        const transitions = element.getAnimations();
        const fade = transitions.find(animation => animation.transitionProperty === 'opacity');
        const duration = fade?.effect.getTiming().duration ?? 0;
        // Seek all transitions on the same clock, including visibility during fade-out.
        for (const animation of transitions) {
            animation.pause();
            animation.currentTime = duration / 2;
        }
        const middle = read();
        for (const animation of transitions) animation.finish();
        return {duration, middle, end: read()};
    }, hidden);
}

test('scroll fades the fixbutton in both directions and respects reduced motion and focus', async t => {
    const browser = await chromium.launch();
    t.after(() => browser.close());
    const page = await browser.newPage({reducedMotion: 'no-preference'});
    await page.setContent('<div id="wrapper-controls"><div class="fixbutton"><a href="#">Home</a></div></div>');
    await page.addStyleTag({path: path.join(__dirname, '../app/src/main/assets/browser-controls/scroll.css')});
    const button = page.locator('.fixbutton');
    const shown = {opacity: 1, visibility: 'visible', pointerEvents: 'auto'};
    const hidden = {opacity: 0, visibility: 'hidden', pointerEvents: 'none'};
    assert.equal(await button.evaluate(element => getComputedStyle(element).opacity), '1');

    for (const hide of [true, false]) {
        const {duration, middle, end} = await sampleChange(button, hide);
        assert.equal(duration, 300);
        assert.ok(middle.opacity > 0 && middle.opacity < 1, 'opacity must be intermediate halfway through the fade');
        assert.equal(middle.visibility, 'visible');
        assert.equal(middle.pointerEvents, hide ? 'none' : 'auto');
        assert.deepEqual(end, hide ? hidden : shown);
    }

    await button.getByRole('link').focus();
    assert.deepEqual((await sampleChange(button, true)).end, shown);
    await sampleChange(button, false);
    await button.getByRole('link').blur();
    await page.emulateMedia({reducedMotion: 'reduce'});
    for (const hide of [true, false]) {
        const {duration, middle} = await sampleChange(button, hide);
        assert.equal(duration, 0);
        assert.deepEqual(middle, hide ? hidden : shown);
    }
});
