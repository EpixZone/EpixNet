const WELCOME_LOGO = 'chrome://epix-addon-installer/content/welcome.png';

// Keep Firefox's localized greeting. Scope the EpixNet brand term to this
// heading so the accompanying legal and privacy notices still identify Firefox.
function welcomeTitle(messageId) {
  const [bundle] = L10nRegistry.getInstance().generateBundlesSync(
    Services.locale.appLocalesAsBCP47, ['browser/preonboarding.ftl']
  );
  const heading = bundle?.getMessage(messageId);
  if (!heading?.value) return 'EpixNet';
  bundle.addResource(new FluentResource('-brand-product-name = EpixNet'));
  return bundle.formatPattern(heading.value);
}

export function configureWelcome() {
  const pref = 'browser.preonboarding.screens';
  if (Services.prefs.getPrefType(pref) !== Services.prefs.PREF_INVALID) return;

  const { OnboardingMessageProvider } = ChromeUtils.importESModule(
    'resource:///modules/asrouter/OnboardingMessageProvider.sys.mjs'
  );
  // Start from the installed ESR's own screens on every launch. Its current
  // agreements, available settings and consent actions stay in sync on update.
  const screens = OnboardingMessageProvider.getPreonboardingMessages()
    .find(message => message.id === 'NEW_USER_TOU_ONBOARDING')?.screens;
  const content = screens?.find(screen => screen.id === 'TOU_ONBOARDING')?.content;
  if (content?.title?.string_id !== 'preonboarding-title' || !content.logo) return;

  content.title = welcomeTitle(content.title.string_id);
  content.logo.imageURL = WELCOME_LOGO;
  const splash = screens.find(screen => screen.id === 'TOU_ONBOARDING_LOADING')?.content.logo;
  if (splash) Object.assign(splash, { imageURL: WELCOME_LOGO, width: '96px', height: '96px' });
  Services.prefs.getDefaultBranch('').setStringPref(pref, JSON.stringify(screens));
}
