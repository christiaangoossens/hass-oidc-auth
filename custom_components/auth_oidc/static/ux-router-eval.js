
export const PresentationStrategy = Object.freeze({
    AUTO_REDIRECT: "auto_redirect", // Auto redirects to Home Assistant login page on desktop (not implemented)
    MOBILE_APP: "mobile_app", //device flow autostarts on companion app (QR shows on tablet size [not implemented])
    TABLET_TV: "tablet_tv", // QR codes shown on smart tv / tablet devices [not implemented]
    AMBIGUOUS: "ambiguous", // device code option shown as well as redirect option shown (default when above situations not detected)
});


export function decideStrategy() {
    const isCompanionApp = (document.querySelector("meta[name='is_companion_app']").getAttribute("content") ?? 'false') == "true";

    if (isCompanionApp) {
        return PresentationStrategy.MOBILE_APP;
    }

    return PresentationStrategy.AMBIGUOUS;
}