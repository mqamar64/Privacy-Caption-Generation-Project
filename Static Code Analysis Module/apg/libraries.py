"""Third-party library / SDK detection by package prefix.

Each class in the APG gets an ``origin``:
  * ``app``       - the developer's own code (manifest package or component packages)
  * ``library``   - a recognised third-party SDK or runtime (see KNOWN_LIBRARIES)
  * ``framework`` - Android / Java platform classes (external to the APK)
  * ``unknown``   - anything else bundled in the APK (often obfuscated app or SDK code)

Extend KNOWN_LIBRARIES as new SDKs show up; longer prefixes win.
"""

from __future__ import annotations

# prefix -> (library name, category)
KNOWN_LIBRARIES: dict[str, tuple[str, str]] = {
    # Analytics / attribution
    "com.google.firebase.analytics": ("Firebase Analytics", "analytics"),
    "com.google.android.gms.measurement": ("Google Analytics for Firebase", "analytics"),
    "com.google.android.gms.analytics": ("Google Analytics", "analytics"),
    "com.flurry": ("Flurry", "analytics"),
    "com.mixpanel": ("Mixpanel", "analytics"),
    "com.amplitude": ("Amplitude", "analytics"),
    "com.segment": ("Segment", "analytics"),
    "com.appsflyer": ("AppsFlyer", "attribution"),
    "com.adjust.sdk": ("Adjust", "attribution"),
    "io.branch": ("Branch", "attribution"),
    "com.kochava": ("Kochava", "attribution"),
    "com.yandex.metrica": ("AppMetrica", "analytics"),
    # Advertising
    "com.google.android.gms.ads": ("Google Mobile Ads", "advertising"),
    "com.google.ads": ("Google Ads", "advertising"),
    "com.facebook.ads": ("Meta Audience Network", "advertising"),
    "com.unity3d.ads": ("Unity Ads", "advertising"),
    "com.applovin": ("AppLovin", "advertising"),
    "com.ironsource": ("ironSource", "advertising"),
    "com.vungle": ("Vungle", "advertising"),
    "com.chartboost": ("Chartboost", "advertising"),
    "com.inmobi": ("InMobi", "advertising"),
    "com.mopub": ("MoPub", "advertising"),
    "com.startapp": ("Start.io", "advertising"),
    "com.bytedance.sdk": ("Pangle", "advertising"),
    # Crash reporting / monitoring
    "com.google.firebase.crashlytics": ("Firebase Crashlytics", "crash_reporting"),
    "com.crashlytics": ("Crashlytics", "crash_reporting"),
    "io.sentry": ("Sentry", "crash_reporting"),
    "com.bugsnag": ("Bugsnag", "crash_reporting"),
    "org.acra": ("ACRA", "crash_reporting"),
    "com.instabug": ("Instabug", "crash_reporting"),
    "com.newrelic": ("New Relic", "monitoring"),
    # Social / identity
    "com.facebook": ("Facebook SDK", "social"),
    "com.twitter": ("Twitter SDK", "social"),
    "com.google.android.gms.auth": ("Google Sign-In", "authentication"),
    "com.google.firebase.auth": ("Firebase Auth", "authentication"),
    # Push / messaging
    "com.google.firebase.messaging": ("Firebase Cloud Messaging", "push_messaging"),
    "com.onesignal": ("OneSignal", "push_messaging"),
    "com.urbanairship": ("Airship", "push_messaging"),
    # Location / maps
    "com.google.android.gms.location": ("Google Location Services", "location"),
    "com.google.android.gms.maps": ("Google Maps", "location"),
    "com.mapbox": ("Mapbox", "location"),
    "org.osmdroid": ("osmdroid", "location"),
    # Payments
    "com.stripe": ("Stripe", "payments"),
    "com.paypal": ("PayPal", "payments"),
    "com.braintreepayments": ("Braintree", "payments"),
    "com.android.billingclient": ("Google Play Billing", "payments"),
    # Cloud / backend
    "com.google.firebase": ("Firebase", "backend"),
    "com.google.android.gms": ("Google Play Services", "backend"),
    "com.amazonaws": ("AWS SDK", "backend"),
    # Networking
    "okhttp3": ("OkHttp", "networking"),
    "okio": ("Okio", "networking"),
    "retrofit2": ("Retrofit", "networking"),
    "com.android.volley": ("Volley", "networking"),
    "io.ktor": ("Ktor", "networking"),
    "org.apache.http": ("Apache HttpClient", "networking"),
    "com.squareup.okhttp": ("OkHttp (legacy)", "networking"),
    "javax.jmdns": ("JmDNS", "networking"),
    # Image loading / UI
    "com.bumptech.glide": ("Glide", "image_loading"),
    "com.squareup.picasso": ("Picasso", "image_loading"),
    "coil": ("Coil", "image_loading"),
    "com.facebook.fresco": ("Fresco", "image_loading"),
    "com.google.android.material": ("Material Components", "ui"),
    "com.journeyapps": ("ZXing Android Embedded", "ui"),
    "com.google.zxing": ("ZXing", "ui"),
    # Data / serialization / storage
    "com.google.gson": ("Gson", "serialization"),
    "com.squareup.moshi": ("Moshi", "serialization"),
    "com.fasterxml.jackson": ("Jackson", "serialization"),
    "kotlinx.serialization": ("kotlinx.serialization", "serialization"),
    "io.realm": ("Realm", "database"),
    "net.sqlcipher": ("SQLCipher", "database"),
    # Crypto
    "org.bouncycastle": ("Bouncy Castle", "crypto"),
    "org.spongycastle": ("Spongy Castle", "crypto"),
    # Language runtimes / platform support
    "kotlin": ("Kotlin stdlib", "runtime"),
    "kotlinx.coroutines": ("Kotlin Coroutines", "runtime"),
    "androidx": ("AndroidX / Jetpack", "jetpack"),
    "android.support": ("Android Support Library", "jetpack"),
    "io.reactivex": ("RxJava", "runtime"),
    "rx": ("RxJava 1", "runtime"),
    "dagger": ("Dagger", "runtime"),
    "javax.inject": ("javax.inject", "runtime"),
    "com.google.common": ("Guava", "runtime"),
    "org.slf4j": ("SLF4J", "logging"),
    "ch.qos.logback": ("Logback", "logging"),
    "timber": ("Timber", "logging"),
}

# Platform packages: classes referenced but not shipped in the APK.
FRAMEWORK_PREFIXES = (
    "android", "java", "javax", "dalvik", "org.json", "org.w3c", "org.xml",
    "org.xmlpull", "sun", "libcore", "com.android.internal",
)

_SORTED = sorted(KNOWN_LIBRARIES.items(), key=lambda kv: -len(kv[0]))


def _has_prefix(name: str, prefix: str) -> bool:
    return name == prefix or name.startswith(prefix + ".") or name.startswith(prefix + "$")


def match_library(class_name: str) -> tuple[str, str, str] | None:
    """Return (prefix, library name, category) for a dotted class name, if known."""
    for prefix, (lib, cat) in _SORTED:
        if _has_prefix(class_name, prefix):
            return prefix, lib, cat
    return None


def is_framework(class_name: str) -> bool:
    return any(_has_prefix(class_name, p) for p in FRAMEWORK_PREFIXES)


class OriginClassifier:
    """Classify classes as app / library / framework / unknown."""

    def __init__(self, app_prefixes: list[str]):
        # Longest first so nested app packages are matched before library prefixes.
        self.app_prefixes = sorted({p for p in app_prefixes if p}, key=len, reverse=True)

    def classify(self, class_name: str, is_external: bool) -> tuple[str, str | None, str | None]:
        """Return (origin, library name, library category)."""
        lib = match_library(class_name)
        app_match = next((p for p in self.app_prefixes if _has_prefix(class_name, p)), None)
        # An app prefix wins unless a more specific library prefix also matches
        # (e.g. app package "com.facebook.katana" vs SDK "com.facebook").
        if app_match and (lib is None or len(app_match) >= len(lib[0])):
            return "app", None, None
        if lib:
            return "library", lib[1], lib[2]
        if is_external or is_framework(class_name):
            return "framework", None, None
        return "unknown", None, None
