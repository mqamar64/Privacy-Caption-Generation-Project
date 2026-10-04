from apg.libraries import OriginClassifier, match_library


def test_longest_prefix_wins():
    assert match_library("com.google.firebase.analytics.FirebaseAnalytics")[1] == "Firebase Analytics"
    assert match_library("com.google.firebase.firestore.X")[1] == "Firebase"
    assert match_library("okhttp3.OkHttpClient")[1] == "OkHttp"
    assert match_library("okhttp3x.Foo") is None


def test_origin_classification():
    c = OriginClassifier(["org.fdroid.fdroid", "com.facebook.katana"])
    assert c.classify("org.fdroid.fdroid.MainActivity", False)[0] == "app"
    assert c.classify("com.facebook.katana.Main", False)[0] == "app"
    assert c.classify("com.facebook.ads.AdView", False)[:2] == ("library", "Meta Audience Network")
    assert c.classify("android.location.LocationManager", True)[0] == "framework"
    assert c.classify("a.b.c", False)[0] == "unknown"
