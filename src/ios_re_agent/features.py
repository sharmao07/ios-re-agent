"""Evidence-backed, conservative feature hypotheses built from static report data."""
from __future__ import annotations

from typing import Any


def build_feature_map(report: dict[str, Any]) -> list[dict[str, Any]]:
    app = report.get("app", {}) if isinstance(report.get("app"), dict) else {}
    inventory = report.get("inventory", {}) if isinstance(report.get("inventory"), dict) else {}
    network = report.get("network_indicators", {}) if isinstance(report.get("network_indicators"), dict) else {}
    macho = report.get("macho", {}) if isinstance(report.get("macho"), dict) else {}
    frameworks = [str(v) for v in inventory.get("frameworks_and_dynamic_libraries", [])]
    extensions = inventory.get("app_extensions", [])
    manifests = inventory.get("privacy_manifests", [])
    urls = network.get("evidence", [])
    schemes = [str(v).lower() for v in app.get("url_schemes", [])]
    query_schemes = [str(v).lower() for v in app.get("queried_url_schemes", [])]
    all_schemes = schemes + query_schemes
    modes = [str(v).lower() for v in app.get("background_modes", [])]
    usage = app.get("privacy_usage_descriptions", [])
    usage_keys = {str(item.get("key", "")) for item in usage if isinstance(item, dict)}
    framework_paths = inventory.get("framework_evidence", {})
    result: list[dict[str, Any]] = []

    def add(feature: str, confidence: str, summary: str, evidence: list[dict[str, str]]) -> None:
        # Normalize and deduplicate evidence to make a stable, readable report.
        unique: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for item in evidence:
            key = (item.get("source_path", "unknown"), item.get("reason", ""))
            if key not in seen:
                seen.add(key)
                unique.append({"source_path": key[0], "reason": key[1]})
        if unique:
            result.append({"feature": feature, "confidence": confidence, "summary": summary, "evidence": unique[:20]})

    ext_evidence: list[dict[str, str]] = []
    for ext in extensions:
        if isinstance(ext, dict) and ("share" in str(ext.get("extension_point", "")).lower() or "ActionExtension" in str(ext.get("path", ""))):
            ext_evidence.append({"source_path": str(ext.get("path", "Info.plist")), "reason": "Share/action extension declared in bundle metadata"})
    if ext_evidence or any("share" in s or "pinterest" in s for s in schemes):
        add("sharing_and_deep_links", "medium", "The package declares share-related components or URL schemes; runtime routing is not verified.", ext_evidence + [{"source_path": "Info.plist", "reason": f"Declared URL scheme: {scheme}"} for scheme in schemes[:4] if "share" in scheme or scheme == "pinterest"])

    push_evidence = [{"source_path": str(ext.get("path", "Info.plist")), "reason": "Notification extension declared"}
                     for ext in extensions if isinstance(ext, dict) and "notification" in str(ext.get("path", "")).lower()]
    if "remote-notification" in modes:
        push_evidence.append({"source_path": "Info.plist", "reason": "UIBackgroundModes includes remote-notification"})
    if push_evidence:
        add("push_notifications", "medium", "Notification-related components or background modes are declared.", push_evidence)

    auth_fws = [f for f in frameworks if any(k in f.lower() for k in ("fbsdk", "auth", "scsdkcorekit"))]
    auth_schemes = [s for s in schemes if any(k in s for k in ("googleusercontent", "fb", "line", "pinterest"))]
    auth_evidence = [{"source_path": str(framework_paths.get(f, "Frameworks/" + f)), "reason": f"Embedded authentication or identity-related SDK: {f}"} for f in auth_fws]
    auth_evidence += [{"source_path": "Info.plist", "reason": f"Authentication-capable URL scheme declared: {s}"} for s in auth_schemes[:5]]
    if auth_evidence:
        add("identity_and_sign_in_integrations", "low", "SDK names or URL schemes suggest identity integrations; actual enabled flows need code-level tracing.", auth_evidence)

    analytics_evidence: list[dict[str, str]] = []
    for manifest in manifests:
        if isinstance(manifest, dict) and (manifest.get("tracking") is True or manifest.get("tracking_domains")):
            analytics_evidence.append({"source_path": str(manifest.get("path", "PrivacyInfo.xcprivacy")), "reason": "Manifest declares tracking or tracking domains"})
    for fw in frameworks:
        if any(k in fw.lower() for k in ("bugsnag", "omsdk", "appsflyer", "firebaseanalytics", "analytics")):
            analytics_evidence.append({"source_path": str(framework_paths.get(fw, "Frameworks/" + fw)), "reason": f"Analytics, attribution, or diagnostics-related framework: {fw}"})
    if analytics_evidence:
        add("analytics_attribution_and_diagnostics", "medium", "The package contains tracking declarations or analytics/diagnostics SDK clues; this is not proof of runtime data collection.", analytics_evidence)

    media_keys = sorted(usage_keys.intersection({"NSCameraUsageDescription", "NSMicrophoneUsageDescription", "NSPhotoLibraryUsageDescription", "NSPhotoLibraryAddUsageDescription"}))
    media_fw = [f for f in frameworks if any(k in f.lower() for k in ("rive", "renderer", "avfoundation", "om sdk"))]
    media_evidence = [{"source_path": "Info.plist", "reason": f"Declared access purpose: {key}"} for key in media_keys]
    media_evidence += [{"source_path": str(framework_paths.get(f, "Frameworks/" + f)), "reason": f"Media/rendering-related framework: {f}"} for f in media_fw]
    if media_evidence:
        add("media_capture_and_rendering", "low", "Permissions or embedded frameworks suggest media creation/rendering capabilities.", media_evidence)

    pay_fw = [f for f in frameworks if any(k in f.lower() for k in ("storekit", "adyen", "stripe", "braintree"))]
    if pay_fw or any("payment" in str(x).lower() or "storekit" in str(x).lower() for x in urls):
        add("payments_or_purchases", "low", "Payment-related framework or string indicators were found; no transaction flow is established.",
            [{"source_path": str(framework_paths.get(f, "Frameworks/" + f)), "reason": f"Potential payment framework: {f}"} for f in pay_fw] +
            [{"source_path": str(item.get("source_path", "unknown")), "reason": "Possible payment-related URL/string indicator"} for item in urls if "payment" in str(item.get("url", "")).lower()][:3])

    gql = [f for f in frameworks if any(k in f.lower() for k in ("apollo", "graphql"))]
    api_urls = [item for item in urls if item.get("classification") == "possible_service_endpoint"]
    if gql or api_urls:
        evidence = [{"source_path": str(framework_paths.get(f, "Frameworks/" + f)), "reason": f"GraphQL/network client framework: {f}"} for f in gql]
        evidence += [{"source_path": str(item.get("source_path", "unknown")), "reason": f"Static URL candidate: {item.get('url', '')}"} for item in api_urls[:5]]
        add("network_api_and_backend_integration", "medium" if gql else "low", "Network-client dependencies or endpoint strings were found; the active backend contract is not yet traced.", evidence)

    widget_evidence = [{"source_path": str(ext.get("path", "Info.plist")), "reason": f"Extension point declared: {ext.get('extension_point', 'unknown')}"}
                       for ext in extensions if isinstance(ext, dict) and any(k in str(ext.get("path", "")).lower() for k in ("widget", "siri", "intent"))]
    if widget_evidence:
        add("widgets_and_system_integrations", "medium", "Widget/Siri/system extension bundles are declared.", widget_evidence)

    slices = macho.get("slices", [])
    if slices:
        add("native_code_present", "high", "A Mach-O executable header was parsed; complete decompilation still requires a native-analysis backend and usable code bytes.",
            [{"source_path": str(app.get("executable") or report.get("input", {}).get("name", "binary")), "reason": f"Mach-O slice metadata: {slice_.get('architecture', 'unknown')} / {slice_.get('file_type', 'unknown')}"}
             for slice_ in slices[:5] if isinstance(slice_, dict)])
    return sorted(result, key=lambda row: row["feature"])
