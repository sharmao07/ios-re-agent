from __future__ import annotations

from ios_re_agent.features import build_feature_map


def test_feature_map_uses_declared_evidence_and_labels_hypotheses() -> None:
    report = {
        "input": {"name": "Demo.ipa"},
        "app": {"executable": "Demo", "url_schemes": ["demo"], "queried_url_schemes": [], "background_modes": ["remote-notification"], "privacy_usage_descriptions": [{"key": "NSCameraUsageDescription"}]},
        "inventory": {
            "frameworks_and_dynamic_libraries": ["Apollo.framework", "Bugsnag.framework"],
            "framework_evidence": {"Apollo.framework": "Frameworks/Apollo.framework/Apollo", "Bugsnag.framework": "Frameworks/Bugsnag.framework/Bugsnag"},
            "app_extensions": [{"path": "PlugIns/NotificationService.appex/Info.plist", "extension_point": "com.apple.usernotifications.service"}],
            "privacy_manifests": [{"path": "PrivacyInfo.xcprivacy", "tracking": True, "tracking_domains": ["metrics.example.test"]}],
        },
        "network_indicators": {"evidence": [{"source_path": "Demo", "url": "https://api.example.test/v1/search", "classification": "possible_service_endpoint"}]},
        "macho": {"slices": [{"architecture": "arm64", "file_type": "executable"}]},
    }
    features = build_feature_map(report)
    names = {item["feature"] for item in features}
    assert "native_code_present" in names
    assert "push_notifications" in names
    assert "network_api_and_backend_integration" in names
    assert all(item["confidence"] in {"low", "medium", "high"} for item in features)
    assert all(item["evidence"] for item in features)
