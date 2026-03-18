"""
CyberShield — Test Suite
========================
Author: Ismaeel Khan
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from cybershield import CyberShieldDataset, ATTACK_TAXONOMY


def test_dataset_loads():
    ds = CyberShieldDataset()
    assert len(ds.attacks) >= 18
    print(f"✅ Dataset loads correctly — {len(ds.attacks)} records")


def test_all_9_categories_present():
    ds = CyberShieldDataset()
    categories = set(a["category"] for a in ds.attacks)
    expected = {
        "IMPERSONATION", "GASLIGHTING", "PHISHING_TRUSTED_CONTACT",
        "RELATIONSHIP_MANIPULATION", "URGENCY_ATTACK", "IDENTITY_THEFT",
        "FAKE_AUTHORITY", "EMOTIONAL_MANIPULATION", "CHARACTER_ASSASSINATION"
    }
    assert expected == categories
    print(f"✅ All 9 attack categories present")


def test_taxonomy_completeness():
    for category, data in ATTACK_TAXONOMY.items():
        assert "code" in data
        assert "severity" in data
        assert "description" in data
        assert "psychological_mechanism" in data
        assert "behavioral_signals" in data
        assert "detection_keywords" in data
        assert "recovery_actions" in data
        assert "author_experience_note" in data
    print(f"✅ Taxonomy complete — all {len(ATTACK_TAXONOMY)} categories verified")


def test_text_analysis_detects_gaslighting():
    ds = CyberShieldDataset()
    text = "You're imagining things. That never happened. Everyone agrees you are overreacting."
    matches = ds.analyze_text(text)
    assert "GASLIGHTING" in matches
    print(f"✅ Gaslighting detection works — keywords: {matches['GASLIGHTING']['matched_keywords']}")


def test_text_analysis_detects_urgency():
    ds = CyberShieldDataset()
    text = "Act now! This is your final warning. Respond immediately or face consequences."
    matches = ds.analyze_text(text)
    assert "URGENCY_ATTACK" in matches
    print(f"✅ Urgency attack detection works")


def test_text_analysis_detects_fake_authority():
    ds = CyberShieldDataset()
    text = "This is the IRS. You face a federal investigation. Legal action will be taken immediately."
    matches = ds.analyze_text(text)
    assert "FAKE_AUTHORITY" in matches
    print(f"✅ Fake authority detection works")


def test_text_analysis_detects_character_assassination():
    ds = CyberShieldDataset()
    text = "Everyone knows what you did. People are saying you have a reputation for this. Screenshots don't lie."
    matches = ds.analyze_text(text)
    assert "CHARACTER_ASSASSINATION" in matches
    print(f"✅ Character assassination detection works")


def test_statistics_generation():
    ds = CyberShieldDataset()
    stats = ds.get_statistics()
    assert stats["total_attacks"] >= 18
    assert stats["total_categories"] == 9
    assert stats["average_recovery_days"] > 0
    print(f"✅ Statistics generated — avg recovery: {stats['average_recovery_days']} days")


def test_search_functionality():
    ds = CyberShieldDataset()
    results = ds.search("gaslighting")
    assert len(results) > 0
    print(f"✅ Search works — found {len(results)} results for 'gaslighting'")


def test_add_new_attack():
    ds = CyberShieldDataset()
    initial_count = len(ds.attacks)
    attack_id = ds.add_attack(
        category="IMPERSONATION",
        sub_type="Test attack",
        severity=8,
        platform="Email",
        vector="Email spoofing",
        description="Test attack record",
        psychological_tactics=["Trust exploitation"],
        behavioral_indicators=["Test indicator"],
        victim_impact=["Test impact"],
        detection_difficulty="HIGH",
        recovery_time_days=7,
        lessons="Test lesson"
    )
    assert len(ds.attacks) == initial_count + 1
    assert attack_id is not None
    print(f"✅ New attack added successfully — ID: {attack_id}")


def test_export_json():
    ds = CyberShieldDataset()
    path = "/tmp/test_export.json"
    result = ds.export_json(path)
    assert os.path.exists(path)
    import json
    with open(path) as f:
        data = json.load(f)
    assert data["metadata"]["total_records"] >= 18
    assert len(data["attacks"]) >= 18
    assert len(data["taxonomy"]) == 9
    print(f"✅ JSON export works — {data['metadata']['total_records']} records exported")


def test_multi_vector_detection():
    """Real attacks use multiple tactics simultaneously — test compound detection."""
    ds = CyberShieldDataset()
    text = """
    URGENT: This is law enforcement. We have been watching you.
    No one will believe you if you tell anyone. You're imagining that
    this is not real. Everyone agrees you have been behaving strangely.
    Act now or face arrest. I thought you cared about your family.
    """
    matches = ds.analyze_text(text)
    assert len(matches) >= 4
    print(f"✅ Multi-vector attack detection works — {len(matches)} attack types identified")
    for cat in matches:
        print(f"   → {cat}")


if __name__ == "__main__":
    print("\n" + "=" * 55)
    print("  CYBERSHIELD TEST SUITE")
    print("  Author: Ismaeel Khan")
    print("=" * 55)
    test_dataset_loads()
    test_all_9_categories_present()
    test_taxonomy_completeness()
    test_text_analysis_detects_gaslighting()
    test_text_analysis_detects_urgency()
    test_text_analysis_detects_fake_authority()
    test_text_analysis_detects_character_assassination()
    test_statistics_generation()
    test_search_functionality()
    test_add_new_attack()
    test_export_json()
    test_multi_vector_detection()
    print("\n✅ ALL 12 TESTS PASSED")
    print("=" * 55 + "\n")
