# 🛡️ CyberShield

**The world's first labeled dataset and analysis framework for psychological cyber attacks.**

Built by **Ismaeel Khan** — from direct personal experience of coordinated, multi-vector psychological cyber operations spanning five years.

---

## ⚠️ This is not theoretical

Every attack category documented here was experienced firsthand. Every behavioral indicator was observed in real attacks. Every recovery lesson was learned the hard way.

This dataset exists because no such resource existed when it was needed most.

---

## 🔬 Research Purpose

CyberShield provides the cybersecurity research community with:

- A **structured, labeled dataset** of psychological cyber attacks
- A **taxonomy** of 9 attack categories with full behavioral documentation
- A **text analysis engine** that detects attack patterns in real-time
- **Recovery guidance** based on lived experience
- A **foundation** for training AI models to detect psychological manipulation

---

## 📊 Dataset Overview

| Category | Code | Severity | Records |
|----------|------|----------|---------|
| Impersonation | IMP | 9/10 | 2+ |
| Gaslighting | GAS | 10/10 | 2+ |
| Phishing via trusted contact | PHT | 8/10 | 2+ |
| Relationship manipulation | REL | 10/10 | 2+ |
| Urgency attacks | URG | 7/10 | 2+ |
| Identity theft | IDT | 10/10 | 2+ |
| Fake authority | FAU | 8/10 | 2+ |
| Emotional manipulation | EMO | 9/10 | 2+ |
| Character assassination | CHA | 10/10 | 2+ |

---

## 🚀 Quick Start

```bash
git clone https://github.com/Ismaeel-Jr/cybershield.git
cd cybershield
python src/cybershield.py
```

No installation required. Pure Python — zero dependencies.

---

## 💻 Usage

### Analyze a text message
```python
from src.cybershield import CyberShieldDataset

ds = CyberShieldDataset()

text = "URGENT: This is the IRS. You face arrest within 2 hours. Act now. Do not tell anyone."

matches = ds.analyze_text(text)
for category, data in matches.items():
    print(f"Attack: {data['attack_type']}")
    print(f"Severity: {data['severity']}/10")
    print(f"What to do: {data['immediate_actions']}")
```

### Search the dataset
```python
results = ds.search("gaslighting")
for attack in results:
    print(f"[{attack['id']}] {attack['sub_type']}")
    print(f"Recovery time: {attack['recovery_time_days']} days")
```

### Get full statistics
```python
stats = ds.get_statistics()
print(f"Total attacks: {stats['total_attacks']}")
print(f"Avg recovery: {stats['average_recovery_days']} days")
```

### Add a new attack record
```python
ds.add_attack(
    category="GASLIGHTING",
    sub_type="Memory denial",
    severity=9,
    platform="WhatsApp",
    vector="Direct messaging",
    description="Attacker denied sending messages victim clearly received",
    psychological_tactics=["Reality distortion", "Persistent denial"],
    behavioral_indicators=["Denied documented communications"],
    victim_impact=["Questioned own memory"],
    detection_difficulty="HIGH",
    recovery_time_days=30,
    lessons="Always screenshot and timestamp all communications"
)
```

### Export to JSON
```python
ds.export_json("my_dataset.json")
```

---

## 🧪 Running Tests

```bash
python tests/test_cybershield.py
```

12 tests — all passing.

---

## 🗺️ Roadmap

- [ ] v1.1 — Web interface for dataset browsing
- [ ] v1.2 — API endpoint for external queries
- [ ] v2.0 — ML classifier trained on dataset
- [ ] v2.1 — Integration with SEGuard for combined detection
- [ ] v3.0 — Community contribution system
- [ ] v3.1 — Multi-language attack pattern library

---

## 🔗 Related Project

**SEGuard** — Real-time social engineering detection tool
github.com/Ismaeel-Jr/social-engineering-detector

CyberShield provides the dataset foundation.
SEGuard provides the real-time detection engine.
Together they form a complete psychological attack defense system.

---

## 👤 Author

**Ismaeel Khan**
🔗 github.com/Ismaeel-Jr

*"The most dangerous cyber weapon is not a virus. It is a well-crafted lie delivered at exactly the right moment."*

---

## 📄 License

MIT License — Free to use for research and education.

---

## 🤝 Contributing

If you have experienced psychological cyber attacks and want to contribute anonymized records to the dataset, please open a pull request or contact the author directly.

Your experience makes this dataset stronger. Your contribution protects others.

---

⭐ **If this dataset helps your research, please star this repository.**
