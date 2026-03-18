"""
CyberShield — Psychological Cyber Attack Dataset & Analyzer
============================================================
Author      : Ismaeel Khan
GitHub      : github.com/Ismaeel-Jr
Contact     : Edu.Ismaeel@gmail.com
Version     : 1.0.0
License     : MIT

Description:
    The world's first labeled dataset and analysis framework for
    psychological cyber attacks — built from direct personal experience
    of coordinated, multi-vector psychological cyber operations spanning
    5 years.

    This is NOT a theoretical framework. Every attack category,
    every tactic, every behavioral pattern documented here was
    experienced firsthand by the author.

Research Goal:
    To provide the cybersecurity research community with a structured,
    labeled, and analyzable dataset of psychological manipulation attacks
    — enabling AI systems to detect, classify, and defend against
    human-targeted cyber threats.

Attack Categories Documented:
    1. Impersonation
    2. Gaslighting
    3. Phishing via trusted contact
    4. Relationship manipulation
    5. Urgency attacks
    6. Identity theft
    7. Fake authority
    8. Emotional manipulation
    9. Character assassination
"""

import json
import re
import os
from datetime import datetime
from collections import defaultdict, Counter


# ─────────────────────────────────────────────────────────────
#  ATTACK TAXONOMY — Built from lived experience
# ─────────────────────────────────────────────────────────────

ATTACK_TAXONOMY = {

    "IMPERSONATION": {
        "code": "IMP",
        "severity": 9,
        "description": (
            "Attacker assumes the identity of a trusted person or organization. "
            "Messages, calls, or profiles are crafted to perfectly mimic known contacts. "
            "The victim's trust in the relationship is the primary attack vector."
        ),
        "psychological_mechanism": "Trust exploitation — victim's established relationships weaponized",
        "behavioral_signals": [
            "Mimics writing style of known contact",
            "References shared personal history to appear authentic",
            "Requests unusual actions framed as normal",
            "Creates urgency to prevent verification",
            "Uses familiar pet names, jokes, or private references",
            "Switches communication channel unexpectedly",
            "Provides just enough real detail to seem genuine",
        ],
        "cognitive_biases_exploited": [
            "Familiarity heuristic",
            "Authority bias",
            "Confirmation bias",
        ],
        "attack_phases": [
            "Reconnaissance — study target's relationships and communication patterns",
            "Profile construction — build convincing identity replica",
            "Initial contact — low-stakes interaction to establish trust",
            "Escalation — gradually increase demands or information requests",
            "Extraction — obtain target information or action",
            "Cover — maintain persona to prevent detection",
        ],
        "real_world_examples": [
            "Message from 'friend' asking for urgent financial help while 'traveling'",
            "Email from 'employer' requesting password reset or document transfer",
            "Call from 'family member' in distress needing immediate action",
            "Social media message from cloned profile of known contact",
            "WhatsApp from saved number used by attacker after SIM swap",
        ],
        "detection_keywords": [
            "urgent", "immediately", "don't tell anyone", "just between us",
            "I need you to", "please don't call", "trust me", "you know me",
            "as we discussed", "remember when we", "our secret"
        ],
        "recovery_actions": [
            "Verify identity through a completely separate channel",
            "Call the real person directly using a known number",
            "Ask a question only the real person would know",
            "Do not act under urgency — slow down deliberately",
        ],
        "author_experience_note": (
            "Experienced multiple instances of contact impersonation. "
            "Attackers studied behavioral patterns of trusted contacts "
            "to replicate communication style with surgical precision."
        )
    },

    "GASLIGHTING": {
        "code": "GAS",
        "severity": 10,
        "description": (
            "Systematic psychological manipulation designed to make the victim "
            "question their own memory, perception, and sanity. "
            "The most psychologically devastating attack type — "
            "it targets the victim's relationship with reality itself."
        ),
        "psychological_mechanism": "Reality distortion — victim's perception of truth is dismantled",
        "behavioral_signals": [
            "Persistent denial of events the victim clearly remembers",
            "Reframing victim's accurate perceptions as paranoia",
            "Claiming victim said or did things they did not",
            "Isolating victim from support networks who might validate reality",
            "Using victim's emotional responses against them as 'proof' of instability",
            "Subtle, gradual escalation — begins small and builds",
            "Triangulating — using third parties to reinforce the false narrative",
            "Creating confusion through contradictory statements",
        ],
        "cognitive_biases_exploited": [
            "Self-doubt amplification",
            "Social proof — 'everyone agrees you are wrong'",
            "Emotional reasoning — 'if I feel confused I must be wrong'",
        ],
        "attack_phases": [
            "Normalization — establish trust and dependency",
            "Introduction — small reality distortions begin",
            "Escalation — frequency and severity of distortions increase",
            "Isolation — victim separated from reality-confirming support",
            "Destabilization — victim's confidence in own judgment collapses",
            "Control — victim now dependent on attacker's version of reality",
        ],
        "real_world_examples": [
            "Attacker denies sending messages that victim clearly received",
            "Claims victim misunderstood 'obvious' meaning of communications",
            "Tells victim their memory of events is 'getting worse'",
            "Recruits others to confirm attacker's false version of events",
            "Uses victim's emotional distress as evidence of mental instability",
            "Rewrites history of interactions to reposition victim as aggressor",
        ],
        "detection_keywords": [
            "you're imagining things", "that never happened", "you always do this",
            "everyone thinks you", "you're overreacting", "I never said that",
            "you're too sensitive", "you're confused", "no one will believe you",
            "you're remembering it wrong", "you're paranoid"
        ],
        "recovery_actions": [
            "Document everything — screenshots, logs, timestamps",
            "Trust your own documented record over attacker's claims",
            "Seek validation from trusted third parties outside the attack network",
            "Recognize that confusion itself is a sign of gaslighting",
        ],
        "author_experience_note": (
            "Gaslighting was the most psychologically devastating attack experienced. "
            "Systematic reality distortion over an extended period caused genuine "
            "questioning of memory and judgment. Documentation was the primary defense."
        )
    },

    "PHISHING_TRUSTED_CONTACT": {
        "code": "PHT",
        "severity": 8,
        "description": (
            "Phishing attacks delivered through — or appearing to come from — "
            "trusted contacts rather than anonymous sources. "
            "Far more effective than traditional phishing because the victim's "
            "trust in the sender bypasses normal suspicion."
        ),
        "psychological_mechanism": "Trust transfer — legitimate relationship trust redirected to malicious request",
        "behavioral_signals": [
            "Message arrives from known contact's real or spoofed account",
            "Content references genuine shared context to appear authentic",
            "Request is unusual but framed within the relationship",
            "Link or attachment presented as something the contact would naturally share",
            "Tone mimics the contact's authentic communication style",
            "Discourages verification — 'I'm in a meeting, just click the link'",
        ],
        "cognitive_biases_exploited": [
            "In-group trust bias",
            "Reciprocity — 'my friend shared this, I should too'",
            "Authority by association",
        ],
        "attack_phases": [
            "Account compromise or spoofing of trusted contact",
            "Reconnaissance of relationship dynamics",
            "Crafting contextually appropriate message",
            "Delivery through trusted channel",
            "Credential or data harvest",
            "Pivot — use obtained access for further attacks",
        ],
        "real_world_examples": [
            "Friend's hacked account sends malware link as 'funny video'",
            "Colleague's spoofed email requests document transfer",
            "Family member's cloned profile asks for financial help",
            "Trusted group chat used to distribute phishing link",
            "Contact's email used after password breach to send malware",
        ],
        "detection_keywords": [
            "check this out", "thought you'd like this", "can you help me with",
            "I found something", "look at this link", "download this",
            "open this file", "click here", "log in to see", "verify your account"
        ],
        "recovery_actions": [
            "Always verify through separate channel before clicking anything",
            "Check sender address carefully — even one character difference",
            "Call the contact directly to confirm they sent the message",
            "Never click links in messages — go directly to official websites",
        ],
        "author_experience_note": (
            "Phishing through trusted contacts was used as an entry vector. "
            "The effectiveness came from the established trust relationship "
            "making the request feel normal and lowering suspicion."
        )
    },

    "RELATIONSHIP_MANIPULATION": {
        "code": "REL",
        "severity": 10,
        "description": (
            "Systematic infiltration and weaponization of the victim's personal "
            "social network. Attackers corrupt relationships, plant misinformation, "
            "and turn trusted people into unwitting instruments of psychological harm. "
            "This is perhaps the most sophisticated and devastating attack type."
        ),
        "psychological_mechanism": "Social network corruption — victim's support system becomes attack infrastructure",
        "behavioral_signals": [
            "Trusted relationships suddenly become distant or hostile without clear reason",
            "Friends or family repeat attacker's narratives as their own beliefs",
            "Victim receives contradictory information from different contacts",
            "Social isolation increases gradually as relationships erode",
            "Third parties take sides against victim based on planted information",
            "Victim's words and actions consistently misrepresented to others",
            "New people enter victim's network who seem aligned with attacker",
        ],
        "cognitive_biases_exploited": [
            "Social proof — 'multiple people agree, so it must be true'",
            "In-group loyalty — friends protect 'their own' against victim",
            "Attribution error — victim blamed for relationship deterioration",
        ],
        "attack_phases": [
            "Mapping — identify key relationships in victim's network",
            "Infiltration — establish contact with key network members",
            "Seeding — plant small doubts and misinformation gradually",
            "Amplification — escalate narrative against victim",
            "Weaponization — turn relationships into active instruments of harm",
            "Isolation — victim cut off from support network entirely",
        ],
        "real_world_examples": [
            "Family members told fabricated stories about victim's behavior",
            "Friends fed misinformation that alters their perception of victim",
            "Professional contacts given false information damaging reputation",
            "Romantic relationships targeted with lies to create conflict",
            "Community or group turned against victim through coordinated false narrative",
            "Victim's own words taken out of context and weaponized",
        ],
        "detection_keywords": [
            "everyone is saying", "people are worried about you",
            "your friends told me", "I heard from someone that you",
            "people think you are", "no one trusts you anymore",
            "you've changed", "everyone agrees", "they all said"
        ],
        "recovery_actions": [
            "Document all relationship changes and their timeline",
            "Identify the information source — who told whom what and when",
            "Communicate directly with affected relationships to share your perspective",
            "Seek relationships outside the compromised network",
        ],
        "author_experience_note": (
            "Relationship manipulation was the most painful attack experienced. "
            "The deliberate corruption of trusted relationships caused profound "
            "isolation. Rebuilding required identifying the information vectors "
            "and addressing each compromised relationship individually."
        )
    },

    "URGENCY_ATTACK": {
        "code": "URG",
        "severity": 7,
        "description": (
            "Artificially manufactured time pressure designed to bypass the victim's "
            "rational decision-making processes. When forced to act quickly, "
            "humans rely on instinct over analysis — attackers engineer this state deliberately."
        ),
        "psychological_mechanism": "Cognitive bypass — time pressure disables rational evaluation",
        "behavioral_signals": [
            "Extreme time constraints placed on decisions",
            "Catastrophic consequences threatened for inaction",
            "Discouragement of consultation with others before acting",
            "Pressure intensifies if victim attempts to slow down",
            "Manufactured scarcity — 'this opportunity disappears in minutes'",
            "Emotional escalation to compound time pressure",
            "Multiple simultaneous pressures to overwhelm processing capacity",
        ],
        "cognitive_biases_exploited": [
            "Loss aversion — fear of missing out or losing something",
            "Fight or flight — urgency triggers survival responses",
            "Decision fatigue — overwhelm leads to compliance",
        ],
        "attack_phases": [
            "Setup — establish context that makes urgency plausible",
            "Trigger — introduce the urgent situation",
            "Pressure — increase urgency if victim hesitates",
            "Isolation — prevent victim from consulting others",
            "Extraction — obtain action or information under pressure",
            "Disappearance — attacker disengages once objective achieved",
        ],
        "real_world_examples": [
            "Account suspension notice demanding immediate login",
            "Tax authority threatening arrest within hours",
            "Family emergency requiring immediate money transfer",
            "Exclusive deal expiring in minutes requiring payment now",
            "Security breach requiring immediate password change via link",
            "Legal threat requiring urgent response to prevent consequences",
        ],
        "detection_keywords": [
            "act now", "immediately", "within the hour", "final warning",
            "last chance", "expires soon", "urgent action required",
            "do not delay", "respond immediately", "time is running out",
            "before it's too late", "critical deadline", "emergency"
        ],
        "recovery_actions": [
            "Deliberately slow down — urgency is the attack itself",
            "Consult a trusted person before taking any action",
            "Verify the claimed situation through official channels",
            "Remember — legitimate organizations allow time for verification",
        ],
        "author_experience_note": (
            "Urgency attacks were frequently layered with other attack types "
            "to compound their effectiveness. The deliberate creation of "
            "time pressure was used to prevent rational analysis of suspicious requests."
        )
    },

    "IDENTITY_THEFT": {
        "code": "IDT",
        "severity": 10,
        "description": (
            "Theft and misuse of personal identity information — going beyond "
            "financial fraud to include reputational damage, digital persona theft, "
            "and the use of stolen identity to attack the victim's relationships "
            "and social standing."
        ),
        "psychological_mechanism": "Identity erosion — victim's sense of self and digital presence hijacked",
        "behavioral_signals": [
            "Accounts created in victim's name without their knowledge",
            "Personal information used in communications the victim did not send",
            "Victim's identity used to damage relationships with others",
            "Financial accounts accessed or opened fraudulently",
            "Digital profiles cloned and used to spread misinformation",
            "Victim's credentials used to access their own accounts",
            "Personal history weaponized in communications to others",
        ],
        "cognitive_biases_exploited": [
            "Identity anchoring — 'if it has my name it must be me'",
            "Digital trust — assumed authenticity of online profiles",
            "Reputation heuristic — past credibility trusted in new contexts",
        ],
        "attack_phases": [
            "Data collection — harvest personal information from multiple sources",
            "Profile construction — build complete identity replica",
            "Deployment — use stolen identity for specific objectives",
            "Damage — use identity to harm victim's reputation or relationships",
            "Cover — obscure the theft to maintain ongoing access",
        ],
        "real_world_examples": [
            "Social media profiles cloned to contact victim's network",
            "Personal information used to answer security questions",
            "Victim's name used to send damaging messages to contacts",
            "Financial accounts opened using stolen personal data",
            "Professional credentials misrepresented using stolen information",
            "Victim's email or phone used to impersonate them to authorities",
        ],
        "detection_keywords": [
            "is this you?", "did you send this?", "I got a message from you",
            "your account says", "someone using your name",
            "I saw your profile", "you contacted me but",
            "are you aware that", "someone claiming to be you"
        ],
        "recovery_actions": [
            "Immediately secure all accounts with strong unique passwords",
            "Enable two-factor authentication on everything",
            "Notify contacts that your identity may be compromised",
            "File reports with relevant authorities and platforms",
            "Monitor your digital footprint regularly",
        ],
        "author_experience_note": (
            "Identity theft extended beyond financial fraud to include "
            "the use of personal identity to damage relationships and reputation. "
            "The psychological impact of having one's identity weaponized "
            "against oneself is profound and lasting."
        )
    },

    "FAKE_AUTHORITY": {
        "code": "FAU",
        "severity": 8,
        "description": (
            "Impersonation of authority figures, institutions, or official bodies "
            "to compel compliance through fear, obligation, or respect. "
            "Exploits the victim's conditioning to comply with authority "
            "as a survival mechanism."
        ),
        "psychological_mechanism": "Authority compliance — deep-seated obedience to perceived power exploited",
        "behavioral_signals": [
            "Claims to represent government, law enforcement, or legal bodies",
            "Uses official-sounding language and formal communication styles",
            "Threatens serious consequences for non-compliance",
            "Requests information or action that real authorities would not ask for",
            "Creates urgency to prevent verification of credentials",
            "Uses logos, letterheads, or official formatting fraudulently",
            "Follows up with escalating 'official' pressure",
        ],
        "cognitive_biases_exploited": [
            "Authority bias — conditioned to comply with figures of power",
            "Fear response — threat of punishment overrides rational analysis",
            "Legitimacy heuristic — official appearance assumed genuine",
        ],
        "attack_phases": [
            "Identity construction — create convincing authority persona",
            "Initial contact — establish official presence",
            "Threat introduction — frame non-compliance as dangerous",
            "Pressure — escalate consequences to force compliance",
            "Extraction — obtain compliance, information, or payment",
            "Disappearance — no follow-up from 'official' body",
        ],
        "real_world_examples": [
            "IRS/tax authority threatening immediate arrest for unpaid taxes",
            "Police claiming victim is under investigation",
            "Bank security team requiring immediate account verification",
            "Immigration authority threatening visa cancellation",
            "Tech company security team claiming account breach requiring action",
            "Legal firm threatening lawsuit requiring immediate payment",
        ],
        "detection_keywords": [
            "this is the IRS", "government notice", "legal action",
            "arrest warrant", "final notice", "official warning",
            "law enforcement", "your visa", "legal consequences",
            "failure to comply", "court order", "federal investigation"
        ],
        "recovery_actions": [
            "Never respond directly — find official contact details independently",
            "Real authorities send written notice through official channels first",
            "Call the organization directly using numbers from their official website",
            "Consult a legal professional before taking any action",
        ],
        "author_experience_note": (
            "Fake authority attacks exploited conditioned responses to institutional power. "
            "The combination of official appearance and threat of severe consequences "
            "created powerful compliance pressure that required deliberate slowing down to resist."
        )
    },

    "EMOTIONAL_MANIPULATION": {
        "code": "EMO",
        "severity": 9,
        "description": (
            "Systematic exploitation of the victim's emotional responses — "
            "including love, guilt, fear, compassion, and loyalty — "
            "to override rational judgment and compel desired actions. "
            "Targets the victim's empathy as the primary vulnerability."
        ),
        "psychological_mechanism": "Empathy exploitation — victim's capacity for care weaponized against them",
        "behavioral_signals": [
            "Manufactured emotional crises requiring victim's immediate response",
            "Guilt induction for normal protective behaviors",
            "Love bombing — excessive positive emotion followed by withdrawal",
            "Victim's compassion consistently redirected toward attacker's goals",
            "Emotional blackmail — 'if you cared you would do this'",
            "Playing victim to reverse actual victim and perpetrator roles",
            "Cycles of emotional highs and lows to create dependency",
        ],
        "cognitive_biases_exploited": [
            "Empathy response — hardwired to respond to others' distress",
            "Reciprocity — emotional investment creates obligation",
            "Sunk cost — past emotional investment justifies continued compliance",
        ],
        "attack_phases": [
            "Trust building — establish genuine-seeming emotional connection",
            "Mapping — identify emotional vulnerabilities and triggers",
            "Exploitation — weaponize identified emotional responses",
            "Escalation — increase emotional intensity to deepen compliance",
            "Dependency — victim emotionally dependent on attacker's approval",
            "Control — victim's actions controlled through emotional levers",
        ],
        "real_world_examples": [
            "Fabricated personal crisis requiring victim's immediate emotional support",
            "Guilt tripping for victim's normal protective boundaries",
            "Manufactured conflict to destabilize victim's emotional state",
            "Using victim's love for others to compel compliance",
            "Emotional withdrawal as punishment for non-compliance",
            "False vulnerability to trigger victim's protective instincts",
        ],
        "detection_keywords": [
            "I thought you cared", "if you loved me", "you're being selfish",
            "I need you right now", "you're breaking my heart",
            "after everything I've done", "I'm so hurt that you",
            "you're abandoning me", "this is your fault",
            "I can't go on without", "you're the only one"
        ],
        "recovery_actions": [
            "Recognize that genuine relationships respect boundaries",
            "Identify patterns — does distress always appear when you say no?",
            "Separate compassion from compliance — you can care without complying",
            "Discuss with a trusted person outside the relationship",
        ],
        "author_experience_note": (
            "Emotional manipulation was sustained and sophisticated. "
            "The deliberate targeting of empathy and compassion as attack vectors "
            "required learning to distinguish genuine emotional need "
            "from manufactured emotional pressure."
        )
    },

    "CHARACTER_ASSASSINATION": {
        "code": "CHA",
        "severity": 10,
        "description": (
            "Systematic destruction of the victim's reputation, credibility, "
            "and social standing through deliberate spread of false information, "
            "reframing of true events, and coordinated narrative campaigns. "
            "Operates in both digital and physical social spaces simultaneously."
        ),
        "psychological_mechanism": "Reputational erasure — victim's social identity dismantled through false narrative",
        "behavioral_signals": [
            "False or distorted information spread through victim's social networks",
            "Victim's past actions reframed in maximally negative light",
            "Coordinated multiple sources spreading the same false narrative",
            "Victim's responses to attacks used as further 'evidence' against them",
            "Professional and personal reputation targeted simultaneously",
            "Anonymous or attributed false claims appearing across platforms",
            "Victim isolated as others distance themselves based on false narrative",
            "True events cherry-picked and weaponized out of context",
        ],
        "cognitive_biases_exploited": [
            "Availability heuristic — repeated exposure makes claims feel true",
            "Negativity bias — negative information weighted more heavily",
            "Social proof — multiple sources seem more credible",
            "Illusory truth effect — repeated lies feel like truth over time",
        ],
        "attack_phases": [
            "Research — gather information about victim's vulnerabilities and history",
            "Narrative construction — build false or distorted story framework",
            "Seeding — introduce narrative through trusted channels",
            "Amplification — spread through multiple nodes of victim's network",
            "Normalization — false narrative becomes accepted 'fact'",
            "Maintenance — sustain and evolve narrative to prevent recovery",
        ],
        "real_world_examples": [
            "False accusations spread through social and professional networks",
            "Private information shared publicly and framed deceptively",
            "Victim's past mistakes amplified while positive history erased",
            "Coordinated online harassment campaigns to damage reputation",
            "False professional misconduct allegations to destroy career",
            "Screenshots taken out of context to misrepresent victim's character",
            "Anonymous reports filed with institutions based on false claims",
        ],
        "detection_keywords": [
            "people are saying you", "I heard that you",
            "everyone knows what you did", "you have a reputation for",
            "multiple people told me", "it's common knowledge that you",
            "screenshots don't lie", "you can't deny that",
            "everyone has seen", "your true colors"
        ],
        "recovery_actions": [
            "Document the false narrative and its spread carefully",
            "Identify origin points — where did the false narrative begin",
            "Address directly with affected parties using clear factual evidence",
            "Build and maintain authentic relationships that can vouch for you",
            "Legal options exist for serious defamation — consult professionals",
        ],
        "author_experience_note": (
            "Character assassination was the most publicly damaging attack type. "
            "The coordinated spread of false narrative through multiple relationship "
            "networks simultaneously created an environment where the victim's "
            "credibility was systematically dismantled. Recovery required "
            "systematic identification and direct address of each false claim "
            "through documented evidence."
        )
    },
}


# ─────────────────────────────────────────────────────────────
#  DATASET CLASS
# ─────────────────────────────────────────────────────────────

class CyberShieldDataset:
    """
    Core dataset class for CyberShield.
    Manages attack records, provides analysis, and exports data.
    """

    def __init__(self):
        self.attacks = []
        self.taxonomy = ATTACK_TAXONOMY
        self._load_seed_data()

    def _load_seed_data(self):
        """Load the initial seed dataset based on documented real-world patterns."""
        seed_attacks = [

            # ── IMPERSONATION ──────────────────────────────────────────
            {
                "id": "IMP-001",
                "category": "IMPERSONATION",
                "sub_type": "Contact cloning",
                "severity": 9,
                "platform": "WhatsApp",
                "vector": "Messaging application",
                "description": "Attacker mimicked close contact's writing style to request sensitive information",
                "psychological_tactics": ["Trust exploitation", "Familiarity mimicry", "Urgency layering"],
                "behavioral_indicators": ["Matched contact's vocabulary and emoji usage", "Referenced real shared memories", "Created artificial urgency to prevent verification"],
                "victim_impact": ["Shared information believing contact was genuine", "Delayed recognition due to high authenticity"],
                "detection_difficulty": "HIGH",
                "recovery_time_days": 14,
                "lessons": "Even high-quality impersonation has micro-inconsistencies — verify through a completely separate channel",
            },
            {
                "id": "IMP-002",
                "category": "IMPERSONATION",
                "sub_type": "Authority figure cloning",
                "severity": 8,
                "platform": "Email",
                "vector": "Email spoofing",
                "description": "Attacker impersonated official institution using convincing email format",
                "psychological_tactics": ["Authority bias exploitation", "Official format mimicry", "Consequence framing"],
                "behavioral_indicators": ["Near-identical email domain", "Official logos and formatting", "Genuine-sounding reference numbers"],
                "victim_impact": ["Nearly complied before verification step caught the attack"],
                "detection_difficulty": "HIGH",
                "recovery_time_days": 2,
                "lessons": "Always verify institutional contact through official website numbers, never reply-to addresses",
            },

            # ── GASLIGHTING ────────────────────────────────────────────
            {
                "id": "GAS-001",
                "category": "GASLIGHTING",
                "sub_type": "Memory distortion",
                "severity": 10,
                "platform": "Multiple — in-person and digital",
                "vector": "Direct communication",
                "description": "Systematic denial of documented communications to make victim question memory",
                "psychological_tactics": ["Persistent denial", "Triangulation through third parties", "Emotional invalidation"],
                "behavioral_indicators": ["Claimed messages were never sent despite victim having screenshots", "Enlisted others to confirm false version", "Escalated aggression when victim produced evidence"],
                "victim_impact": ["Genuine questioning of own memory", "Emotional distress", "Temporary loss of confidence in own judgment"],
                "detection_difficulty": "VERY HIGH",
                "recovery_time_days": 90,
                "lessons": "Documentation is the primary defense against gaslighting. Screenshot everything. Date-stamp everything.",
            },
            {
                "id": "GAS-002",
                "category": "GASLIGHTING",
                "sub_type": "Reality reframing",
                "severity": 9,
                "platform": "Social network",
                "vector": "Social environment manipulation",
                "description": "Coordinated effort to make victim believe their accurate perceptions were signs of mental instability",
                "psychological_tactics": ["Perception invalidation", "Social isolation", "Identity destabilization"],
                "behavioral_indicators": ["Multiple people simultaneously questioning victim's perceptions", "Victim's emotional responses used as evidence of instability", "Gradual isolation from reality-confirming relationships"],
                "victim_impact": ["Extended period of self-doubt", "Social withdrawal", "Difficulty trusting own perceptions"],
                "detection_difficulty": "EXTREME",
                "recovery_time_days": 180,
                "lessons": "Gaslighting at scale requires coordination — identifying the common source of the false narrative is critical",
            },

            # ── PHISHING TRUSTED CONTACT ───────────────────────────────
            {
                "id": "PHT-001",
                "category": "PHISHING_TRUSTED_CONTACT",
                "sub_type": "Hacked contact delivery",
                "severity": 8,
                "platform": "Email",
                "vector": "Compromised trusted account",
                "description": "Phishing link delivered through genuinely compromised account of trusted contact",
                "psychological_tactics": ["Trust transfer", "Contextual authenticity", "Relationship leverage"],
                "behavioral_indicators": ["Email from known address with unusual link", "Content referenced genuine shared context", "Timing coincided with real ongoing communication"],
                "victim_impact": ["Nearly clicked before noticing link destination mismatch"],
                "detection_difficulty": "HIGH",
                "recovery_time_days": 1,
                "lessons": "Even messages from known addresses can be compromised. Hover over links before clicking. Verify unusual requests.",
            },
            {
                "id": "PHT-002",
                "category": "PHISHING_TRUSTED_CONTACT",
                "sub_type": "Social media clone delivery",
                "severity": 7,
                "platform": "Social media",
                "vector": "Cloned profile messaging",
                "description": "Cloned social media profile of trusted contact used to deliver malicious link",
                "psychological_tactics": ["Profile mimicry", "Relationship continuity illusion", "Casual framing"],
                "behavioral_indicators": ["New friend request from someone already connected", "Slightly different username", "Immediately sent link after connection"],
                "victim_impact": ["Recognized clone due to duplicate connection notification"],
                "detection_difficulty": "MEDIUM",
                "recovery_time_days": 1,
                "lessons": "Duplicate connection requests are a red flag. Check profile creation date and post history.",
            },

            # ── RELATIONSHIP MANIPULATION ──────────────────────────────
            {
                "id": "REL-001",
                "category": "RELATIONSHIP_MANIPULATION",
                "sub_type": "Network infiltration",
                "severity": 10,
                "platform": "Multiple — social and digital",
                "vector": "Social network compromise",
                "description": "Systematic infiltration and corruption of victim's primary support network",
                "psychological_tactics": ["Misinformation seeding", "Trust network corruption", "Isolation engineering"],
                "behavioral_indicators": ["Multiple relationships changed simultaneously without apparent cause", "Common narrative appearing across different contacts", "New people entering network with pre-formed negative view of victim"],
                "victim_impact": ["Profound social isolation", "Loss of multiple key relationships", "Extended psychological trauma"],
                "detection_difficulty": "EXTREME",
                "recovery_time_days": 365,
                "lessons": "When multiple relationships change simultaneously, a common source exists. Map the information flow to find it.",
            },
            {
                "id": "REL-002",
                "category": "RELATIONSHIP_MANIPULATION",
                "sub_type": "Misinformation campaign",
                "severity": 9,
                "platform": "Social network",
                "vector": "Coordinated false narrative",
                "description": "Coordinated spread of false information through victim's personal and professional networks",
                "psychological_tactics": ["False narrative construction", "Multi-source amplification", "Credibility destruction"],
                "behavioral_indicators": ["Same false information appearing through multiple independent channels", "Contacts reluctant to discuss source of changed perception", "Victim's denials dismissed as further evidence of the false narrative"],
                "victim_impact": ["Professional and personal reputation damage", "Loss of opportunities", "Long-term trust deficit"],
                "detection_difficulty": "VERY HIGH",
                "recovery_time_days": 270,
                "lessons": "Coordinated misinformation requires systematic address — each node of the network must be approached individually with evidence",
            },

            # ── URGENCY ATTACK ─────────────────────────────────────────
            {
                "id": "URG-001",
                "category": "URGENCY_ATTACK",
                "sub_type": "Financial emergency",
                "severity": 7,
                "platform": "Phone call",
                "vector": "Voice social engineering",
                "description": "Fabricated financial emergency requiring immediate wire transfer",
                "psychological_tactics": ["Crisis manufacturing", "Time pressure", "Verification prevention"],
                "behavioral_indicators": ["Extreme time constraint on decision", "Discouragement of family consultation", "Escalating distress to amplify urgency"],
                "victim_impact": ["Significant stress during call", "Caught the attack by insisting on verification delay"],
                "detection_difficulty": "MEDIUM",
                "recovery_time_days": 1,
                "lessons": "Any financial request with time pressure should automatically trigger maximum skepticism and verification",
            },
            {
                "id": "URG-002",
                "category": "URGENCY_ATTACK",
                "sub_type": "Account suspension threat",
                "severity": 6,
                "platform": "Email",
                "vector": "Phishing email",
                "description": "Fabricated account suspension threat requiring immediate credential entry",
                "psychological_tactics": ["Loss aversion", "Consequence amplification", "Credential harvesting"],
                "behavioral_indicators": ["Generic greeting despite claiming to know account", "Link URL did not match claimed sender", "Grammatical inconsistencies in 'official' message"],
                "victim_impact": ["Recognized attack through URL inspection before any action"],
                "detection_difficulty": "LOW",
                "recovery_time_days": 0,
                "lessons": "Account suspension notices should always be verified by logging into the actual website directly, never through links",
            },

            # ── IDENTITY THEFT ─────────────────────────────────────────
            {
                "id": "IDT-001",
                "category": "IDENTITY_THEFT",
                "sub_type": "Digital persona theft",
                "severity": 10,
                "platform": "Multiple platforms",
                "vector": "Profile cloning and credential theft",
                "description": "Systematic theft of digital identity used to damage reputation and relationships",
                "psychological_tactics": ["Identity weaponization", "Reputational damage", "Social confusion"],
                "behavioral_indicators": ["Contacts receiving messages the victim did not send", "Accounts opened in victim's name without knowledge", "Personal information appearing in communications the victim did not make"],
                "victim_impact": ["Significant reputational damage", "Relationship trust destroyed", "Extended period of identity recovery"],
                "detection_difficulty": "VERY HIGH",
                "recovery_time_days": 180,
                "lessons": "Regular monitoring of digital footprint is essential. Set up Google alerts for your own name.",
            },
            {
                "id": "IDT-002",
                "category": "IDENTITY_THEFT",
                "sub_type": "Credential theft for pivot",
                "severity": 9,
                "platform": "Online accounts",
                "vector": "Phishing and credential harvesting",
                "description": "Account credentials stolen and used as pivot point for attacks on relationships",
                "psychological_tactics": ["Account takeover", "Relationship channel hijacking", "Victim impersonation"],
                "behavioral_indicators": ["Login notifications from unknown locations", "Contacts receiving messages the victim denied sending", "Account settings changed without victim's knowledge"],
                "victim_impact": ["Lost control of communication channels temporarily", "Damage to relationships from messages sent as victim"],
                "detection_difficulty": "HIGH",
                "recovery_time_days": 30,
                "lessons": "Enable two-factor authentication on every account. Review login activity regularly.",
            },

            # ── FAKE AUTHORITY ─────────────────────────────────────────
            {
                "id": "FAU-001",
                "category": "FAKE_AUTHORITY",
                "sub_type": "Law enforcement impersonation",
                "severity": 8,
                "platform": "Phone call",
                "vector": "Voice authority impersonation",
                "description": "Caller claiming to be law enforcement threatening legal consequences for non-compliance",
                "psychological_tactics": ["Authority fear response", "Consequence amplification", "Isolation from support"],
                "behavioral_indicators": ["Instructed not to tell family", "Demanded immediate payment to avoid arrest", "Could not provide official badge number or callback number"],
                "victim_impact": ["Significant fear response during call", "Caught attack through institutional verification"],
                "detection_difficulty": "MEDIUM",
                "recovery_time_days": 1,
                "lessons": "Real law enforcement never demands immediate payment over phone. Always verify through official non-provided numbers.",
            },
            {
                "id": "FAU-002",
                "category": "FAKE_AUTHORITY",
                "sub_type": "Technical authority impersonation",
                "severity": 7,
                "platform": "Phone call and remote access",
                "vector": "Tech support scam",
                "description": "Caller claiming to be tech support detecting malware requiring immediate remote access",
                "psychological_tactics": ["Technical authority", "Fear of device compromise", "Remote access request"],
                "behavioral_indicators": ["Unsolicited contact claiming to detect problems", "Requested remote access to 'fix' the issue", "Created urgency around fictional security threat"],
                "victim_impact": ["Recognized scam before granting access"],
                "detection_difficulty": "MEDIUM",
                "recovery_time_days": 0,
                "lessons": "Legitimate tech support never calls you unsolicited. Never grant remote access to unsolicited callers.",
            },

            # ── EMOTIONAL MANIPULATION ─────────────────────────────────
            {
                "id": "EMO-001",
                "category": "EMOTIONAL_MANIPULATION",
                "sub_type": "Sustained dependency creation",
                "severity": 9,
                "platform": "Multiple — digital and in-person",
                "vector": "Relationship-based manipulation",
                "description": "Long-term emotional manipulation designed to create psychological dependency and compliance",
                "psychological_tactics": ["Love bombing", "Intermittent reinforcement", "Guilt weaponization", "Empathy exploitation"],
                "behavioral_indicators": ["Alternating periods of excessive warmth and withdrawal", "Guilt framing for normal protective behavior", "Victim's compassion consistently redirected toward attacker's goals", "Emotional crises manufactured at strategic moments"],
                "victim_impact": ["Extended period of emotional confusion", "Difficulty establishing healthy boundaries", "Recovery required therapeutic support"],
                "detection_difficulty": "VERY HIGH",
                "recovery_time_days": 270,
                "lessons": "Intermittent reinforcement creates powerful psychological bonds. Recognizing the pattern is the first step to breaking it.",
            },
            {
                "id": "EMO-002",
                "category": "EMOTIONAL_MANIPULATION",
                "sub_type": "Compassion exploitation",
                "severity": 8,
                "platform": "Messaging",
                "vector": "Manufactured crisis",
                "description": "Repeated manufactured emotional crises designed to extract resources and compliance",
                "psychological_tactics": ["Crisis manufacturing", "Compassion exploitation", "Reciprocity obligation"],
                "behavioral_indicators": ["Crisis always emerged when victim attempted to create distance", "Emotional intensity calibrated to victim's response threshold", "Each crisis required progressively more from victim"],
                "victim_impact": ["Significant emotional and practical resource drain", "Recognition came through pattern identification"],
                "detection_difficulty": "HIGH",
                "recovery_time_days": 60,
                "lessons": "When crises consistently appear at boundaries, the crisis is manufactured. Compassion is not compliance.",
            },

            # ── CHARACTER ASSASSINATION ────────────────────────────────
            {
                "id": "CHA-001",
                "category": "CHARACTER_ASSASSINATION",
                "sub_type": "Coordinated false narrative",
                "severity": 10,
                "platform": "Social network and digital platforms",
                "vector": "Multi-node narrative campaign",
                "description": "Systematic coordinated campaign to destroy victim's reputation across multiple social spheres simultaneously",
                "psychological_tactics": ["False narrative construction", "Multi-source amplification", "Illusory truth creation", "Social proof manipulation"],
                "behavioral_indicators": ["Same false narrative appearing through completely independent sources", "Victim's accurate responses dismissed as 'defensiveness'", "Professional and personal reputation targeted simultaneously", "Anonymous and identified sources both involved"],
                "victim_impact": ["Significant professional and social reputation damage", "Long-term relationship trust damage", "Extended psychological trauma from identity attack"],
                "detection_difficulty": "EXTREME",
                "recovery_time_days": 540,
                "lessons": "Coordinated character assassination requires systematic evidence-based response. Document everything. Address each node individually.",
            },
            {
                "id": "CHA-002",
                "category": "CHARACTER_ASSASSINATION",
                "sub_type": "Context manipulation",
                "severity": 9,
                "platform": "Digital platforms",
                "vector": "Screenshot weaponization",
                "description": "True information selectively extracted and reframed to create maximally damaging false impression",
                "psychological_tactics": ["Selective truth weaponization", "Context removal", "Amplification through network"],
                "behavioral_indicators": ["Real statements or actions presented without context", "Worst possible interpretation presented as obvious meaning", "Target audience chosen to maximize reputational impact"],
                "victim_impact": ["Difficult to defend against — the information was technically true", "Required extensive context-restoration effort"],
                "detection_difficulty": "VERY HIGH",
                "recovery_time_days": 180,
                "lessons": "Context is everything. Selective truth is still deception. Counter with full context, documented timeline, and character witnesses.",
            },
        ]

        for attack in seed_attacks:
            attack["logged_at"] = "2026-03-18"
            attack["source"] = "Author personal experience — Ismaeel Khan"
            self.attacks.append(attack)

    def add_attack(self, category, sub_type, severity, platform, vector, description,
                   psychological_tactics, behavioral_indicators, victim_impact,
                   detection_difficulty, recovery_time_days, lessons):
        """Add a new attack record to the dataset."""
        if category not in self.taxonomy:
            print(f"Unknown category: {category}. Valid: {list(self.taxonomy.keys())}")
            return None

        attack_id = f"{self.taxonomy[category]['code']}-{len([a for a in self.attacks if a['category'] == category]) + 1:03d}"
        record = {
            "id": attack_id,
            "category": category,
            "sub_type": sub_type,
            "severity": severity,
            "platform": platform,
            "vector": vector,
            "description": description,
            "psychological_tactics": psychological_tactics,
            "behavioral_indicators": behavioral_indicators,
            "victim_impact": victim_impact,
            "detection_difficulty": detection_difficulty,
            "recovery_time_days": recovery_time_days,
            "lessons": lessons,
            "logged_at": datetime.now().strftime("%Y-%m-%d"),
            "source": "User contribution",
        }
        self.attacks.append(record)
        print(f"Attack logged: {attack_id}")
        return attack_id

    def analyze_text(self, text):
        """Analyze text against all known attack patterns."""
        text_lower = text.lower()
        matches = {}
        for category, data in self.taxonomy.items():
            found = []
            for keyword in data.get("detection_keywords", []):
                if keyword.lower() in text_lower:
                    found.append(keyword)
            if found:
                matches[category] = {
                    "attack_type": category.replace("_", " ").title(),
                    "matched_keywords": found,
                    "severity": data["severity"],
                    "psychological_mechanism": data["psychological_mechanism"],
                    "immediate_actions": data["recovery_actions"][:2],
                }
        return matches

    def get_statistics(self):
        """Generate comprehensive dataset statistics."""
        if not self.attacks:
            return {}
        category_counts = Counter(a["category"] for a in self.attacks)
        severity_scores = defaultdict(list)
        for a in self.attacks:
            severity_scores[a["category"]].append(a["severity"])
        recovery_times = [a["recovery_time_days"] for a in self.attacks]
        platform_counts = Counter(a["platform"] for a in self.attacks)
        difficulty_counts = Counter(a["detection_difficulty"] for a in self.attacks)
        return {
            "total_attacks": len(self.attacks),
            "total_categories": len(set(a["category"] for a in self.attacks)),
            "category_distribution": dict(category_counts),
            "average_severity_by_category": {
                cat: round(sum(scores) / len(scores), 1)
                for cat, scores in severity_scores.items()
            },
            "average_recovery_days": round(sum(recovery_times) / len(recovery_times), 1),
            "max_recovery_days": max(recovery_times),
            "platform_distribution": dict(platform_counts),
            "detection_difficulty_distribution": dict(difficulty_counts),
            "highest_severity_attacks": sorted(
                self.attacks, key=lambda x: x["severity"], reverse=True
            )[:3],
        }

    def search(self, query):
        """Search attacks by keyword."""
        query_lower = query.lower()
        results = []
        for attack in self.attacks:
            searchable = (
                attack.get("description", "") + " " +
                attack.get("sub_type", "") + " " +
                attack.get("category", "") + " " +
                " ".join(attack.get("psychological_tactics", [])) + " " +
                " ".join(attack.get("behavioral_indicators", [])) + " " +
                attack.get("author_experience_note", "")
            ).lower()
            if query_lower in searchable:
                results.append(attack)
        return results

    def get_by_category(self, category):
        """Get all attacks in a specific category."""
        return [a for a in self.attacks if a["category"] == category]

    def export_json(self, filepath="cybershield_dataset.json"):
        """Export full dataset to JSON."""
        export_data = {
            "metadata": {
                "name": "CyberShield Dataset",
                "version": "1.0.0",
                "author": "Ismaeel Khan",
                "description": "World's first labeled dataset of psychological cyber attacks",
                "total_records": len(self.attacks),
                "categories": len(self.taxonomy),
                "created": "2026-03-18",
                "github": "github.com/Ismaeel-Jr/cybershield",
                "license": "MIT",
                "note": "Built from direct personal experience of coordinated psychological cyber operations",
            },
            "taxonomy": {k: {
                "code": v["code"],
                "severity": v["severity"],
                "description": v["description"],
                "psychological_mechanism": v["psychological_mechanism"],
            } for k, v in self.taxonomy.items()},
            "attacks": self.attacks,
            "statistics": self.get_statistics(),
        }
        with open(filepath, "w") as f:
            json.dump(export_data, f, indent=2)
        print(f"Dataset exported to: {filepath}")
        return filepath


# ─────────────────────────────────────────────────────────────
#  REPORT GENERATOR
# ─────────────────────────────────────────────────────────────

def generate_report(dataset):
    """Generate a full analysis report."""
    stats = dataset.get_statistics()
    print("\n" + "=" * 65)
    print("   CYBERSHIELD — PSYCHOLOGICAL ATTACK DATASET REPORT")
    print("   Author: Ismaeel Khan | github.com/Ismaeel-Jr")
    print("=" * 65)
    print(f"\n  Total attacks documented : {stats['total_attacks']}")
    print(f"  Attack categories        : {stats['total_categories']}")
    print(f"  Avg recovery time        : {stats['average_recovery_days']} days")
    print(f"  Longest recovery         : {stats['max_recovery_days']} days")
    print("\n  ATTACK DISTRIBUTION BY CATEGORY:")
    for cat, count in sorted(stats["category_distribution"].items(), key=lambda x: -x[1]):
        severity = stats["average_severity_by_category"].get(cat, 0)
        bar = "█" * count
        print(f"  {cat[:30]:<30} {bar} ({count}) | Avg severity: {severity}/10")
    print("\n  DETECTION DIFFICULTY:")
    for diff, count in sorted(stats["detection_difficulty_distribution"].items()):
        print(f"  {diff:<12} : {count} attacks")
    print("\n  PLATFORM DISTRIBUTION:")
    for platform, count in sorted(stats["platform_distribution"].items(), key=lambda x: -x[1]):
        print(f"  {platform:<30} : {count} attacks")
    print("\n  TOP 3 HIGHEST SEVERITY ATTACKS:")
    for a in stats["highest_severity_attacks"]:
        print(f"  [{a['id']}] {a['sub_type']} — Severity: {a['severity']}/10")
        print(f"          Recovery: {a['recovery_time_days']} days")
    print("\n" + "=" * 65)
    print("  Built from 5 years of direct personal experience.")
    print("  Every record is real. Every lesson was lived.")
    print("=" * 65 + "\n")


# ─────────────────────────────────────────────────────────────
#  MAIN DEMO
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n🛡️  Initializing CyberShield Dataset...\n")
    ds = CyberShieldDataset()

    # Generate full report
    generate_report(ds)

    # Demo: analyze a real attack text
    print("\n🔍 LIVE TEXT ANALYSIS DEMO:")
    print("-" * 65)
    test_text = """
    URGENT: This is the government security office. We have detected
    suspicious activity on your account. You must verify your identity
    immediately or your account will be suspended within 2 hours.
    Do not tell anyone about this notice. Click here to verify now.
    I thought you cared about protecting yourself. Everyone knows
    your account has been compromised. You're imagining that this
    is not real - this is an official notice.
    """
    print(f"Text: {test_text[:120]}...")
    print()
    matches = ds.analyze_text(test_text)
    if matches:
        print(f"  Attack types detected: {len(matches)}")
        for cat, data in matches.items():
            print(f"\n  [{data['attack_type']}]")
            print(f"  Severity     : {data['severity']}/10")
            print(f"  Mechanism    : {data['psychological_mechanism']}")
            print(f"  Keywords hit : {data['matched_keywords']}")
            print(f"  Action 1     : {data['immediate_actions'][0]}")
            print(f"  Action 2     : {data['immediate_actions'][1]}")

    # Export dataset
    print("\n📤 Exporting dataset...")
    ds.export_json("/home/claude/cybershield/data/cybershield_dataset.json")
    print("\n✅ CyberShield v1.0 fully operational.")
    print("   Records:", len(ds.attacks))
    print("   Categories:", len(ds.taxonomy))
    print("   github.com/Ismaeel-Jr/cybershield\n")
