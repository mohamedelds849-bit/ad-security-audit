"""Domain password and lockout policy (Default Domain Policy)."""
from ..engine import Check, register


@register
class WeakPasswordPolicy(Check):
    id = "AD-PWD-001"
    title = "Politique de mot de passe du domaine trop faible"
    severity = "high"
    category = "accounts"
    effort = "30d"
    why = ("Des mots de passe courts, sans historique ou stockés de façon réversible sont "
           "plus faciles à deviner ou à retrouver. C'est la première barrière de tous les comptes.")
    remediation = ("Dans la Default Domain Policy (ou une Fine-Grained Password Policy) : longueur "
                   "minimale >= 12 (14 recommandé), complexité activée, historique >= 12 (24 "
                   "recommandé), chiffrement réversible désactivé. Préférer des phrases de passe "
                   "et communiquer le changement aux utilisateurs avant de l'appliquer.")
    references = [
        "ANSSI — Recommandations relatives à l'authentification multifacteur et aux mots de passe (2021)",
        "CIS Benchmark Windows Server — Account Policies > Password Policy",
        "Microsoft — Password policy recommendations (Microsoft Learn)",
    ]
    mitre = [("T1110.001", "Brute Force: Password Guessing"),
             ("T1110.003", "Brute Force: Password Spraying")]

    def evaluate(self, d, cfg):
        p, th = d.policy, cfg["thresholds"]
        ev = []
        if p["minPasswordLength"] < th["min_password_length"]:
            ev.append(f"Longueur minimale = {p['minPasswordLength']} (attendu >= {th['min_password_length']})")
        if not p["complexityEnabled"]:
            ev.append("Complexité des mots de passe désactivée")
        if p["passwordHistoryCount"] < th["min_password_history"]:
            ev.append(f"Historique = {p['passwordHistoryCount']} (attendu >= {th['min_password_history']})")
        if p["reversibleEncryptionEnabled"]:
            ev.append("Stockage des mots de passe avec chiffrement réversible activé")
        return ev


@register
class NoAccountLockout(Check):
    id = "AD-PWD-002"
    title = "Verrouillage de compte absent ou trop permissif"
    severity = "high"
    category = "accounts"
    effort = "quick"
    why = ("Sans verrouillage après plusieurs échecs, rien ne limite les essais de mots de "
           "passe en ligne sur tous les comptes du domaine.")
    remediation = ("Fixer un seuil de verrouillage entre 5 et 10 tentatives, une durée et une "
                   "fenêtre d'observation d'au moins 15 minutes. Surveiller l'événement 4740 "
                   "(compte verrouillé) pour détecter les vagues d'échecs.")
    references = [
        "CIS Benchmark Windows Server — Account Policies > Account Lockout Policy",
        "Microsoft Security Baseline — Account lockout threshold = 10",
    ]
    mitre = [("T1110.001", "Brute Force: Password Guessing"),
             ("T1110.003", "Brute Force: Password Spraying")]

    def evaluate(self, d, cfg):
        p, mx = d.policy, cfg["thresholds"]["max_lockout_threshold"]
        if p["lockoutThreshold"] == 0:
            return ["Seuil de verrouillage = 0 (les comptes ne se verrouillent jamais)"]
        ev = []
        if p["lockoutThreshold"] > mx:
            ev.append(f"Seuil de verrouillage = {p['lockoutThreshold']} (attendu <= {mx})")
        if p["lockoutDurationMinutes"] < 15 and p["lockoutDurationMinutes"] != 0:
            ev.append(f"Durée de verrouillage = {p['lockoutDurationMinutes']} min (attendu >= 15)")
        return ev
