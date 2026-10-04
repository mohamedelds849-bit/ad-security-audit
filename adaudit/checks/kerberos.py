"""Kerberos settings: pre-authentication, service accounts, delegation, krbtgt."""
from ..engine import Check, register
from . import enabled_users, label, privileged_map


@register
class PreauthDisabled(Check):
    id = "AD-KRB-001"
    title = "Comptes sans pré-authentification Kerberos"
    severity = "high"
    category = "kerberos"
    effort = "quick"
    why = ("Sans pré-authentification, le contrôleur de domaine renvoie à n'importe qui une "
           "réponse chiffrée avec le mot de passe du compte, qui peut ensuite être attaquée "
           "hors ligne sans laisser d'échec de connexion.")
    remediation = ("Décocher « Ne pas exiger de pré-authentification Kerberos » "
                   "(Set-ADAccountControl -DoesNotRequirePreAuth $false) puis changer le mot de "
                   "passe du compte. Documenter toute exception applicative.")
    references = [
        "ANSSI vuln_kerberos_properties_preauth — Comptes sans préauthentification Kerberos",
        "ANSSI vuln_kerberos_properties_preauth_priv — Comptes privilégiés sans préauthentification",
    ]
    mitre = [("T1558.004", "Steal or Forge Kerberos Tickets: AS-REP Roasting")]

    def evaluate(self, d, cfg):
        pmap = privileged_map(d, cfg)
        ev = []
        for u in enabled_users(d):
            if u["doesNotRequirePreAuth"]:
                tag = " (compte PRIVILÉGIÉ)" if u["samAccountName"].lower() in pmap else ""
                ev.append(f"{label(u)} : pré-authentification désactivée{tag}")
        return ev


@register
class OldServiceAccountPasswords(Check):
    id = "AD-KRB-002"
    title = "Comptes de service (SPN) avec un mot de passe ancien"
    severity = "high"
    category = "kerberos"
    effort = "90d"
    why = ("Tout utilisateur du domaine peut obtenir un ticket chiffré avec le mot de passe "
           "d'un compte de service. Un mot de passe humain, ancien et jamais changé est "
           "vulnérable à un cassage hors ligne.")
    remediation = ("Migrer vers des gMSA (Group Managed Service Accounts : mot de passe "
                   "aléatoire de 120 caractères changé automatiquement). À défaut : mot de passe "
                   ">= 25 caractères, renouvelé chaque année, AES uniquement, droits minimaux.")
    references = [
        "Microsoft — Group Managed Service Accounts overview (Microsoft Learn)",
        "ANSSI vuln_kerberos_properties_encryption — Algorithmes de chiffrement des comptes de service",
    ]
    mitre = [("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting")]

    def evaluate(self, d, cfg):
        limit = cfg["thresholds"]["spn_password_max_days"]
        ev = []
        for u in enabled_users(d):
            if not u["servicePrincipalNames"]:
                continue
            age = d.age_days(u["pwdLastSet"])
            if age is None or age > limit:
                age_txt = "jamais défini" if age is None else f"{age} jours"
                ev.append(f"{label(u)} : SPN {u['servicePrincipalNames'][0]}"
                          f"{' (+%d)' % (len(u['servicePrincipalNames']) - 1) if len(u['servicePrincipalNames']) > 1 else ''}"
                          f", mot de passe âgé de {age_txt}")
        return ev


@register
class UnconstrainedDelegation(Check):
    id = "AD-KRB-003"
    title = "Délégation Kerberos non contrainte (hors contrôleurs de domaine)"
    severity = "critical"
    category = "kerberos"
    effort = "30d"
    why = ("Un serveur en délégation non contrainte reçoit et garde en mémoire les tickets des "
           "utilisateurs qui s'y connectent, y compris ceux des administrateurs. Sa "
           "compromission expose ces identités.")
    remediation = ("Remplacer par une délégation contrainte (ou basée sur les ressources) "
                   "limitée aux services nécessaires, ou la supprimer. Protéger les comptes "
                   "d'administration avec Protected Users / « sensible et ne peut pas être "
                   "délégué ». Seuls les DC doivent avoir ce réglage (par défaut).")
    references = [
        "ANSSI vuln_delegation_t4d — Délégation d'authentification non contrainte",
        "Microsoft — Kerberos Constrained Delegation overview (Microsoft Learn)",
    ]
    mitre = [("T1558", "Steal or Forge Kerberos Tickets"),
             ("T1550.003", "Use Alternate Authentication Material: Pass the Ticket")]

    def evaluate(self, d, cfg):
        ev = [f"{c['name']} (ordinateur) : TrustedForDelegation"
              for c in d.computers
              if c["enabled"] and c["trustedForDelegation"] and not c["isDomainController"]]
        ev += [f"{label(u)} (utilisateur) : TrustedForDelegation"
               for u in enabled_users(d) if u["trustedForDelegation"]]
        return ev


@register
class KrbtgtPasswordAge(Check):
    id = "AD-KRB-004"
    title = "Secret du compte krbtgt trop ancien"
    severity = "high"
    category = "kerberos"
    effort = "30d"
    why = ("Le secret du compte krbtgt chiffre et signe les tickets d'authentification (TGT) "
           "de tout le domaine. S'il a été "
           "volé un jour, il reste exploitable tant qu'il n'est pas renouvelé. Le changer "
           "régulièrement limite cette fenêtre.")
    remediation = ("Renouveler le mot de passe krbtgt deux fois, en laissant passer au moins "
                   "la durée de vie maximale d'un ticket (10 h par défaut) et la réplication "
                   "complète entre les deux changements. Utiliser le script officiel Microsoft "
                   "et planifier un renouvellement au moins annuel (ici : tous les 180 jours).")
    references = [
        "ANSSI vuln_krbtgt — Mot de passe du compte krbtgt inchangé depuis plus d'un an",
        "Microsoft — AD Forest Recovery: resetting the krbtgt password (Microsoft Learn)",
    ]
    mitre = [("T1558.001", "Steal or Forge Kerberos Tickets: Golden Ticket")]

    def evaluate(self, d, cfg):
        limit = cfg["thresholds"]["krbtgt_max_days"]
        age = d.age_days(d.krbtgt["pwdLastSet"])
        if age > limit:
            return [f"krbtgt : dernier changement le {d.krbtgt['pwdLastSet']:%Y-%m-%d} "
                    f"({age} jours, attendu <= {limit})"]
        return []
