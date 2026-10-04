"""User account hygiene."""
from ..engine import Check, register
from . import compile_hint_regex, enabled_users, label

MASK = "********"


@register
class StaleEnabledAccounts(Check):
    id = "AD-ACC-001"
    title = "Comptes actifs inutilisés depuis longtemps"
    severity = "medium"
    category = "accounts"
    effort = "quick"
    why = ("Un compte actif que plus personne n'utilise (ancien salarié, stagiaire, test) "
           "n'est surveillé par personne : son utilisation par un tiers passerait inaperçue.")
    remediation = ("Mettre en place une revue trimestrielle avec les RH : désactiver les "
                   "comptes sans connexion depuis plus de 180 jours, les déplacer dans une OU "
                   "« Désactivés », puis les supprimer après une période de rétention.")
    references = [
        "ANSSI vuln_user_accounts_dormant — Nombre important de comptes actifs inutilisés",
        "CIS Controls v8 — 5.3 Disable Dormant Accounts",
    ]
    mitre = [("T1078.002", "Valid Accounts: Domain Accounts")]

    def evaluate(self, d, cfg):
        limit = cfg["thresholds"]["stale_days"]
        ev = []
        for u in enabled_users(d):
            if u["isBuiltinGuest"]:
                continue  # covered by AD-ACC-002
            age = d.age_days(u["lastLogon"])
            if age is None:
                created = d.age_days(u["whenCreated"])
                if created is None or created > limit:
                    ev.append(f"{label(u)} : jamais connecté"
                              + (f" (créé il y a {created} jours)" if created is not None else ""))
            elif age > limit:
                ev.append(f"{label(u)} : dernière connexion il y a {age} jours")
        return ev


@register
class GuestEnabled(Check):
    id = "AD-ACC-002"
    title = "Compte Invité (Guest) activé"
    severity = "high"
    category = "accounts"
    effort = "quick"
    why = ("Le compte Invité intégré permet un accès sans identité nominative. Il ne doit "
           "jamais servir dans un domaine.")
    remediation = "Désactiver le compte Invité (RID 501) et vérifier qu'aucun service n'en dépend."
    references = [
        "ANSSI vuln_guest — Compte Invité actif",
        "CIS Benchmark Windows Server — Accounts: Guest account status = Disabled",
    ]
    mitre = [("T1078.001", "Valid Accounts: Default Accounts")]

    def evaluate(self, d, cfg):
        return [f"{label(u)} : compte Invité intégré activé"
                for u in d.users if u["isBuiltinGuest"] and u["enabled"]]


@register
class PasswordInDescription(Check):
    id = "AD-ACC-003"
    title = "Mot de passe probable dans le champ Description"
    severity = "high"
    category = "accounts"
    effort = "quick"
    why = ("Le champ Description est lisible par tous les utilisateurs authentifiés du "
           "domaine. Un mot de passe noté là est en pratique public dans l'entreprise.")
    remediation = ("Effacer la valeur, considérer le mot de passe comme compromis et le "
                   "changer immédiatement. Stocker les secrets dans un coffre (gestionnaire de "
                   "mots de passe d'équipe), jamais dans l'annuaire.")
    references = [
        "Microsoft — attribut description lisible par Authenticated Users (schéma AD par défaut)",
        "CIS Controls v8 — 3.11 Encrypt Sensitive Data at Rest (principe)",
    ]
    mitre = [("T1552", "Unsecured Credentials")]

    def evaluate(self, d, cfg):
        rx = compile_hint_regex(cfg.get("password_hint_patterns", []))
        ev = []
        for u in d.users:
            m = rx.search(u["description"] or "")
            if m:
                # Never echo the value: only the keyword and a fixed-length mask.
                ev.append(f"{label(u)} : description contient « {m.group(1).lower()} » suivi "
                          f"d'une valeur (masquée : {MASK}) - à vérifier manuellement")
        return ev


@register
class PasswordNotRequired(Check):
    id = "AD-ACC-004"
    title = "Comptes avec l'option « mot de passe non requis »"
    severity = "medium"
    category = "accounts"
    effort = "quick"
    why = ("Le drapeau PASSWD_NOTREQD autorise un mot de passe vide, quelle que soit la "
           "politique du domaine. Il est souvent laissé par des scripts de création.")
    remediation = ("Retirer le drapeau (Set-ADAccountControl -PasswordNotRequired $false), "
                   "puis forcer un nouveau mot de passe conforme.")
    references = [
        "Microsoft — userAccountControl flag PASSWD_NOTREQD (0x0020)",
    ]
    mitre = [("T1078.002", "Valid Accounts: Domain Accounts")]

    def evaluate(self, d, cfg):
        return [f"{label(u)} : PASSWD_NOTREQD présent"
                for u in enabled_users(d) if u["passwordNotRequired"]]
