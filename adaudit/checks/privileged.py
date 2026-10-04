"""Privileged accounts and groups (tier 0)."""
from ..engine import Check, register
from . import KRBTGT, fmt_groups, label, privileged_map

# Nesting that exists by default in every AD domain and must not be reported.
DEFAULT_NESTING = {
    ("administrators", "domain admins"),
    ("administrators", "enterprise admins"),
}


@register
class TooManyDomainAdmins(Check):
    id = "AD-PRIV-001"
    title = "Trop de membres dans Domain Admins"
    severity = "high"
    category = "privileged"
    effort = "30d"
    why = ("Chaque compte Domain Admins peut prendre le contrôle complet du domaine. Plus "
           "ils sont nombreux, plus il y a de chances qu'un seul soit compromis.")
    remediation = ("Garder 2 ou 3 comptes d'administration dédiés (jamais le compte "
                   "bureautique quotidien). Déléguer les tâches courantes (réinitialiser un mot "
                   "de passe, joindre un poste) via des groupes à droits limités sur des OU.")
    references = [
        "ANSSI vuln_privileged_members — Nombre important de membres des groupes privilégiés",
        "Microsoft — Best Practices for Securing Active Directory, Appendix B / D",
    ]
    mitre = [("T1078.002", "Valid Accounts: Domain Accounts")]

    def evaluate(self, d, cfg):
        if d.group("Domain Admins") is None:
            return []
        members, _ = d.expand("Domain Admins")
        active = sorted(label(d.user(m)) for m in members
                        if d.user(m) is not None and d.user(m)["enabled"])
        mx = cfg["thresholds"]["max_domain_admins"]
        if len(active) <= mx:
            return []
        return [f"{len(active)} comptes actifs effectifs (attendu <= {mx}) : " + ", ".join(active)]


@register
class NestedPrivilegedGroups(Check):
    id = "AD-PRIV-002"
    title = "Groupes imbriqués dans des groupes privilégiés"
    severity = "medium"
    category = "privileged"
    effort = "30d"
    why = ("Un groupe ordinaire imbriqué dans un groupe d'administration donne des droits "
           "d'administrateur à ses membres sans que cela soit visible dans la console. Les "
           "gestionnaires de ce groupe deviennent de fait administrateurs du domaine.")
    remediation = ("Mettre les comptes d'administration directement dans le groupe privilégié "
                   "et retirer les groupes imbriqués non standard. Revoir qui gère les groupes "
                   "retirés.")
    references = [
        "ANSSI vuln_privileged_members — Nombre important de membres des groupes privilégiés",
        "Microsoft — Best Practices for Securing Active Directory, Appendix B",
    ]
    mitre = [("T1078.002", "Valid Accounts: Domain Accounts")]

    def evaluate(self, d, cfg):
        ev = []
        for pg in cfg.get("privileged_groups", []):
            g = d.group(pg)
            if g is None:
                continue
            for m in g["members"]:
                if m["type"] != "group":
                    continue
                if (pg.lower(), m["name"].lower()) in DEFAULT_NESTING:
                    continue
                users, _ = d.expand(m["name"])
                ev.append(f"{g['name']} <- {m['name']} ({len(users)} utilisateur(s) hérite(nt) des droits)")
        return ev


@register
class PrivilegedNotProtected(Check):
    id = "AD-PRIV-003"
    title = "Comptes privilégiés hors Protected Users ou délégables"
    severity = "high"
    category = "privileged"
    effort = "30d"
    why = ("Le groupe Protected Users et l'option « Le compte est sensible et ne peut pas être "
           "délégué » limitent ce qu'un service ou un poste compromis peut faire avec "
           "l'identité d'un administrateur (pas de délégation, pas de NTLM, pas de mise en "
           "cache des identifiants pour Protected Users).")
    remediation = ("Cocher « sensible et ne peut pas être délégué » sur tous les comptes "
                   "d'administration et les ajouter à Protected Users après un test (Protected "
                   "Users interdit NTLM et le chiffrement faible : vérifier les applications). "
                   "Ne jamais y mettre de comptes de service.")
    references = [
        "ANSSI vuln_protected_users — Comptes privilégiés non membres du groupe Protected Users",
        "Microsoft — Protected Users Security Group (Microsoft Learn)",
    ]
    mitre = [("T1550.003", "Use Alternate Authentication Material: Pass the Ticket"),
             ("T1550.002", "Use Alternate Authentication Material: Pass the Hash")]

    def evaluate(self, d, cfg):
        pmap = privileged_map(d, cfg)
        pu_name = cfg.get("protected_users_group", "Protected Users")
        protected = d.expand(pu_name)[0] if d.group(pu_name) else set()
        ev = []
        for name in sorted(pmap):
            u = d.user(name)
            if u["servicePrincipalNames"]:
                continue  # service accounts are handled by AD-PRIV-006, not Protected Users
            missing = []
            if name not in protected:
                missing.append("hors Protected Users")
            if not u["accountNotDelegated"]:
                missing.append("délégable (option « sensible » non cochée)")
            if missing:
                ev.append(f"{label(u)} [{fmt_groups(pmap[name])}] : " + " ; ".join(missing))
        return ev


@register
class PrivilegedPasswordNeverExpires(Check):
    id = "AD-PRIV-004"
    title = "Comptes privilégiés dont le mot de passe n'expire jamais"
    severity = "medium"
    category = "privileged"
    effort = "quick"
    why = ("Un mot de passe d'administrateur qui ne change jamais reste valable des années "
           "s'il a fuité (ancien prestataire, ancien salarié, fichier oublié).")
    remediation = ("Retirer l'option « Le mot de passe n'expire jamais » des comptes "
                   "privilégiés et appliquer une Fine-Grained Password Policy dédiée aux "
                   "administrateurs (longueur >= 16, renouvellement planifié).")
    references = [
        "ANSSI vuln_dont_expire_priv — Comptes privilégiés dont le mot de passe n'expire jamais",
        "ANSSI vuln_password_change_priv — mot de passe privilégié inchangé depuis plus de 3 ans",
    ]
    mitre = [("T1078.002", "Valid Accounts: Domain Accounts")]

    def evaluate(self, d, cfg):
        pmap = privileged_map(d, cfg)
        ev = []
        for name in sorted(pmap):
            u = d.user(name)
            if u["passwordNeverExpires"]:
                age = d.age_days(u["pwdLastSet"])
                age_txt = "jamais défini" if age is None else f"{age} jours"
                ev.append(f"{label(u)} [{fmt_groups(pmap[name])}] : n'expire jamais, âge du mot de passe {age_txt}")
        return ev


@register
class AdminCountOrphans(Check):
    id = "AD-PRIV-005"
    title = "Comptes adminCount=1 qui ne sont plus privilégiés"
    severity = "low"
    category = "privileged"
    effort = "quick"
    why = ("adminCount=1 indique un ancien membre d'un groupe protégé. Le compte garde les "
           "permissions figées par AdminSDHolder (héritage désactivé) : il échappe aux "
           "délégations normales et brouille l'inventaire des vrais administrateurs.")
    remediation = ("Vérifier que le compte n'a plus besoin de privilèges, remettre adminCount "
                   "à 0 et réactiver l'héritage des permissions sur l'objet. Supprimer le "
                   "compte s'il n'est plus utilisé.")
    references = [
        "Microsoft — AdminSDHolder, Protected Groups and SDPROP (Microsoft Learn)",
        "ANSSI vuln_privileged_members_no_admincount (contrôle inverse : membres sans adminCount)",
    ]
    mitre = []  # no direct ATT&CK technique: hygiene / inventory issue

    def evaluate(self, d, cfg):
        pmap = d.privileged_users(cfg.get("privileged_groups", []))
        ev = []
        for u in d.users:
            name = u["samAccountName"].lower()
            if name == KRBTGT or u["adminCount"] != 1:
                continue
            if name not in pmap:
                state = "actif" if u["enabled"] else "désactivé"
                ev.append(f"{label(u)} ({state}) : adminCount=1 mais membre d'aucun groupe privilégié")
        return ev


@register
class PrivilegedServiceAccounts(Check):
    id = "AD-PRIV-006"
    title = "Comptes de service (SPN) membres de groupes privilégiés"
    severity = "critical"
    category = "privileged"
    effort = "30d"
    why = ("Un compte qui porte un SPN peut faire l'objet d'une demande de ticket de service "
           "par n'importe quel utilisateur du domaine, puis d'une tentative de cassage hors "
           "ligne de son mot de passe. S'il est administrateur, un mot de passe faible suffit "
           "à perdre tout le domaine.")
    remediation = ("Retirer le compte de service des groupes privilégiés et ne lui donner que "
                   "les droits nécessaires sur ses serveurs. Le remplacer par un gMSA (mot de "
                   "passe de 120 caractères renouvelé automatiquement).")
    references = [
        "ANSSI vuln_spn_priv — Comptes privilégiés avec SPN",
        "Microsoft — Group Managed Service Accounts overview (Microsoft Learn)",
    ]
    mitre = [("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting")]

    def evaluate(self, d, cfg):
        pmap = privileged_map(d, cfg)
        ev = []
        for name in sorted(pmap):
            u = d.user(name)
            if u["servicePrincipalNames"]:
                ev.append(f"{label(u)} [{fmt_groups(pmap[name])}] : {len(u['servicePrincipalNames'])} SPN")
        return ev


@register
class GroupNestingLoops(Check):
    id = "AD-PRIV-007"
    title = "Boucles d'imbrication de groupes"
    severity = "low"
    category = "accounts"
    effort = "quick"
    why = ("Une boucle (A membre de B, B membre de A) rend l'appartenance réelle difficile à "
           "comprendre et peut cacher des droits hérités. Elle signale une gestion des "
           "groupes sans revue.")
    remediation = "Casser la boucle en retirant l'un des liens, puis revoir le besoin métier."
    references = ["ANSSI vuln_group_loop — Présences de boucles d'imbrication de groupes"]
    mitre = []

    def evaluate(self, d, cfg):
        graph = {g["name"].lower(): [m["name"].lower() for m in g["members"] if m["type"] == "group"]
                 for g in d.groups}
        names = {g["name"].lower(): g["name"] for g in d.groups}
        cycles, seen = [], set()
        WHITE, GREY, BLACK = 0, 1, 2
        color = {n: WHITE for n in graph}
        # Iterative DFS (no recursion limit on deep or hostile nesting).
        for root in sorted(graph):
            if color[root] != WHITE:
                continue
            stack = [(root, iter(graph[root]))]
            path = [root]
            color[root] = GREY
            while stack:
                node, children = stack[-1]
                nxt = next(children, None)
                if nxt is None:
                    stack.pop()
                    path.pop()
                    color[node] = BLACK
                    continue
                if nxt not in graph:
                    continue
                if color[nxt] == GREY:
                    cyc = path[path.index(nxt):]
                    key = frozenset(cyc)
                    if key not in seen:
                        seen.add(key)
                        cycles.append(cyc + [nxt])
                elif color[nxt] == WHITE:
                    color[nxt] = GREY
                    path.append(nxt)
                    stack.append((nxt, iter(graph[nxt])))
        return [" -> ".join(names.get(x, x) for x in c) for c in cycles]

