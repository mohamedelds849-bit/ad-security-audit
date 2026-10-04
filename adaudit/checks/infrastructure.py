"""Computers, GPO-level network hardening and trusts."""
from ..engine import Check, register


@register
class LapsNotDeployed(Check):
    id = "AD-INF-001"
    title = "LAPS absent ou couverture incomplète"
    severity = "high"
    category = "infrastructure"
    effort = "30d"
    why = ("Sans LAPS, le compte administrateur local a souvent le même mot de passe sur tous "
           "les postes : un seul poste compromis donne l'accès administrateur à tous les autres.")
    remediation = ("Déployer Windows LAPS (intégré à Windows depuis avril 2023) par GPO : "
                   "mot de passe unique, aléatoire et renouvelé par machine, stocké dans l'AD "
                   "et lisible uniquement par un groupe d'administration dédié.")
    references = [
        "Microsoft — Windows LAPS overview (Microsoft Learn)",
        "CIS Benchmark Windows Server — section LAPS",
    ]
    mitre = [("T1078.003", "Valid Accounts: Local Accounts"),
             ("T1550.002", "Use Alternate Authentication Material: Pass the Hash")]

    def evaluate(self, d, cfg):
        ev = []
        if not d.gpo["lapsDeployed"]:
            ev.append("Aucune GPO LAPS déclarée dans l'export")
        members = [c for c in d.computers if c["enabled"] and not c["isDomainController"]]
        if members:
            covered = sum(1 for c in members if c["lapsPasswordSet"])
            ratio = covered / len(members)
            if ratio < cfg["thresholds"]["laps_min_coverage"]:
                ev.append(f"Couverture LAPS : {covered}/{len(members)} ordinateurs membres "
                          f"({ratio:.0%}, attendu >= {cfg['thresholds']['laps_min_coverage']:.0%})")
        return ev


@register
class ObsoleteOperatingSystems(Check):
    id = "AD-INF-002"
    title = "Systèmes d'exploitation obsolètes (hors support)"
    severity = "high"
    category = "infrastructure"
    effort = "90d"
    why = ("Un système hors support ne reçoit plus de correctifs de sécurité : chaque nouvelle "
           "faille publiée reste ouverte définitivement.")
    remediation = ("Planifier la migration (ou l'abonnement ESU temporaire), isoler les "
                   "machines restantes dans un VLAN filtré et en priorité les contrôleurs de "
                   "domaine et serveurs exposés.")
    references = [
        "ANSSI vuln_dc_obsolete — DC/RODC ayant un système d'exploitation obsolète",
        "Microsoft Lifecycle Policy (learn.microsoft.com/lifecycle)",
    ]
    mitre = [("T1210", "Exploitation of Remote Services")]

    def evaluate(self, d, cfg):
        patterns = [p.lower() for p in cfg.get("obsolete_os", [])]
        exceptions = [p.lower() for p in cfg.get("obsolete_os_exceptions", [])]
        ev = []
        for c in d.computers:
            os_name = (c["operatingSystem"] or "").lower()
            if not c["enabled"] or not os_name:
                continue
            if any(e in os_name for e in exceptions):
                continue
            if any(p in os_name for p in patterns):
                role = " [CONTRÔLEUR DE DOMAINE]" if c["isDomainController"] else ""
                ev.append(f"{c['name']} : {c['operatingSystem']}{role}")
        return ev


@register
class SmbSigningNotRequired(Check):
    id = "AD-INF-003"
    title = "Signature SMB non exigée"
    severity = "medium"
    category = "infrastructure"
    effort = "30d"
    why = ("Sans signature SMB obligatoire, une machine placée sur le réseau peut relayer "
           "l'authentification d'un utilisateur vers un autre serveur.")
    remediation = ("GPO « Serveur réseau Microsoft : communications signées numériquement "
                   "(toujours) » = Activé, sur les DC et les serveurs membres, puis sur les "
                   "postes. Tester les vieux NAS/imprimantes avant généralisation.")
    references = [
        "CIS Benchmark Windows Server — Microsoft network server: Digitally sign communications (always)",
        "Microsoft — Overview of Server Message Block signing (Microsoft Learn)",
    ]
    mitre = [("T1557.001", "Adversary-in-the-Middle: Name Resolution Poisoning and SMB Relay")]

    def evaluate(self, d, cfg):
        ev = []
        if not d.gpo["smbSigningRequiredDCs"]:
            ev.append("Signature SMB non exigée sur les contrôleurs de domaine")
        if not d.gpo["smbSigningRequiredMembers"]:
            ev.append("Signature SMB non exigée sur les serveurs et postes membres")
        return ev


@register
class LlmnrNetbiosEnabled(Check):
    id = "AD-INF-004"
    title = "LLMNR et/ou NetBIOS-NS actifs"
    severity = "medium"
    category = "infrastructure"
    effort = "30d"
    why = ("LLMNR et NetBIOS-NS diffusent les noms introuvables à tout le réseau local : "
           "n'importe quelle machine peut répondre à la place du vrai serveur et recevoir "
           "une tentative d'authentification.")
    remediation = ("GPO « Désactiver la résolution de noms multidiffusion » (LLMNR) = Activé ; "
                   "désactiver NetBIOS sur TCP/IP (DHCP option ou script). Vérifier que le DNS "
                   "interne résout bien tous les noms utilisés.")
    references = [
        "CIS Benchmark Windows — Turn off multicast name resolution = Enabled",
        "Microsoft — DNS Client Group Policy settings (Microsoft Learn)",
    ]
    mitre = [("T1557.001", "Adversary-in-the-Middle: Name Resolution Poisoning and SMB Relay")]

    def evaluate(self, d, cfg):
        ev = []
        if not d.gpo["llmnrDisabled"]:
            ev.append("LLMNR non désactivé par GPO")
        if not d.gpo["netbiosDisabled"]:
            ev.append("NetBIOS sur TCP/IP non désactivé")
        return ev


@register
class NtlmV1Allowed(Check):
    id = "AD-INF-005"
    title = "LM / NTLMv1 encore acceptés"
    severity = "high"
    category = "infrastructure"
    effort = "90d"
    why = ("LM et NTLMv1 sont des protocoles d'authentification anciens et cryptographiquement "
           "faibles : une réponse capturée permet de retrouver le secret du compte.")
    remediation = ("Auditer d'abord l'usage de NTLMv1 (événements 4624 avec « Package Name "
                   "(NTLM only) : NTLM V1 »), corriger les applications concernées, puis fixer "
                   "« Sécurité réseau : niveau d'authentification LAN Manager » = « Envoyer "
                   "uniquement des réponses NTLMv2. Refuser LM et NTLM » (niveau 5).")
    references = [
        "CIS Benchmark Windows Server — Network security: LAN Manager authentication level",
        "Microsoft — Network security: LAN Manager authentication level (Microsoft Learn)",
    ]
    mitre = [("T1557.001", "Adversary-in-the-Middle: Name Resolution Poisoning and SMB Relay"),
             ("T1550.002", "Use Alternate Authentication Material: Pass the Hash")]

    def evaluate(self, d, cfg):
        level = d.gpo["lmCompatibilityLevel"]
        need = cfg["thresholds"]["min_lm_compatibility_level"]
        if level >= need:
            return []
        detail = ("les clients peuvent encore envoyer LM/NTLMv1" if level < 3
                  else "les DC acceptent encore LM et/ou NTLMv1")
        return [f"LmCompatibilityLevel = {level} (attendu {need}) : {detail}"]


@register
class TrustWithoutSidFiltering(Check):
    id = "AD-TRU-001"
    title = "Approbation sans filtrage des SID"
    severity = "high"
    category = "trusts"
    effort = "30d"
    why = ("Sans filtrage des SID (quarantaine), le domaine fait confiance aux identifiants "
           "de groupes fournis par le domaine approuvé : une compromission chez le partenaire "
           "peut se propager dans ce domaine avec des droits élevés.")
    remediation = ("Activer le filtrage des SID (netdom trust /quarantine:yes pour une "
                   "approbation externe), activer l'authentification sélective et supprimer les "
                   "approbations qui ne servent plus.")
    references = [
        "ANSSI vuln_trusts_domain_notfiltered — Relations d'approbation sortante de type domaine non filtré",
        "Microsoft — Security considerations for trusts (Microsoft Learn)",
    ]
    mitre = [("T1134.005", "Access Token Manipulation: SID-History Injection"),
             ("T1484.002", "Domain or Tenant Policy Modification: Trust Modification")]

    def evaluate(self, d, cfg):
        ev = []
        for t in d.trusts:
            if not t["sidFilteringEnabled"]:
                extra = "" if t["selectiveAuthentication"] else ", authentification sélective désactivée"
                ev.append(f"{t['target']} ({t['trustType']}, {t['direction']}) : filtrage des SID désactivé{extra}")
        return ev
