# LEARN — comprendre le projet ad-security-audit

Ce document m'aide à expliquer le projet en entretien. Il est volontairement simple.
Toutes les données du projet sont **synthétiques** (entreprise fictive AgriSouss SARL).

## 1. Les bases d'Active Directory

**Active Directory (AD)** : l'annuaire de Microsoft. Il contient les comptes des
utilisateurs, des ordinateurs et des groupes d'une entreprise, et décide qui a le droit de
faire quoi. Presque toutes les entreprises sous Windows en ont un. Si l'AD tombe entre de
mauvaises mains, toute l'entreprise est compromise : c'est pour cela qu'on l'audite.

**Domaine** : l'ensemble des objets gérés par un même AD, avec un nom DNS
(`agrisouss.local`). Une **forêt** regroupe un ou plusieurs domaines.

**Contrôleur de domaine (DC)** : le serveur qui héberge l'annuaire et authentifie les
utilisateurs. Il y en a au moins deux pour la redondance (DC01, DC02 dans AgriSouss).

**OU (unité d'organisation)** : un dossier dans l'annuaire (par exemple « Postes Agadir »).
On y range les objets pour leur appliquer des GPO ou déléguer leur gestion.

**GPO (stratégie de groupe)** : un ensemble de réglages poussés automatiquement sur les
ordinateurs et utilisateurs d'une OU (politique de mot de passe, signature SMB, LAPS...).

**Groupes** : un groupe rassemble des comptes pour leur donner des droits. Un groupe peut
contenir un autre groupe (**imbrication**). Les **groupes privilégiés** (Domain Admins,
Enterprise Admins, Administrators, Backup Operators...) donnent le contrôle de tout ou partie
du domaine.

**Kerberos (niveau concept)** : le protocole d'authentification principal. L'utilisateur
prouve son identité au DC et reçoit un « ticket » ; il présente ensuite ce ticket aux
serveurs au lieu de son mot de passe. Le premier ticket (TGT) est chiffré et signé avec le
secret d'un compte spécial, **krbtgt** ; les tickets de service sont chiffrés avec le secret
du compte de service.

**NTLM (niveau concept)** : l'ancien protocole d'authentification par défi-réponse, gardé
pour compatibilité. Sa version 1 (et LM) est faible ; NTLMv2 est meilleure ; Kerberos est
préféré.

**SPN (Service Principal Name)** : l'identifiant d'un service (par exemple un serveur SQL)
attaché à un compte. Un compte qui porte un SPN est un **compte de service**.

**Modèle en tiers (tiering)** : on sépare les comptes d'administration en niveaux. Tier 0 =
ce qui contrôle l'AD (DC, Domain Admins) ; Tier 1 = serveurs ; Tier 2 = postes de travail.
Un compte d'un tier ne se connecte jamais à une machine d'un tier inférieur, pour que la
compromission d'un poste ne donne pas les identifiants d'un administrateur du domaine.

**LAPS** : outil Microsoft (intégré à Windows depuis 2023) qui donne à chaque ordinateur un
mot de passe administrateur local unique, aléatoire et renouvelé, stocké dans l'AD.

**gMSA (Group Managed Service Account)** : un compte de service dont le mot de passe
(120 caractères) est généré et changé automatiquement par l'AD. Personne ne le connaît.

**Protected Users** : un groupe spécial. Ses membres ne peuvent pas utiliser NTLM, ni le
chiffrement faible, ni la délégation, et leurs identifiants ne sont pas gardés en cache.
On y met les administrateurs (après tests), jamais les comptes de service.

**adminCount / AdminSDHolder** : l'AD protège les membres des groupes privilégiés en leur
appliquant des permissions figées et en mettant `adminCount=1`. Quand on retire quelqu'un du
groupe, l'attribut reste : c'est un « orphelin ».

## 2. Ce que fait l'outil, en une phrase

Il lit un fichier JSON qui décrit la configuration d'un domaine (exporté en lecture seule
par un administrateur), lance 23 contrôles, calcule un score de risque de 0 à 100 (plus bas =
mieux) et produit un rapport HTML/JSON avec un plan de remédiation en trois horizons.

Flux : `export JSON -> validation (model.py) -> contrôles (checks/) -> score (scoring.py)
-> plan (plan.py) -> rapport (report.py) -> comparaison avant/après (compare.py)`.

## 3. Pourquoi chaque mauvaise configuration compte (vue défensive)

| Contrôle | Le risque, simplement | Ce que le défenseur fait |
|---|---|---|
| Politique de mot de passe faible | des mots de passe courts sont devinés | longueur >= 12-14, historique, phrases de passe |
| Pas de verrouillage | rien ne limite les essais en ligne | seuil 5-10, surveiller l'événement 4740 |
| Trop de Domain Admins | plus de comptes = plus de chances qu'un tombe | 2-3 comptes dédiés, délégation sur OU |
| Groupes imbriqués | des droits d'admin cachés | membres directs uniquement |
| Admins hors Protected Users | identité d'admin réutilisable depuis une machine compromise | Protected Users + « sensible, non délégable » |
| Mot de passe admin qui n'expire jamais | une fuite ancienne reste valable | FGPP admin, rotation |
| adminCount orphelin | permissions figées, inventaire faux | remettre à 0, réactiver l'héritage |
| Compte de service (SPN) admin | son mot de passe peut être attaqué hors ligne | sortir des groupes admin, gMSA |
| Boucle de groupes | appartenance illisible | casser la boucle |
| Comptes dormants | compte que personne ne surveille | revue trimestrielle avec les RH |
| Invité actif | accès sans identité | désactiver |
| Mot de passe en description | lisible par tout le domaine | effacer, changer le mot de passe, coffre |
| PASSWD_NOTREQD | mot de passe vide possible | retirer le drapeau |
| Pré-authentification désactivée | réponse attaquable hors ligne sans échec de connexion | réactiver, changer le mot de passe |
| SPN avec vieux mot de passe | cassage hors ligne d'un mot de passe humain | gMSA ou 25+ caractères |
| Délégation non contrainte | le serveur garde les tickets des admins qui s'y connectent | délégation contrainte, Protected Users |
| krbtgt ancien | un vol ancien du secret reste exploitable | double rotation planifiée |
| Pas de LAPS | même mot de passe admin local partout = propagation | Windows LAPS |
| OS obsolète | failles jamais corrigées | migration, isolement VLAN |
| Signature SMB non exigée | relais d'authentification | GPO signature « toujours » |
| LLMNR / NetBIOS | une machine du réseau peut se faire passer pour un serveur | désactiver par GPO, DNS propre |
| NTLMv1 / LM | réponses faibles | auditer puis niveau 5 |
| Trust sans filtrage SID | une compromission chez le partenaire se propage | quarantaine SID, authentification sélective |

Je n'explique jamais *comment* exploiter ces faiblesses : l'outil et ce document parlent
de risque, de détection et de correction.

## 4. Choix techniques à savoir défendre

- **Hors ligne, sur un export** : aucun accès réseau, aucun identifiant manipulé, résultat
  reproductible (les âges sont calculés par rapport à `exportedAt`, pas à l'horloge).
- **Plugins** : chaque contrôle est une classe avec `@register` ; `engine.all_checks()` les
  découvre automatiquement avec `pkgutil`.
- **Validation stricte** : types, champs obligatoires, doublons, taille max, UTF-8 avec BOM
  accepté, `true` refusé là où un entier est attendu. Erreur = code retour 2.
- **Groupes imbriqués** : parcours itératif avec ensemble `visited` -> pas de boucle infinie,
  pas de limite de récursion (testé avec 5 000 niveaux).
- **Masquage** : la description n'est jamais recopiée, seulement le mot-clé et `********`.
  Un test vérifie que les faux secrets plantés n'apparaissent dans aucune sortie.
- **HTML sûr** : tout passe par `html.escape`, aucun script, aucun CDN, CSP stricte.
- **Score** : 0-100, plus bas = mieux ; catégorie = min(100, somme des points) ; global =
  moitié pire catégorie + moitié moyenne (voir docs/SCORING.md).
- **Données synthétiques déterministes** : l'export durci = export vulnérable + une
  correction par contrôle ; l'export « quick wins » applique seulement les corrections
  rapides. Un test vérifie que les fichiers commités sont identiques au générateur.

## 5. Questions d'entretien (18) et réponses

1. **Présente ton projet en une minute.**
   J'ai construit un auditeur hors ligne de configuration Active Directory, inspiré de
   PingCastle et de la checklist ANSSI. Il lit un export JSON, lance 23 contrôles, donne un
   score de risque et un plan de remédiation en trois horizons. Je l'ai testé sur des données
   synthétiques d'une PME fictive : 90/100 avant, 74 après les quick wins, 0 après durcissement.

2. **Pourquoi auditer un export plutôt que le domaine en direct ?**
   Pour ne rien toucher en production, ne manipuler aucun identifiant, et avoir un résultat
   reproductible. Le client garde la main : il exporte en lecture seule et me transmet le fichier.

3. **As-tu audité une vraie entreprise ?**
   Non. Toutes les données sont synthétiques. Le script d'export PowerShell est vérifié
   syntaxiquement mais je ne l'ai pas lancé sur un vrai domaine.

4. **Qu'est-ce que krbtgt et pourquoi vérifier l'âge de son mot de passe ?**
   C'est le compte dont le secret chiffre et signe les TGT (les tickets d'authentification)
   de tout le domaine. S'il a été volé un jour,
   il reste utilisable tant qu'on ne le change pas. On le renouvelle deux fois, avec une
   pause pour la réplication et la durée de vie des tickets.

5. **Différence entre Kerberos et NTLM ?**
   Kerberos utilise des tickets délivrés par le DC ; NTLM est un défi-réponse plus ancien.
   NTLMv1 et LM sont faibles. L'objectif est de réduire NTLM et d'interdire v1 (niveau 5).

6. **Pourquoi un compte de service avec SPN est-il sensible ?**
   N'importe quel utilisateur du domaine peut demander un ticket de service chiffré avec son
   mot de passe et tenter de le casser hors ligne. La réponse défensive : gMSA, ou mot de
   passe très long, et jamais de droits d'administrateur du domaine.

7. **Qu'est-ce que LAPS et quel risque il réduit ?**
   Un mot de passe administrateur local unique par machine. Sans lui, un mot de passe
   identique partout permet de passer d'un poste à tous les autres.

8. **Que fait le groupe Protected Users ?**
   Il interdit NTLM, la délégation, le chiffrement faible et le cache d'identifiants pour ses
   membres. On y met les admins après test, pas les comptes de service.

9. **Explique le modèle en tiers.**
   Tier 0 contrôle l'AD, Tier 1 les serveurs, Tier 2 les postes. Un admin Tier 0 ne se
   connecte jamais sur un poste Tier 2, pour que ses identifiants n'y soient pas exposés.

10. **Comment as-tu calculé le score ?**
    Points par sévérité (40/20/10/5), plafond 100 par catégorie, global = moitié pire
    catégorie + moitié moyenne. Le max seul (PingCastle) cache les progrès ; la moyenne
    seule noie une catégorie catastrophique.

11. **Pourquoi le nombre d'objets touchés ne change pas le score ?**
    Pour ne pas pénaliser les grands domaines ni récompenser un export partiel. Le nombre
    est affiché à part dans le rapport. C'est un compromis que j'assume.

12. **Comment évites-tu une boucle infinie dans les groupes imbriqués ?**
    Parcours itératif avec un ensemble des groupes déjà visités. Testé avec une boucle A-B
    et 5 000 niveaux d'imbrication. Les boucles sont aussi signalées (contrôle AD-PRIV-007).

13. **Comment gères-tu un mot de passe trouvé dans une description ?**
    Je signale le compte avec le mot-clé et un masque fixe, sans jamais recopier la valeur.
    Le script d'export la masque même avant l'écriture du fichier. Un test vérifie l'absence
    des faux secrets dans toutes les sorties.

14. **Comment as-tu testé l'outil ?**
    174 tests pytest. Chaque contrôle doit se déclencher sur l'export vulnérable, rester
    silencieux sur l'export durci, et se déclencher seul après une seule modification d'un
    export minimal propre. Plus les limites de seuils, le score, la CLI, les entrées
    malformées et l'échappement HTML.

15. **Quelles sont les limites de ton outil ?**
    Pas d'analyse des ACL ni des chemins d'attaque, pas d'ADCS, pas de PSO, pas d'Entra ID.
    La partie GPO est remplie à la main. PingCastle ou les outils ANSSI couvrent beaucoup plus.

16. **Comment as-tu choisi tes références ?**
    J'ai relevé les identifiants de la checklist ANSSI / CERT-FR (par exemple `vuln_krbtgt`,
    `vuln_delegation_t4d`) et vérifié les techniques MITRE ATT&CK sur la version 19.2. Pour
    CIS, je cite le nom du réglage car la numérotation change selon les versions.

17. **Que ferais-tu ensuite ?**
    Ajouter les Fine-Grained Password Policies, la délégation contrainte avec transition de
    protocole, et lancer l'export sur un domaine de laboratoire pour valider le script.

18. **As-tu écrit tout le code toi-même ?**
    Je l'ai construit avec l'aide d'une IA. J'ai relu chaque module, compris les choix,
    lancé les tests et vérifié les références moi-même ; je peux expliquer chaque contrôle et
    modifier le code. Je préfère le dire honnêtement.

## 6. Ligne de CV (honnête)

> Développement d'un auditeur hors ligne de configuration Active Directory en Python
> (23 contrôles inspirés de l'ANSSI et du CIS, score de risque, rapport HTML, plan de
> remédiation, 174 tests), validé sur des **données synthétiques** d'une PME fictive.

## 7. À ne jamais dire

- « J'ai audité l'Active Directory d'une entreprise. » (faux : données synthétiques)
- « Mon outil remplace PingCastle. » (il en couvre une petite partie)
- « J'ai testé le script PowerShell en production. » (jamais lancé sur un vrai domaine)
