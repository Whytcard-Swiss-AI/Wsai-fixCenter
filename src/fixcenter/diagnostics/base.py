from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from fixcenter.models import Finding, Problem, Severity

ALL_TYPES = frozenset(
    {
        "hook",
        "plugin",
        "skill",
        "config",
        "system",
        "network",
        "runtime",
        "security",
        "integration",
        "codex",
        "unknown",
    }
)


@dataclass(frozen=True)
class Diagnostic:
    name: str
    supported_types: frozenset[str]
    run: Callable[[Problem], list[Finding]]


def _text(problem: Problem) -> str:
    return ("\n".join(problem.logs) + " " + problem.description).lower()


def _contains(problem: Problem, terms: tuple[str, ...]) -> bool:
    text = _text(problem)
    return any(term in text for term in terms)


def _finding(
    finding_id: str,
    title: str,
    severity: Severity,
    confidence: float,
    evidence: str,
    explanation: str,
    fixes: list[str],
    diagnostic: str,
) -> list[Finding]:
    return [
        Finding(
            finding_id,
            title,
            severity,
            confidence,
            [evidence],
            explanation,
            fixes,
            diagnostic,
        )
    ]


def check_missing_component(problem: Problem) -> list[Finding]:
    if not _contains(
        problem, ("not found", "missing", "inconnu", "introuvable", "no such file")
    ):
        return []
    return _finding(
        "component-missing",
        "Composant introuvable ou non chargé",
        "high",
        0.86,
        "Un signal explicite de composant ou fichier manquant apparaît dans les données fournies.",
        "Le nom demandé n'est probablement pas résolu dans le chemin de recherche actif.",
        [
            "Vérifier le nom exact et la casse.",
            "Contrôler environment.path et le registre du composant.",
            "Réinstaller seulement après validation de la source.",
        ],
        "missing-component",
    )


def check_config_shape(problem: Problem) -> list[Finding]:
    if not problem.config:
        return []
    suspicious = [
        key
        for key in ("hooks", "plugins", "skills")
        if key in problem.config and not isinstance(problem.config[key], (dict, list))
    ]
    if not suspicious:
        return []
    return _finding(
        "config-shape",
        "Structure de configuration inattendue",
        "high",
        0.91,
        f"Les clés {', '.join(suspicious)} ne sont ni une liste ni un objet.",
        "Le chargeur peut ignorer silencieusement une section dont le type ne correspond pas au schéma attendu.",
        [
            "Comparer la section au schéma de la version installée.",
            "Corriger le type sans inclure de secrets.",
            "Relancer le diagnostic.",
        ],
        "config-shape",
    )


def check_hook_order(problem: Problem) -> list[Finding]:
    if problem.problem_type != "hook" or not _contains(
        problem, ("order", "ordre", "before", "after", "timeout", "timed out")
    ):
        return []
    return _finding(
        "hook-order",
        "Ordre ou délai d'exécution du hook suspect",
        "medium",
        0.72,
        "Le signal mentionne un ordre, une dépendance ou un délai de hook.",
        "Une dépendance implicite ou un hook bloquant peut provoquer un échec en cascade.",
        [
            "Lister l'ordre effectif des hooks.",
            "Isoler le dernier hook ajouté.",
            "Ajouter un délai borné et des marqueurs début/fin.",
        ],
        "hook-order",
    )


def check_permission_denied(problem: Problem) -> list[Finding]:
    if not _contains(
        problem,
        (
            "permission denied",
            "access denied",
            "unauthorizedaccess",
            "eacces",
            "operation not permitted",
            "accès refusé",
        ),
    ):
        return []
    return _finding(
        "permission-denied",
        "Autorisation insuffisante",
        "high",
        0.9,
        "Les logs contiennent un refus d'accès explicite.",
        "L'identité active, les ACL ou une politique d'exécution empêchent l'opération.",
        [
            "Contrôler identity.permissions et security.policies.",
            "Identifier la ressource exacte refusée.",
            "Accorder uniquement le droit minimal nécessaire.",
        ],
        "permission-denied",
    )


def check_dependency_conflict(problem: Problem) -> list[Finding]:
    if not _contains(
        problem,
        (
            "version conflict",
            "dependency conflict",
            "resolutionimpossible",
            "requires version",
            "incompatible version",
            "could not resolve",
        ),
    ):
        return []
    return _finding(
        "dependency-conflict",
        "Conflit de dépendances",
        "high",
        0.87,
        "Un conflit ou une incompatibilité de version est signalé.",
        "Deux composants demandent probablement des versions incompatibles d'une même dépendance.",
        [
            "Capturer les versions de tooling.runtimes et packages.managers.",
            "Comparer le lockfile au manifeste.",
            "Tester la résolution dans un environnement isolé.",
        ],
        "dependency-conflict",
    )


def check_authentication(problem: Problem) -> list[Finding]:
    if not _contains(
        problem,
        (
            "401",
            "403",
            "unauthorized",
            "forbidden",
            "invalid token",
            "authentication failed",
            "oauth",
        ),
    ):
        return []
    return _finding(
        "authentication-failed",
        "Authentification ou autorisation distante échouée",
        "high",
        0.84,
        "Un statut ou message d'authentification est présent.",
        "Le jeton peut être absent, expiré, mal ciblé ou dépourvu du scope requis.",
        [
            "Ne jamais copier le secret dans le rapport.",
            "Vérifier présence, expiration, audience et scopes côté fournisseur.",
            "Réautoriser via le flux officiel si nécessaire.",
        ],
        "authentication",
    )


def check_network(problem: Problem) -> list[Finding]:
    if not _contains(
        problem,
        (
            "dns",
            "enotfound",
            "connection refused",
            "econnrefused",
            "network unreachable",
            "tls",
            "certificate verify",
            "proxy",
        ),
    ):
        return []
    return _finding(
        "network-path",
        "Chemin réseau, DNS, proxy ou TLS suspect",
        "high",
        0.82,
        "Le signal correspond à une erreur de résolution, connexion, proxy ou certificat.",
        "La panne peut se situer avant l'application : résolution, route, écoute locale, filtrage ou confiance TLS.",
        [
            "Contrôler network.adapters, network.dns et network.proxy.",
            "Vérifier security.firewall et security.certificates.",
            "Tester l'hôte exact sans exposer d'identifiants.",
        ],
        "network-path",
    )


def check_schema_protocol(problem: Problem) -> list[Finding]:
    if not _contains(
        problem,
        (
            "invalid schema",
            "schema validation",
            "jsonrpc",
            "method not found",
            "-32601",
            "-32602",
            "protocol version",
            "invalid params",
        ),
    ):
        return []
    return _finding(
        "protocol-schema",
        "Contrat MCP ou schéma incompatible",
        "high",
        0.89,
        "Une incompatibilité JSON-RPC, de paramètres ou de version de protocole est signalée.",
        "Le client et le serveur ne partagent probablement pas le même contrat d'outil ou la même version.",
        [
            "Comparer initialize, tools/list et le schéma réellement envoyé.",
            "Valider les paramètres avant tools/call.",
            "Mettre à niveau un seul côté à la fois puis rejouer le test.",
        ],
        "protocol-schema",
    )


def check_duplicate_registration(problem: Problem) -> list[Finding]:
    if not _contains(
        problem,
        (
            "already registered",
            "duplicate",
            "already exists",
            "conflict 409",
            "nom déjà utilisé",
        ),
    ):
        return []
    return _finding(
        "duplicate-registration",
        "Enregistrement dupliqué",
        "medium",
        0.83,
        "Le nom ou l'identifiant semble déjà enregistré.",
        "Deux configurations, caches ou processus peuvent déclarer le même hook, plugin, skill ou serveur.",
        [
            "Lister les sources de configuration actives.",
            "Comparer les identifiants normalisés et la casse.",
            "Supprimer uniquement l'enregistrement obsolète après sauvegarde.",
        ],
        "duplicate-registration",
    )


def check_path_resolution(problem: Problem) -> list[Finding]:
    if not _contains(
        problem,
        (
            "not recognized as",
            "is not recognized",
            "command not found",
            "executable not found",
            "path is not set",
            "cannot locate executable",
        ),
    ):
        return []
    return _finding(
        "path-resolution",
        "Exécutable absent du PATH",
        "high",
        0.88,
        "Le lanceur ne parvient pas à résoudre une commande.",
        "Le binaire est absent, le PATH actif diffère du shell attendu, ou le processus n'a pas été redémarré après installation.",
        [
            "Contrôler environment.path et tooling.runtimes.",
            "Utiliser temporairement un chemin absolu validé.",
            "Redémarrer le client après correction du PATH.",
        ],
        "path-resolution",
    )


def check_crash(problem: Problem) -> list[Finding]:
    if not _contains(
        problem,
        (
            "traceback",
            "segmentation fault",
            "panic:",
            "unhandled exception",
            "fatal error",
            "exit code 1",
        ),
    ):
        return []
    return _finding(
        "runtime-crash",
        "Crash ou exception non gérée",
        "high",
        0.8,
        "Une trace d'exception, un panic ou une sortie fatale est visible.",
        "L'échec se produit dans le processus plutôt que dans la découverte du composant.",
        [
            "Conserver la première exception et sa cause chaînée.",
            "Reproduire avec la configuration minimale.",
            "Comparer la version du runtime et la dernière modification.",
        ],
        "runtime-crash",
    )


def check_probe_failures(problem: Problem) -> list[Finding]:
    failed = [
        item
        for item in problem.observations
        if item.get("status") in {"nonzero", "unavailable", "timeout", "error"}
    ]
    if not failed:
        return []
    ids = [str(item.get("control_id", "unknown")) for item in failed[:8]]
    return _finding(
        "observation-incomplete",
        "Contrôles système incomplets",
        "medium",
        0.95,
        f"Les contrôles suivants n'ont pas abouti : {', '.join(ids)}.",
        "Une couverture d'exécution inférieure à 100 % signifie que certaines causes restent non observées.",
        [
            "Examiner le statut de chaque probe sans augmenter les privilèges par défaut.",
            "Installer l'outil système manquant si sa provenance est sûre.",
            "Rejouer seulement les contrôles échoués.",
        ],
        "observation-failures",
    )


def check_remote_control(problem: Problem) -> list[Finding]:
    if not _contains(
        problem,
        (
            "remote control availability",
            "remote control is unavailable",
            "disponibilité du contrôle à distance",
            "controle a distance indisponible",
        ),
    ):
        return []
    return _finding(
        "remote-control-state",
        "État du contrôle à distance non synchronisé",
        "high",
        0.86,
        "Le client signale qu'il ne peut pas mettre à jour la disponibilité du contrôle à distance.",
        "La session locale, la connectivité vers le service ou l'état distant peuvent être désynchronisés.",
        [
            "Contrôler agents.codex_runtime et agents.remote_control sans lire les contenus privés.",
            "Vérifier séparément la connexion du client et l'état du service distant.",
            "Redémarrer ou reconnecter le client seulement après avoir préservé le travail en cours.",
        ],
        "remote-control-state",
    )


def check_conversation_stream(problem: Problem) -> list[Finding]:
    if not _contains(
        problem,
        (
            "is not being streamed",
            "conversation is not streaming",
            "error creating chat",
            "stream disconnected",
            "stream closed",
            "conversation non diffusée",
        ),
    ):
        return []
    return _finding(
        "conversation-stream",
        "Conversation créée sans flux actif",
        "high",
        0.92,
        "Le client indique qu'une conversation n'est pas associée à un flux actif.",
        "Un état de conversation obsolète, une reconnexion interrompue ou une course entre création et abonnement au flux est probable.",
        [
            "Contrôler agents.codex_runtime et agents.chat_stream.",
            "Préserver le texte non envoyé avant toute fermeture de la tâche.",
            "Recréer une tâche seulement si la conversation ne peut pas être reprise après reconnexion.",
        ],
        "conversation-stream",
    )


def check_hook_source_health(problem: Problem) -> list[Finding]:
    text = _text(problem)
    hook_signal = "hook" in text and any(
        term in text for term in ("problem", "problème", "failed", "invalid", "error")
    )
    source_signal = any(
        term in text
        for term in (
            "user configuration",
            "configuration utilisateur",
            "plugin",
            "plug-in",
        )
    )
    if problem.problem_type not in {"hook", "codex"} or not (
        hook_signal and source_signal
    ):
        return []
    return _finding(
        "hook-source-health",
        "Hooks en erreur dans une couche de configuration",
        "high",
        0.88,
        "Un problème de hook est associé à la configuration utilisateur ou à un plug-in.",
        "Le conflit peut provenir d'un hook dupliqué, d'un exécutable absent, d'un schéma invalide ou d'un ordre incompatible entre couches.",
        [
            "Contrôler agents.hook_health et agents.configuration_layers.",
            "Identifier la couche fautive avant de désactiver quoi que ce soit.",
            "Comparer noms, commandes, ordre et disponibilité des exécutables avec des valeurs secrètes masquées.",
        ],
        "hook-source-health",
    )


DEFAULT_DIAGNOSTICS = (
    Diagnostic("missing-component", ALL_TYPES, check_missing_component),
    Diagnostic("config-shape", ALL_TYPES, check_config_shape),
    Diagnostic("hook-order", frozenset({"hook"}), check_hook_order),
    Diagnostic("permission-denied", ALL_TYPES, check_permission_denied),
    Diagnostic("dependency-conflict", ALL_TYPES, check_dependency_conflict),
    Diagnostic("authentication", ALL_TYPES, check_authentication),
    Diagnostic("network-path", ALL_TYPES, check_network),
    Diagnostic("protocol-schema", ALL_TYPES, check_schema_protocol),
    Diagnostic("duplicate-registration", ALL_TYPES, check_duplicate_registration),
    Diagnostic("path-resolution", ALL_TYPES, check_path_resolution),
    Diagnostic("runtime-crash", ALL_TYPES, check_crash),
    Diagnostic("observation-failures", ALL_TYPES, check_probe_failures),
    Diagnostic("remote-control-state", ALL_TYPES, check_remote_control),
    Diagnostic("conversation-stream", ALL_TYPES, check_conversation_stream),
    Diagnostic(
        "hook-source-health",
        frozenset({"hook", "codex"}),
        check_hook_source_health,
    ),
)
