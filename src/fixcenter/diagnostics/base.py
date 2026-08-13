from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from fixcenter.models import Finding, Problem


@dataclass(frozen=True)
class Diagnostic:
    name: str
    supported_types: frozenset[str]
    run: Callable[[Problem], list[Finding]]


def _text(problem: Problem) -> str:
    return "\n".join(problem.logs).lower() + " " + problem.description.lower()


def check_missing_component(problem: Problem) -> list[Finding]:
    text = _text(problem)
    if not any(term in text for term in ("not found", "missing", "inconnu", "introuvable")):
        return []
    return [Finding("component-missing", "Composant introuvable ou non chargé", "high", 0.86,
        ["Le signal 'not found/missing' apparaît dans la description ou les logs."],
        "Le nom demandé n'est probablement pas résolu dans le chemin de recherche actif.",
        ["Vérifier le nom exact et la casse.", "Afficher les chemins de recherche réellement actifs.", "Réinstaller ou réenregistrer le composant après validation de sa source."],
        "missing-component")]


def check_config_shape(problem: Problem) -> list[Finding]:
    config = problem.config
    if not config:
        return []
    suspicious = [key for key in ("hooks", "plugins", "skills") if key in config and not isinstance(config[key], (dict, list))]
    if not suspicious:
        return []
    return [Finding("config-shape", "Structure de configuration inattendue", "high", 0.91,
        [f"Les clés {', '.join(suspicious)} ne sont ni une liste ni un objet."],
        "Le chargeur peut ignorer silencieusement une section dont le type ne correspond pas au schéma attendu.",
        ["Comparer la section avec l'exemple de configuration supporté.", "Corriger le type sans toucher aux secrets.", "Relancer le diagnostic après correction."],
        "config-shape")]


def check_hook_order(problem: Problem) -> list[Finding]:
    if problem.problem_type != "hook":
        return []
    text = _text(problem)
    if not any(term in text for term in ("order", "ordre", "before", "after", "timeout", "timed out")):
        return []
    return [Finding("hook-order", "Ordre ou délai d'exécution du hook suspect", "medium", 0.68,
        ["Le signal mentionne un ordre, une dépendance ou un délai."],
        "Un hook qui dépend d'un autre hook doit être ordonné et limité dans le temps pour éviter un échec en cascade.",
        ["Lister les hooks activés avec leur ordre effectif.", "Désactiver temporairement le hook le plus récent pour isoler la régression.", "Ajouter un timeout et un log de début/fin."],
        "hook-order")]


DEFAULT_DIAGNOSTICS = (
    Diagnostic("missing-component", frozenset({"hook", "plugin", "skill", "config", "unknown"}), check_missing_component),
    Diagnostic("config-shape", frozenset({"config", "hook", "plugin", "skill", "unknown"}), check_config_shape),
    Diagnostic("hook-order", frozenset({"hook"}), check_hook_order),
)

