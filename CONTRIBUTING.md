# Contribuer à stdflow-cli

Merci de vouloir contribuer ! Ce document résume comment mettre en place l'environnement, les règles de style, et le processus de contribution.

## Pré-requis

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) pour la gestion des dépendances
- Docker (optionnel, pour tester l'image ou builder en local)
- Un realm Keycloak accessible (local ou distant) pour tester le standard flow de bout en bout

## Mettre en place l'environnement local

```bash
git clone https://github.com/MdkKmg/stdflow-cli.git
cd stdflow-cli
cp .env.example .env   # puis éditer avec les infos de votre Keycloak de test
uv sync                # installe les dépendances (dont les outils de dev : ruff)
uv run uvicorn app.main:app --reload --port 8080
```

Voir le [README](README.md) pour le détail des variables d'environnement et le lancement via Docker/Kubernetes.

## Workflow de contribution

La branche `main` est protégée : aucun push direct, tout passe par une **Pull Request**.

1. Créer une branche depuis `main` : `git checkout -b feature/ma-fonctionnalite`
2. Faire les changements, en gardant chaque commit cohérent et son message explicite
3. Vérifier localement le format et le lint (voir ci-dessous) avant de pousser
4. Ouvrir une Pull Request vers `main`
5. La CI **Ruff** (`.github/workflows/ruff.yml`) se déclenche automatiquement sur la PR et doit passer au vert avant fusion

Une fois la PR mergée, une release se fait en posant un tag `vX.Y.Z` sur `main`, ce qui déclenche la CI de build/publication de l'image (`.github/workflows/build-image.yml`) — voir la section *CI/CD* du README.

## Style de code

Le code est formaté et linté avec [Ruff](https://docs.astral.sh/ruff/) (config dans `pyproject.toml`). Avant de pousser :

```bash
uv run ruff format .   # formatage
uv run ruff check .    # lint
```

La CI refuse la fusion si l'un des deux échoue. Pour un fix automatique des problèmes sûrs : `uv run ruff check --fix .`.

Conventions générales du projet :
- Pas de commentaire pour expliquer *ce que* fait le code (les noms doivent suffire) — seulement le *pourquoi* quand c'est non évident (contrainte cachée, contournement, comportement surprenant).
- Pas d'abstraction ou de configuration ajoutée pour un besoin hypothétique : on code ce dont on a besoin maintenant.
- Toute variable de configuration fonctionnelle passe par `app/config.py` (`Settings`), pas de valeur en dur éparpillée dans le code.

## Vérifier ses changements

Il n'y a pas de suite de tests automatisés pour l'instant. Avant d'ouvrir une PR, vérifier manuellement que le flow fonctionne :

1. Lancer l'app en local (`uv run uvicorn app.main:app --reload`)
2. Faire un login complet contre un Keycloak de test (réel, ou un realm dédié aux tests)
3. Si le changement touche PKCE, DPoP, ou l'ACR : tester avec le mécanisme concerné activé **et** désactivé
4. Vérifier que la page de résultat et les logs stdout (JSON) restent cohérents

Si vous ajoutez un comportement difficile à valider manuellement (ex. un cas d'erreur réseau), n'hésitez pas à décrire dans la PR comment vous l'avez testé (mock, Keycloak local, etc.).

## Commits

- Utiliser des messages de commit clairs, qui expliquent le *pourquoi* du changement.
- Les commits doivent être **signed-off** (`Signed-off-by: ...`), via `git commit -s` ou l'équivalent dans votre éditeur (dans VS Code : `git.alwaysSignOff` dans les settings).
- Ne jamais committer de secret réel (`KEYCLOAK_CLIENT_SECRET`, tokens, exports de realm Keycloak, `.env`) — vérifier `git status`/`git diff` avant de pousser.

## Sécurité

`stdflow-cli` est un outil de debug : il affiche des tokens complets et désactive volontairement certaines vérifications (`HTTP_VERIFY_TLS=false` figé au build de l'image via le `Dockerfile`, décodage JWT non vérifié). Toute contribution touchant à ces zones doit préserver le fait que ces comportements restent **explicites et opt-in**, jamais un défaut silencieux — et pour `HTTP_VERIFY_TLS`, jamais surchargeable au déploiement.

Pour signaler une vulnérabilité, ouvrir une issue privée ou contacter directement le mainteneur plutôt qu'une issue publique.

## Licence

En contribuant, vous acceptez que votre contribution soit distribuée sous la licence [Apache 2.0](LICENSE) du projet.
