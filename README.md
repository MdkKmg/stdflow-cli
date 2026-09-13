# stdflow-cli

Petite application (Python / FastAPI) pour tester une configuration Keycloak en
réalisant un vrai login **standard flow** (Authorization Code) : elle logue
l'intégralité des échanges HTTP du flow (découverte OIDC, échange du code
contre les tokens, appel `/userinfo`) et affiche le JWT décodé en cas de
succès. PKCE et DPoP sont activables/désactivables par configuration.

Conçue pour tourner en un pod léger sur Kubernetes, en un seul replica.

## Fonctionnement

1. `GET /` — affiche la configuration effective (masquée pour le secret) et un
   bouton *Se connecter*.
2. `GET /login` — récupère le document de découverte OIDC
   (`/.well-known/openid-configuration`), prépare PKCE et/ou une paire de clés
   DPoP éphémère si activés, puis redirige le navigateur vers la page de login
   Keycloak.
3. L'utilisateur s'authentifie sur Keycloak (formulaire natif Keycloak, hors de
   cette appli).
4. `GET /callback` — reçoit le `code`, l'échange contre les tokens auprès du
   `token_endpoint` (avec preuve DPoP si activé, y compris le retry
   `use_dpop_nonce`), appelle `/userinfo` avec l'access_token, puis affiche :
   - le détail de **chaque** requête/réponse HTTP (headers + body, secrets
     masqués) sur la page ET sur stdout (JSON, une ligne par échange — lisible
     par `kubectl logs` / votre pile de logs) ;
   - le JWT (header + payload) décodé pour `id_token`, `access_token` et
     `refresh_token` s'ils sont au format JWT ;
   - la réponse `/userinfo` ;
   - les tokens bruts (repliés par défaut).

Quand PKCE et/ou DPoP sont activés, l'UI affiche aussi des encarts pédagogiques
(accordéons) expliquant le mécanisme, avec les valeurs réellement utilisées pour
la tentative en cours : `code_verifier`/`code_challenge`, ou la clé publique DPoP,
son empreinte (thumbprint RFC 7638) comparée au claim `cnf.jkt` de l'access_token
reçu, et chaque preuve DPoP décodée à côté de la requête HTTP correspondante.

La page `/` propose aussi un champ **ACR** (Authentication Context Class
Reference) modifiable à chaque tentative, sans redéploiement : une valeur
`acr_values` (hint standard) et une case "exiger strictement" qui ajoute en
plus le paramètre OIDC `claims` avec `essential: true`. Le résultat compare le
claim `acr` reçu dans l'`id_token` à la valeur demandée.

Le décodage de JWT n'effectue **aucune vérification de signature** : c'est un
outil de debug, pas un vérificateur de tokens (l'objectif est d'inspecter le
contenu, pas de faire confiance au token).

## Configuration (variables d'environnement)

La quasi-totalité de la configuration se fait par variables d'environnement —
pas de formulaire runtime. Pour changer un paramètre : modifier le
ConfigMap/Secret puis redéployer le pod. Seule exception : le champ **ACR**
(voir plus haut), modifiable directement dans l'UI à chaque tentative — les
variables `ACR_VALUES`/`ACR_ESSENTIAL` ne servent qu'à pré-remplir ce champ.

| Variable | Obligatoire | Défaut | Description |
|---|---|---|---|
| `KEYCLOAK_BASE_URL` | oui | — | URL racine de Keycloak, ex. `https://keycloak.example.com` |
| `KEYCLOAK_REALM` | oui | — | Nom du realm |
| `KEYCLOAK_CLIENT_ID` | oui | — | Client ID, type **Standard flow** activé côté Keycloak |
| `KEYCLOAK_CLIENT_SECRET` | non | — | A renseigner uniquement si le client est confidentiel |
| `KEYCLOAK_SCOPE` | non | `openid` | Scopes demandés, séparés par des espaces (`openid` est ajouté automatiquement si absent) |
| `ENABLE_PKCE` | non | `true` | Active PKCE (méthode `S256`) |
| `ENABLE_DPOP` | non | `false` | Active DPoP (RFC 9449) sur le token endpoint et `/userinfo` |
| `ACR_VALUES` | non | — | Pré-remplit le champ `acr_values` de l'UI (modifiable à chaque login) |
| `ACR_ESSENTIAL` | non | `false` | Pré-coche la case "exiger strictement" de l'UI |
| `PUBLIC_BASE_URL` | oui | — | URL publique du service (sert à construire le `redirect_uri` : `PUBLIC_BASE_URL/callback`) |
| `REDIRECT_URI` | non | dérivé | Override explicite si le `redirect_uri` doit différer de `PUBLIC_BASE_URL/callback` |
| `PORT` | non | `8080` | Port d'écoute |
| `LOG_LEVEL` | non | `INFO` | Niveau de log |
| `STATE_TTL_SECONDS` | non | `300` | Durée de vie max d'une tentative de login en cours |
| `HTTP_VERIFY_TLS` | non | `true` | Vérification du certificat TLS de Keycloak. À passer à `false` uniquement en dev local face à un certificat auto-signé (ex. Keycloak lancé en `start-dev` sans vrai cert) — **jamais** en dehors de ce cas : le statut est loggué au démarrage et affiché en alerte sur `/`. |

**Côté Keycloak**, le client doit avoir :
- *Standard flow* activé (Authorization Code) ;
- `PUBLIC_BASE_URL/callback` dans les *Valid Redirect URIs* ;
- `PUBLIC_BASE_URL/` dans les *Valid post logout redirect URIs* (nécessaire pour
  le bouton de logout sur la page de résultat) ;
- si `ENABLE_PKCE=true` : rien de spécial à faire côté Keycloak (S256 est
  accepté par défaut) — pour forcer PKCE côté serveur, activer *Proof Key for
  Code Exchange Code Challenge Method* = `S256` sur le client ;
- si `ENABLE_DPOP=true` : activer *OAuth 2.0 DPoP Bound Access Tokens* sur le
  client (Keycloak ≥ 25.0, support DPoP).

## Lancer en local

Gestion des dépendances via [uv](https://docs.astral.sh/uv/) (`pyproject.toml` + `uv.lock`).

```bash
cp .env.example .env       # puis éditer .env
uv sync                    # crée .venv/ et installe les dépendances figées par uv.lock
uv run uvicorn app.main:app --reload --port 8080
```

Ouvrir http://localhost:8080.

Pour ajouter/mettre à jour une dépendance : `uv add <paquet>` (ou `uv lock --upgrade-package <paquet>`), ce qui met à jour `pyproject.toml` et `uv.lock` à committer ensemble.

## Construire et lancer l'image Docker

```bash
docker build -t stdflow-cli:latest .
docker run --rm -p 8080:8080 --env-file .env stdflow-cli:latest
```

## Déployer sur Kubernetes

```bash
kubectl apply -f k8s/configmap.yaml
# Si client confidentiel : copier k8s/secret.example.yaml -> k8s/secret.yaml,
# renseigner le vrai secret, puis :
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
# Optionnel : adapter et appliquer k8s/ingress.example.yaml
```

⚠️ **Limitations à connaître :**
- **Un seul replica.** L'état d'une tentative de login (state OAuth,
  `code_verifier` PKCE, clé DPoP éphémère) est gardé en mémoire dans le
  process ; avec plusieurs replicas le callback peut atterrir sur un autre pod
  que celui qui a initié `/login` et échouer. Le `Deployment` fourni est figé à
  `replicas: 1`.
- **Outil de debug, pas un service de prod** : les tokens complets et le JWT
  décodé sont affichés dans la page et dans les logs du pod. À ne déployer que
  sur un accès restreint (réseau interne, auth au niveau de l'ingress, etc.),
  jamais exposé publiquement sans protection.
- Le décodage de JWT ne valide pas la signature.
