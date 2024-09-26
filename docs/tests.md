# TESTS

## A quoi servent les tests

Faire des tests avant de "pusher" du code est crucial pour plusieurs raisons :

- Détection précoce des erreurs : Les tests permettent de détecter les erreurs de manière précoce, avant qu'elles ne deviennent des problèmes dans le code en production. Cela réduit les risques d'erreurs et de dysfonctionnements dans les applications.
- Assurance de la qualité du code : Les tests garantissent que le code fonctionne correctement selon les spécifications définies. Cela garantit la qualité du code et réduit le nombre de bogues introduits dans le système.
- Maintenabilité du code : Les tests fournissent une documentation vivante du comportement attendu du code. Cela facilite la maintenance du code à long terme, car les développeurs peuvent comprendre rapidement comment le code devrait se comporter et identifier les impacts potentiels des modifications.
- Confiance dans les déploiements : En ayant des tests solides en place, les développeurs et les équipes de déploiement ont plus de confiance lorsqu'ils effectuent des déploiements. Cela réduit le stress et les risques associés aux mises à jour du logiciel.
- Réduction des coûts : En détectant les erreurs tôt dans le processus de développement, les tests contribuent à réduire les coûts associés à la correction des bogues dans les phases ultérieures du cycle de développement logiciel, où les corrections sont souvent plus coûteuses.

En somme, faire des tests avant de "pusher" du code permet d'améliorer la qualité du logiciel, de réduire les risques et les coûts associés aux erreurs, et de renforcer la confiance dans les processus de développement et de déploiement.


## Comment créer des tests

Les tests ont pour but de tester chaque fonction d'un projet, si toutes les fonctions sont correctes, alors le rendu final du projet est correct aussi.
Ils permettent donc en premier temps de vérifier si le projet renvoie bien ce qu'il faut, mais ils permettent notamment lors de la modification des scripts de vérifier si des erreurs de programmations ont été commise. 

## Implémentation dans le projet

Il faut creer en premier temps un dossier "tests"


### Nommages des fichiers scripts de tests

Dans celui-ci il faudra créer des fichiers scripts qui correspondes aux scripts que vous voulez tester:

script que nous voulons tester:       script_sae.py

test du script                        test_script_sae.py

### Nommage des fonctions de tests

Il faut faire exactement la meme chose que pour les fichiers, si la fonctions que nous voulons tester est "def launch_sae()" son test associé sera "def test_launch_sae"

Toutes les fonctions ayants "test" devant son noms, seront lancées automatiquement par Pytest, il faut bien entendu que celle-ci soient dans un fichiers tests_x.py.
