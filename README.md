# SAE501 - SAE502

### Membres

- Léo BRUALLA
    - Interface Graphique
    - Analyse DHCP
- Justin RALITE
    - Sonde DNS
    - Sonde DHCP
- Joey GALIGANI
    - Analyse DNS
    - Modularité
- Elouan FIORE
    - API
    - Base de donnée

### Documentations
- [Utilisateur](docs/Interface-Utilisateur.md)
- [Tests](docs/tests.md)
- [Developpeur/Installation](docs/dev_install.md)
- API (http://\<serveur_api\>:8000/docs)

### Fonctionnalités  non implémentés

#### Serveurs DHCP autorisés
- Présent sur l'API
- Présent sur le moteur d'analyse DHCP
- Absent de l'interface graphique

#### Serveurs DNS autorisés
- Présent sur le moteur d'analyse DNS
- Absent sur l'API
- Absent de l'interface graphique

#### Domaines DNS dangereux
- Présent sur le moteur d'analyse DNS
- Absent sur l'API
- Absent de l'interface graphique

#### Statisques DNS
- Présent sur le moteur d'analyse DNS
- Présent sur l'API
- Absent de l'interface graphique