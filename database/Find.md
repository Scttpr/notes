- **URL :** https://www.funix.org/fr/unix/grep-find.htm
- **Description :** La commande **find** permet de retrouver des fichiers à partir de certains critères
- **Platforms :** [[Unix]]
- **Category :** [[Tools]]
- **Tags :** [[CLI]]

## Syntaxe

```
find <répertoire de recherche> <critères de recherche>
```

Les critères de recherche sont les suivants :
- **-name** recherche sur le nom du fichier,
- **-perm** recherche sur les droits d'accès du fichier,
- **-links** recherche sur le nombre de liens du fichier,
- **-user** recherche sur le propriétaire du fichier,
- **-group** recherche sur le groupe auquel appartient le fichier,
- **-type** recherche sur le type (d=répertoire, c=caractère, f=fichier normal),
- **-size** recherche sur la taille du fichier en nombre de blocs (1 bloc=512octets),
- **-atime** recherche par date de dernier accès en lecture du fichier,
- **-mtime** recherche par date de dernière modification du fichier,
- **-ctime** recherche par date de création du fichier.

On peut combiner les critères avec des opérateurs logiques :
- **critère1 critère2** ou **critère1 -a critère2** correspond au **et** logique,
- **!critère** non logique,
- **\ (critère1 -o critère2\)** ou logique

```
find . -name toto -exec rm {}\;
```