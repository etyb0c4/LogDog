# LogDog - IP Log Analyzer

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

An open-source system log analyzer for detecting and analyzing IP activities on Linux systems.

---

# English Documentation

## 🎯 Features

LogDog analyzes system log files to identify:
- **General IP Activity**: Counts occurrences of each IP address
- **Successful Logins**: Detects logged-in accounts with their authentication types
- **Active Terminals**: Analyzes `wtmp` files to identify active sessions

## 📋 Requirements

- Python 3.7 or higher
- No external dependencies (only Python standard libraries)

## 🚀 Installation

Clone the repository:
```bash
git clone https://github.com/votre-username/logdog.git
cd logdog
```

Make the script executable:
```bash
chmod +x logdog.py
```

## 📖 Usage

### Analyze a standard log file
```bash
python3 logdog.py -l /var/log/auth.log
```

### Analyze a wtmp file
```bash
python3 logdog.py -w /var/log/wtmp
```

### Analyze both file types
```bash
python3 logdog.py -l /var/log/auth.log -w /var/log/wtmp
```

### Display help
```bash
python3 logdog.py --help
```

## 📊 Output

The analysis produces three distinct sections:

### 1. General IP Activity
```
=== GENERAL IP ACTIVITY ===
[+] IP:   192.168.1.100       appears   47 times
[+] IP:   10.0.0.5            appears   23 times
```

### 2. Successful Logins / Compromises
```
=== SUCCESSFUL LOGINS / COMPROMISES ===
[SUCCESS] Account admin      by IP 192.168.1.100   with authentication type password   at 2024-01-15 14:30:22
```

### 3. Active Terminals
```
=== ACTIVATED TERMINALS ===
[WTMP SESSION] Active session detected from 192.168.1.100 at Thu Jul 16 00:04:15
```

## 🔍 Automatic Detection

LogDog automatically detects if a wtmp file is:
- A readable text file (e.g., `last` command output)
- A raw binary wtmp file (e.g., `/var/log/wtmp`)

It then uses the system's `last` tool to read binary files or reads the text directly if necessary.

## 🛡️ Use Cases

- **Security Audit**: Analyze server logs after a potential compromise
- **Monitoring**: Regular surveillance of suspicious IP addresses
- **Investigation**: Identify compromised accounts and active terminals

## ⚙️ Supported File Formats

### Standard log files (`.log`)
- `/var/log/auth.log` (Debian/Ubuntu)
- `/var/log/secure` (RHEL/CentOS)
- `/var/log/messages`

### wtmp files
- `/var/log/wtmp` (raw binary file)
- `/var/log/btmp` (failed login files)

## 📝 Examples

### Example 1 - Quick server analysis
```bash
python3 logdog.py -l /var/log/auth.log
```

### Example 2 - Full analysis with active sessions
```bash
python3 logdog.py -l /var/log/auth.log -w /var/log/wtmp
```

### Example 3 - Analysis with file redirection
```bash
python3 logdog.py -l /var/log/auth.log > analysis.log
```

## 🔧 Customization

The tool uses regular expressions to detect IPs and dates. Supported formats include:
- `YYYY-MM-DD HH:MM:SS`
- `YYYY/MM/DD HH:MM:SS`
- `DD Mon YYYY HH:MM:SS`
- Abbreviated format: `HH:MM:SS`

## 📄 License

This project is licensed under the MIT License. See the LICENSE file for more details.

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Open issues for bugs
- Submit pull requests for new features
- Improve the documentation

## 📧 Contact

For any questions or suggestions, please open an issue on GitHub, contact me directly or by ryansama.tech@gmail.com

## 🙏 Acknowledgments

This tool was created to simplify system log analysis in an easy and effective way.

---

# Documentation Française

## 🎯 Fonctionnalités

LogDog analyse les fichiers de logs système pour identifier:
- **Activités IP générales**: Compte le nombre d'apparitions de chaque adresse IP
- **Connexions réussies**: Détecte les comptes connectés avec leurs types d'authentification
- **Terminaux activés**: Analyse les fichiers `wtmp` pour identifier les sessions actives

## 📋 Prérequis

- Python 3.7 ou supérieur
- Aucune dépendance externe (seulement les bibliothèques standard Python)

## 🚀 Installation

Cloner le dépôt:
```bash
git clone https://github.com/votre-username/logdog.git
cd logdog
```

Rendre le script exécutable:
```bash
chmod +x logdog.py
```

## 📖 Utilisation

### Analyse d'un fichier de log standard
```bash
python3 logdog.py -l /var/log/auth.log
```

### Analyse d'un fichier wtmp
```bash
python3 logdog.py -w /var/log/wtmp
```

### Analyser les deux types de fichiers
```bash
python3 logdog.py -l /var/log/auth.log -w /var/log/wtmp
```

### Afficher l'aide
```bash
python3 logdog.py --help
```

## 📊 Sortie

L'analyse produit trois sections distinctes:

### 1. Activité IP Générale
```
=== GENERAL IP ACTIVITY ===
[+] IP:   192.168.1.100       appears   47 times
[+] IP:   10.0.0.5            appears   23 times
```

### 2. Connexions Réussies / Compromissions
```
=== SUCCESSFUL LOGINS / COMPROMISES ===
[SUCCESS] Account admin      by IP 192.168.1.100   with authentication type password   at 2024-01-15 14:30:22
```

### 3. Terminaux Activés
```
=== ACTIVATED TERMINALS ===
[WTMP SESSION] Active session detected from 192.168.1.100 at Thu Jul 16 00:04:15
```

## 🔍 Détection Automatique

LogDog détecte automatiquement si un fichier wtmp est:
- Un fichier texte lisible (ex: sortie de la commande `last`)
- Un fichier binaire wtmp brut (ex: `/var/log/wtmp`)

Il utilise ensuite l'outil `last` du système pour lire les fichiers binaires ou lit directement le texte si nécessaire.

## 🛡️ Cas d'Utilisation

- **Audit de sécurité**: Analyser les logs d'un serveur après une compromission potentielle
- **Surveillance**: Surveillance régulière des adresses IP suspectes
- **Investigation**: Identifier les comptes compromis et les terminaux actifs

## ⚙️ Format des Fichiers Supportés

### Fichiers de log standard (`.log`)
- `/var/log/auth.log` (Debian/Ubuntu)
- `/var/log/secure` (RHEL/CentOS)
- `/var/log/messages`

### Fichiers wtmp
- `/var/log/wtmp` (fichier binaire brut)
- `/var/log/btmp` (fichiers de connexion échouées)

## 📝 Exemples

### Exemple 1 - Analyse rapide d'un serveur
```bash
python3 logdog.py -l /var/log/auth.log
```

### Exemple 2 - Analyse complète avec sessions actives
```bash
python3 logdog.py -l /var/log/auth.log -w /var/log/wtmp
```

### Exemple 3 - Analyse avec redirection vers fichier
```bash
python3 logdog.py -l /var/log/auth.log > analyse.log
```

## 🔧 Personnalisation

L'outil utilise des expressions régulières pour détecter les IP et les dates. Les formats supportés incluent:
- `YYYY-MM-DD HH:MM:SS`
- `YYYY/MM/DD HH:MM:SS`
- `DD Mon YYYY HH:MM:SS`
- Format abrégé: `HH:MM:SS`

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à:
- Ouvrir des issues pour les bugs
- Soumettre des pull requests pour les nouvelles fonctionnalités
- Améliorer la documentation

## 📧 Contact

Pour toute question ou suggestion, n'hésitez pas à ouvrir une issue sur GitHub, me contacter directement ou par ryansama.tech@gmail.com

## 🙏 Remerciements

Cet outil a été créé pour faciliter l'analyse de logs système de manière simple et efficace.
