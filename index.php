<?php
session_start();
require_once 'includes/db.php';

if (isset($_POST['action']) && $_POST['action'] === 'login') {
    $login = $_POST['login'] ?? '';
    $mdp   = hash('sha256', $_POST['mot_de_passe'] ?? '');
    $stmt  = $pdo->prepare("SELECT * FROM UTILISATEUR WHERE login = :login AND mot_de_passe = :mdp");
    $stmt->execute([':login' => $login, ':mdp' => $mdp]);
    $user  = $stmt->fetch();
    if ($user) {
        $_SESSION['user'] = $user['login'];
    } else {
        $erreur = "Identifiants incorrects";
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}

if (isset($_GET['export']) && isset($_SESSION['user'])) {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="historique_' . date('Ymd_His') . '.csv"');
    $out = fopen('php://output', 'w');
    fputcsv($out, ['ID', 'Capteur', 'Type', 'Valeur', 'Date/Heure']);
    $rows = $pdo->query("
        SELECT m.id_mesure, c.emplacement, c.type, m.valeur, m.date_heure
        FROM MESURE m JOIN CAPTEUR c ON m.id_capteur = c.id_capteur
        ORDER BY m.date_heure DESC
    ")->fetchAll(PDO::FETCH_ASSOC);
    foreach ($rows as $row) fputcsv($out, $row);
    fclose($out);
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'add_auth' && isset($_SESSION['user'])) {
    $stmt = $pdo->prepare("INSERT INTO AUTORISATION (nom, prenom, login, email, autorise) VALUES (:nom, :prenom, :login, :email, :autorise)");
    $stmt->execute([
        ':nom'      => $_POST['nom'],
        ':prenom'   => $_POST['prenom'],
        ':login'    => $_POST['login'],
        ':email'    => $_POST['email'],
        ':autorise' => isset($_POST['autorise']) ? 1 : 0
    ]);
    header('Location: index.php?page=autorisations');
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'toggle_auth' && isset($_SESSION['user'])) {
    $stmt = $pdo->prepare("UPDATE AUTORISATION SET autorise = NOT autorise WHERE id_autorisation = :id");
    $stmt->execute([':id' => $_POST['id']]);
    header('Location: index.php?page=autorisations');
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'delete_auth' && isset($_SESSION['user'])) {
    $stmt = $pdo->prepare("DELETE FROM AUTORISATION WHERE id_autorisation = :id");
    $stmt->execute([':id' => $_POST['id']]);
    header('Location: index.php?page=autorisations');
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'marquer_lu' && isset($_SESSION['user'])) {
    $stmt = $pdo->prepare("UPDATE ALERTE SET statut = 'lu' WHERE id_alerte = :id");
    $stmt->execute([':id' => $_POST['id']]);
    header('Location: index.php?page=dashboard');
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'marquer_tout_lu' && isset($_SESSION['user'])) {
    $pdo->query("UPDATE ALERTE SET statut = 'lu' WHERE statut = 'non_lu'");
    header('Location: index.php?page=dashboard');
    exit;
}

$page = $_GET['page'] ?? 'dashboard';
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Supervision Baie</title>
<style>
  body { font-family: monospace; font-size: 14px; margin: 20px; background: #fff; color: #000; }
  a { color: #000; }
  nav { border-bottom: 1px solid #000; padding-bottom: 8px; margin-bottom: 16px; }
  nav a { margin-right: 16px; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
  th, td { border: 1px solid #000; padding: 6px 10px; text-align: left; }
  th { background: #eee; }
  input[type=text], input[type=password], input[type=email] { border: 1px solid #000; padding: 4px; margin-bottom: 6px; display: block; width: 200px; }
  button, .btn { border: 1px solid #000; background: #fff; padding: 4px 10px; cursor: pointer; font-family: monospace; font-size: 14px; }
  button:hover { background: #eee; }
  h2 { margin: 16px 0 8px 0; font-size: 15px; border-bottom: 1px solid #ccc; padding-bottom: 4px; }
  .erreur { color: red; }
  .info { margin-bottom: 16px; }
  .login-box { width: 260px; margin: 80px auto; border: 1px solid #000; padding: 20px; }
  .login-box h1 { font-size: 16px; margin-bottom: 12px; }
</style>
</head>
<body>

<?php if (!isset($_SESSION['user'])): ?>

<div class="login-box">
  <h1>Supervision Baie — Connexion</h1>
  <?php if (isset($erreur)): ?><p class="erreur"><?= $erreur ?></p><?php endif; ?>
  <form method="POST">
    <input type="hidden" name="action" value="login">
    <input type="text"     name="login"        placeholder="Identifiant">
    <input type="password" name="mot_de_passe" placeholder="Mot de passe">
    <button type="submit">Se connecter</button>
  </form>
</div>

<?php else: ?>

<nav>
  <strong>Supervision Baie</strong> |
  <a href="?page=dashboard">Tableau de bord</a>
  <a href="?page=autorisations">Autorisations</a>
  <a href="?logout=1">Deconnexion (<?= $_SESSION['user'] ?>)</a>
</nav>

<?php if ($page === 'dashboard'): ?>
<?php
$derniere_temp = $pdo->query("
    SELECT m.valeur, m.date_heure FROM MESURE m
    JOIN CAPTEUR c ON m.id_capteur = c.id_capteur
    WHERE c.type = 'temperature' ORDER BY m.date_heure DESC LIMIT 1
")->fetch(PDO::FETCH_ASSOC);

$derniere_ouverture = $pdo->query("
    SELECT m.valeur, m.date_heure FROM MESURE m
    JOIN CAPTEUR c ON m.id_capteur = c.id_capteur
    WHERE c.type = 'ouverture' ORDER BY m.date_heure DESC LIMIT 1
")->fetch(PDO::FETCH_ASSOC);

$nb_alertes = $pdo->query("SELECT COUNT(*) FROM ALERTE WHERE statut = 'non_lu'")->fetchColumn();

$mesures = $pdo->query("
    SELECT m.id_mesure, c.emplacement, c.type, m.valeur, m.date_heure
    FROM MESURE m JOIN CAPTEUR c ON m.id_capteur = c.id_capteur
    ORDER BY m.date_heure DESC LIMIT 50
")->fetchAll(PDO::FETCH_ASSOC);

$alertes = $pdo->query("
    SELECT a.id_alerte, a.type, a.statut, a.date_heure, m.valeur, d.email
    FROM ALERTE a
    JOIN MESURE m ON a.id_mesure = m.id_mesure
    JOIN CAPTEUR c ON m.id_capteur = c.id_capteur
    JOIN DESTINATAIRE d ON a.id_destinataire = d.id_destinataire
    ORDER BY a.date_heure DESC LIMIT 20
")->fetchAll(PDO::FETCH_ASSOC);
?>

<div class="info" id="info-live">
  Temperature : <strong id="temp-valeur"><?= $derniere_temp ? $derniere_temp['valeur'] . '°C' : '--' ?></strong>
  (<?= $derniere_temp ? date('d/m/Y H:i', strtotime($derniere_temp['date_heure'])) : '' ?>) |
  Baie : <strong id="baie-statut"><?= ($derniere_ouverture && $derniere_ouverture['valeur'] == 1) ? 'OUVERTE' : 'FERMEE' ?></strong>
  (<?= $derniere_ouverture ? date('d/m/Y H:i', strtotime($derniere_ouverture['date_heure'])) : '' ?>) |
  Alertes non lues : <strong id="nb-alertes"><?= $nb_alertes ?></strong> |
  <span id="last-update">--</span>
</div>

<h2>Historique des mesures — <a href="?export=1">Export CSV</a></h2>
<table>
  <thead><tr><th>#</th><th>Capteur</th><th>Type</th><th>Valeur</th><th>Date/Heure</th></tr></thead>
  <tbody id="tbody-mesures">
  <?php foreach ($mesures as $m): ?>
    <tr>
      <td><?= $m['id_mesure'] ?></td>
      <td><?= htmlspecialchars($m['emplacement']) ?></td>
      <td><?= $m['type'] === 'temperature' ? 'Temperature' : 'Ouverture' ?></td>
      <td><?= $m['type'] === 'temperature' ? $m['valeur'] . '°C' : ($m['valeur'] == 1 ? 'Ouverte' : 'Fermee') ?></td>
      <td><?= date('d/m/Y H:i:s', strtotime($m['date_heure'])) ?></td>
    </tr>
  <?php endforeach; ?>
  </tbody>
</table>

<h2>Alertes —
  <form method="POST" style="display:inline">
    <input type="hidden" name="action" value="marquer_tout_lu">
    <button type="submit">Tout marquer comme lu</button>
  </form>
</h2>
<table>
  <thead><tr><th>#</th><th>Type</th><th>Valeur</th><th>Destinataire</th><th>Statut</th><th>Date/Heure</th></tr></thead>
  <tbody id="tbody-alertes">
  <?php if (empty($alertes)): ?>
    <tr><td colspan="6">Aucune alerte</td></tr>
  <?php else: ?>
    <?php foreach ($alertes as $a): ?>
    <tr>
      <td><?= $a['id_alerte'] ?></td>
      <td><?= match($a['type']) {
        'temperature_haute' => 'Temperature haute',
        'temperature_basse' => 'Temperature basse',
        'ouverture_baie'    => 'Ouverture baie',
        default => $a['type']
      } ?></td>
      <td><?= $a['valeur'] ?></td>
      <td><?= htmlspecialchars($a['email']) ?></td>
      <td>
        <?= $a['statut'] ?>
        <?php if ($a['statut'] === 'non_lu'): ?>
          <form method="POST" style="display:inline">
            <input type="hidden" name="action" value="marquer_lu">
            <input type="hidden" name="id" value="<?= $a['id_alerte'] ?>">
            <button type="submit">Marquer lu</button>
          </form>
        <?php endif; ?>
      </td>
      <td><?= date('d/m/Y H:i:s', strtotime($a['date_heure'])) ?></td>
    </tr>
    <?php endforeach; ?>
  <?php endif; ?>
  </tbody>
</table>

<?php elseif ($page === 'autorisations'): ?>
<?php
$autorisations = $pdo->query("SELECT * FROM AUTORISATION ORDER BY autorise DESC, nom ASC")->fetchAll(PDO::FETCH_ASSOC);
?>

<h2>Ajouter un utilisateur</h2>
<form method="POST">
  <input type="hidden" name="action" value="add_auth">
  Nom : <input type="text" name="nom" required>
  Prenom : <input type="text" name="prenom" required>
  Login : <input type="text" name="login" required>
  Email : <input type="email" name="email">
  <label><input type="checkbox" name="autorise" checked> Autoriser l'acces</label><br><br>
  <button type="submit">Ajouter</button>
</form>

<h2>Liste des autorisations (<?= count($autorisations) ?> utilisateurs)</h2>
<table>
  <thead><tr><th>Nom</th><th>Prenom</th><th>Login</th><th>Email</th><th>Acces</th><th>Actions</th></tr></thead>
  <tbody>
  <?php foreach ($autorisations as $a): ?>
    <tr>
      <td><?= htmlspecialchars($a['nom']) ?></td>
      <td><?= htmlspecialchars($a['prenom']) ?></td>
      <td><?= htmlspecialchars($a['login']) ?></td>
      <td><?= htmlspecialchars($a['email']) ?></td>
      <td><?= $a['autorise'] ? 'Oui' : 'Non' ?></td>
      <td>
        <form method="POST" style="display:inline">
          <input type="hidden" name="action" value="toggle_auth">
          <input type="hidden" name="id" value="<?= $a['id_autorisation'] ?>">
          <button type="submit"><?= $a['autorise'] ? 'Refuser' : 'Autoriser' ?></button>
        </form>
        <form method="POST" style="display:inline" onsubmit="return confirm('Supprimer ?')">
          <input type="hidden" name="action" value="delete_auth">
          <input type="hidden" name="id" value="<?= $a['id_autorisation'] ?>">
          <button type="submit">Supprimer</button>
        </form>
      </td>
    </tr>
  <?php endforeach; ?>
  </tbody>
</table>

<?php endif; ?>

<script>
<?php if ($page === 'dashboard'): ?>
function refreshData() {
    fetch('api/data.php')
        .then(r => r.json())
        .then(data => {
            document.getElementById('last-update').textContent = 'MAJ : ' + new Date().toLocaleTimeString('fr-FR');
            if (data.temperature) document.getElementById('temp-valeur').textContent = data.temperature.valeur + '°C';
            if (data.ouverture)   document.getElementById('baie-statut').textContent = data.ouverture.valeur == 1 ? 'OUVERTE' : 'FERMEE';
            document.getElementById('nb-alertes').textContent = data.nb_alertes;

            const tbody = document.getElementById('tbody-mesures');
            tbody.innerHTML = '';
            data.mesures.forEach(m => {
                const valeur = m.type === 'temperature' ? m.valeur + '°C' : (m.valeur == 1 ? 'Ouverte' : 'Fermee');
                const type   = m.type === 'temperature' ? 'Temperature' : 'Ouverture';
                const d      = new Date(m.date_heure.replace(' ', 'T'));
                tbody.innerHTML += `<tr><td>${m.id_mesure}</td><td>${m.emplacement}</td><td>${type}</td><td>${valeur}</td><td>${d.toLocaleString('fr-FR')}</td></tr>`;
            });

            const tbodyA = document.getElementById('tbody-alertes');
            tbodyA.innerHTML = '';
            if (!data.alertes.length) {
                tbodyA.innerHTML = '<tr><td colspan="6">Aucune alerte</td></tr>';
            } else {
                const types = { temperature_haute: 'Temperature haute', temperature_basse: 'Temperature basse', ouverture_baie: 'Ouverture baie' };
                data.alertes.forEach(a => {
                    const d   = new Date(a.date_heure.replace(' ', 'T'));
                    const btn = a.statut === 'non_lu'
                        ? `<form method="POST" style="display:inline"><input type="hidden" name="action" value="marquer_lu"><input type="hidden" name="id" value="${a.id_alerte}"><button type="submit">Marquer lu</button></form>`
                        : '';
                    tbodyA.innerHTML += `<tr><td>${a.id_alerte}</td><td>${types[a.type]||a.type}</td><td>${a.valeur}</td><td>${a.email}</td><td>${a.statut} ${btn}</td><td>${d.toLocaleString('fr-FR')}</td></tr>`;
                });
            }
        });
}
setInterval(refreshData, 5000);
refreshData();
<?php endif; ?>
</script>

<?php endif; ?>
</body>
</html>
