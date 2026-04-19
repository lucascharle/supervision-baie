<?php
session_start();
require_once 'includes/db.php';

// ── CONFIG LDAP ──
define('LDAP_HOST',   '10.1.40.44');
define('LDAP_DOMAIN', 'orange.local');
define('LDAP_USER',   'Administrateur@orange.local');
define('LDAP_PASS',   'h3RgFdEyC3V5dCHWBWnx');
define('LDAP_BASE',   'DC=orange,DC=local');
define('LDAP_OU',     'OU=Baie,DC=orange,DC=local');

function ldap_connect_ad() {
    putenv('LDAPTLS_REQCERT=never');
    $conn = ldap_connect('ldaps://' . LDAP_HOST . ':636');
    if (!$conn) return false;
    ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($conn, LDAP_OPT_REFERRALS, 0);
    ldap_set_option($conn, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_NEVER);
    if (!@ldap_bind($conn, LDAP_USER, LDAP_PASS)) return false;
    return $conn;
}

// Créer un utilisateur dans l'AD
function ldap_create_user($nom, $prenom, $login, $email) {
    $conn = ldap_connect_ad();
    if (!$conn) return ['ok' => false, 'msg' => 'Connexion AD impossible'];
    $dn  = "CN={$prenom} {$nom}," . LDAP_OU;
    $upn = "{$login}@" . LDAP_DOMAIN;
    $entry = [
        'objectClass'       => ['top', 'person', 'organizationalPerson', 'user'],
        'cn'                => "{$prenom} {$nom}",
        'sAMAccountName'    => $login,
        'userPrincipalName' => $upn,
        'givenName'         => $prenom,
        'sn'                => $nom,
        'displayName'       => "{$prenom} {$nom}",
        'mail'              => $email,
        'userAccountControl'=> '512',
    ];
    if (@ldap_add($conn, $dn, $entry)) {
        ldap_close($conn);
        return ['ok' => true, 'msg' => "Utilisateur {$login} créé dans l'AD (OU=Baie)"];
    }
    $err = ldap_error($conn);
    ldap_close($conn);
    return ['ok' => false, 'msg' => 'Erreur AD : ' . $err];
}

// Supprimer un utilisateur dans l'AD
function ldap_delete_user($login) {
    $conn = ldap_connect_ad();
    if (!$conn) return false;
    $search = ldap_search($conn, LDAP_BASE, "(sAMAccountName={$login})", ['dn']);
    $entries = ldap_get_entries($conn, $search);
    if ($entries['count'] > 0) {
        @ldap_delete($conn, $entries[0]['dn']);
    }
    ldap_close($conn);
    return true;
}

// Importer les utilisateurs AD vers la BDD
function ldap_import_users($pdo) {
    $conn = ldap_connect_ad();
    if (!$conn) return ['ok' => false, 'msg' => 'Connexion AD impossible'];
    $search  = ldap_search($conn, LDAP_OU, '(&(objectClass=user)(objectCategory=person))', ['sAMAccountName','givenName','sn','mail','userAccountControl']);
    $entries = ldap_get_entries($conn, $search);
    $imported = 0;
    for ($i = 0; $i < $entries['count']; $i++) {
        $e      = $entries[$i];
        $login  = $e['samaccountname'][0] ?? '';
        $prenom = $e['givenname'][0] ?? '';
        $nom    = $e['sn'][0] ?? $login;
        $email  = $e['mail'][0] ?? '';
        $uac    = (int)($e['useraccountcontrol'][0] ?? 512);
        $active = !($uac & 2) ? 1 : 0;
        if (empty($login)) continue;
        $exists = $pdo->prepare("SELECT COUNT(*) FROM AUTORISATION WHERE login = :l");
        $exists->execute([':l' => $login]);
        if ($exists->fetchColumn() == 0) {
            $pdo->prepare("INSERT INTO AUTORISATION (nom, prenom, login, email, autorise) VALUES (:n,:p,:l,:e,:a)")
                ->execute([':n'=>$nom,':p'=>$prenom,':l'=>$login,':e'=>$email,':a'=>$active]);
            $imported++;
        }
    }
    ldap_close($conn);
    return ['ok' => true, 'msg' => "{$imported} utilisateur(s) importé(s) depuis l'AD (OU=Baie)"];
}

if (isset($_POST['action']) && $_POST['action'] === 'login') {
    $login = $_POST['login'] ?? '';
    $mdp   = hash('sha256', $_POST['mot_de_passe'] ?? '');
    $stmt  = $pdo->prepare("SELECT * FROM UTILISATEUR WHERE login = :login AND mot_de_passe = :mdp");
    $stmt->execute([':login' => $login, ':mdp' => $mdp]);
    $user  = $stmt->fetch();
    if ($user) { $_SESSION['user'] = $user['login']; }
    else { $erreur = "Identifiants incorrects"; }
}
if (isset($_GET['logout'])) { session_destroy(); header('Location: index.php'); exit; }
if (isset($_GET['test_alerte']) && isset($_SESSION['user'])) {
    // Récupère la dernière mesure et le premier destinataire
    $last = $pdo->query("SELECT id_mesure FROM MESURE ORDER BY date_heure DESC LIMIT 1")->fetchColumn();
    $dest = $pdo->query("SELECT id_destinataire FROM DESTINATAIRE LIMIT 1")->fetchColumn();
    if ($last && $dest) {
        $pdo->prepare("INSERT INTO ALERTE (type, statut, date_heure, id_mesure, id_destinataire) VALUES ('temperature_haute', 'non_lu', NOW(), :m, :d)")
            ->execute([':m' => $last, ':d' => $dest]);
    }
    header('Location: index.php?page=dashboard'); exit;
}
if (isset($_GET['export']) && isset($_SESSION['user'])) {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="historique_' . date('Ymd_His') . '.csv"');
    $out = fopen('php://output', 'w');
    fputcsv($out, ['ID', 'Capteur', 'Type', 'Valeur', 'Date/Heure']);
    $rows = $pdo->query("SELECT m.id_mesure, c.emplacement, c.type, m.valeur, m.date_heure FROM MESURE m JOIN CAPTEUR c ON m.id_capteur = c.id_capteur ORDER BY m.date_heure DESC")->fetchAll(PDO::FETCH_ASSOC);
    foreach ($rows as $row) fputcsv($out, $row);
    fclose($out); exit;
}
if (isset($_POST['action']) && $_POST['action'] === 'add_auth' && isset($_SESSION['user'])) {
    $nom    = $_POST['nom'];
    $prenom = $_POST['prenom'];
    $login  = $_POST['login'];
    $email  = $_POST['email'];
    $auto   = isset($_POST['autorise']) ? 1 : 0;
    // Insérer en BDD
    $pdo->prepare("INSERT INTO AUTORISATION (nom, prenom, login, email, autorise) VALUES (:n,:p,:l,:e,:a)")
        ->execute([':n'=>$nom,':p'=>$prenom,':l'=>$login,':e'=>$email,':a'=>$auto]);
    // Créer dans l'AD
    $ldap_result = ldap_create_user($nom, $prenom, $login, $email);
    $_SESSION['notif'] = $ldap_result['msg'];
    header('Location: index.php?page=autorisations'); exit;
}
if (isset($_GET['toggle_auth']) && isset($_SESSION['user'])) {
    $pdo->prepare("UPDATE AUTORISATION SET autorise = NOT autorise WHERE id_autorisation = :id")->execute([':id'=>(int)$_GET['toggle_auth']]);
    header('Location: index.php?page=autorisations'); exit;
}
if (isset($_GET['delete_auth']) && isset($_SESSION['user'])) {
    // Récupérer le login avant suppression
    $row = $pdo->prepare("SELECT login FROM AUTORISATION WHERE id_autorisation = :id");
    $row->execute([':id'=>(int)$_GET['delete_auth']]);
    $u = $row->fetch();
    if ($u) ldap_delete_user($u['login']);
    $pdo->prepare("DELETE FROM AUTORISATION WHERE id_autorisation = :id")->execute([':id'=>(int)$_GET['delete_auth']]);
    header('Location: index.php?page=autorisations'); exit;
}
if (isset($_POST['action']) && $_POST['action'] === 'import_ad' && isset($_SESSION['user'])) {
    $result = ldap_import_users($pdo);
    $_SESSION['notif'] = $result['msg'];
    header('Location: index.php?page=autorisations'); exit;
}
if (isset($_POST['action']) && $_POST['action'] === 'marquer_lu' && isset($_SESSION['user'])) {
    $pdo->prepare("UPDATE ALERTE SET statut = 'lu' WHERE id_alerte = :id")->execute([':id'=>$_POST['id']]);
    header('Location: index.php?page=dashboard'); exit;
}
if (isset($_POST['action']) && $_POST['action'] === 'marquer_tout_lu' && isset($_SESSION['user'])) {
    $pdo->query("UPDATE ALERTE SET statut = 'lu' WHERE statut = 'non_lu'");
    header('Location: index.php?page=dashboard'); exit;
}
if (isset($_POST['action']) && $_POST['action'] === 'save_config' && isset($_SESSION['user'])) {
    foreach (['seuil_temp_haute','seuil_temp_basse','email_alerte','intervalle_refresh'] as $k) {
        if (isset($_POST[$k])) {
            $pdo->prepare("INSERT INTO CONFIG (cle,valeur) VALUES (:k,:v) ON DUPLICATE KEY UPDATE valeur=:v2")
                ->execute([':k'=>$k,':v'=>$_POST[$k],':v2'=>$_POST[$k]]);
        }
    }
    header('Location: index.php?page=gestion&saved=1'); exit;
}
if (isset($_POST['action']) && $_POST['action'] === 'add_dest' && isset($_SESSION['user'])) {
    $pdo->prepare("INSERT INTO DESTINATAIRE (email) VALUES (:e)")->execute([':e'=>$_POST['email']]);
    header('Location: index.php?page=gestion'); exit;
}
if (isset($_GET['del_dest']) && isset($_SESSION['user'])) {
    $pdo->prepare("DELETE FROM DESTINATAIRE WHERE id_destinataire=:id")->execute([':id'=>(int)$_GET['del_dest']]);
    header('Location: index.php?page=gestion'); exit;
}
$page = $_GET['page'] ?? 'dashboard';
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Supervision Baie</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg:      #0c0e14;
  --bg2:     #13151e;
  --bg3:     #1a1d29;
  --border:  rgba(255,255,255,0.07);
  --accent:  #2dd4bf;
  --purple:  #a78bfa;
  --green:   #34d399;
  --red:     #f87171;
  --orange:  #fb923c;
  --text:    #f1f5f9;
  --muted:   #64748b;
  --sw:      220px;
}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;
  background-image:
    radial-gradient(ellipse 70% 50% at 10% 0%,   rgba(167,139,250,.12) 0%,transparent 60%),
    radial-gradient(ellipse 50% 40% at 90% 100%,  rgba(45,212,191,.10) 0%,transparent 55%),
    radial-gradient(ellipse 40% 35% at 80% 10%,   rgba(244,114,182,.08) 0%,transparent 50%);
  background-attachment:fixed;
}

/* ══ LOGIN ══ */
.lp{min-height:100vh;display:flex;align-items:center;justify-content:center;position:relative;overflow:hidden;}
.orb{position:absolute;border-radius:50%;filter:blur(70px);pointer-events:none;}
.o1{width:500px;height:500px;background:rgba(167,139,250,.15);top:-150px;left:-150px;animation:of 10s ease-in-out infinite;}
.o2{width:400px;height:400px;background:rgba(45,212,191,.12);bottom:-100px;right:-100px;animation:of 13s ease-in-out infinite reverse;}
.o3{width:250px;height:250px;background:rgba(244,114,182,.10);top:40%;left:55%;animation:of 8s ease-in-out infinite 2s;}
@keyframes of{0%,100%{transform:translate(0,0) scale(1);}50%{transform:translate(25px,-20px) scale(1.06);}}

.lc{
  position:relative;z-index:5;width:440px;
  background:rgba(255,255,255,.05);
  backdrop-filter:blur(48px) saturate(180%);
  -webkit-backdrop-filter:blur(48px) saturate(180%);
  border:1px solid rgba(255,255,255,.12);
  border-radius:28px;padding:52px 44px;
  box-shadow:0 40px 100px rgba(0,0,0,.55),inset 0 1px 0 rgba(255,255,255,.1);
  animation:ci .7s cubic-bezier(.16,1,.3,1);
}
@keyframes ci{from{opacity:0;transform:translateY(28px) scale(.97);}to{opacity:1;transform:none;}}

.lbrand{display:flex;align-items:center;gap:13px;margin-bottom:38px;}
.lbicon{
  width:50px;height:50px;border-radius:15px;
  background:linear-gradient(135deg,var(--purple),var(--accent));
  display:flex;align-items:center;justify-content:center;font-size:22px;
  box-shadow:0 8px 24px rgba(167,139,250,.35);
}
.lbn{font-family:'Space Grotesk',sans-serif;font-size:19px;font-weight:700;letter-spacing:.5px;}
.lbs{font-size:11px;color:var(--muted);margin-top:2px;}
.ltitle{font-family:'Space Grotesk',sans-serif;font-size:30px;font-weight:700;margin-bottom:6px;
  background:linear-gradient(135deg,#fff 0%,rgba(255,255,255,.65) 100%);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;}
.lsub{font-size:14px;color:var(--muted);margin-bottom:34px;}

.ig{position:relative;margin-bottom:18px;}
.ig label{display:block;font-size:11px;font-weight:600;color:var(--muted);letter-spacing:.8px;text-transform:uppercase;margin-bottom:8px;}
.ig input{
  width:100%;background:rgba(255,255,255,.05);
  border:1px solid rgba(255,255,255,.1);border-radius:13px;
  padding:14px 16px 14px 46px;color:var(--text);
  font-family:'Inter',sans-serif;font-size:14px;outline:none;transition:all .2s;
}
.ig input:focus{border-color:var(--accent);background:rgba(45,212,191,.05);box-shadow:0 0 0 3px rgba(45,212,191,.12);}
.ig-icon{position:absolute;bottom:14px;left:15px;font-size:17px;opacity:.35;}
.err{background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.25);border-radius:11px;padding:12px 15px;color:var(--red);font-size:13px;margin-bottom:18px;display:flex;align-items:center;gap:8px;}
.lbtn{
  width:100%;margin-top:6px;padding:15px;
  background:linear-gradient(135deg,var(--purple),var(--accent));
  color:#fff;border:none;border-radius:13px;
  font-family:'Space Grotesk',sans-serif;font-size:15px;font-weight:600;letter-spacing:.5px;
  cursor:pointer;transition:all .2s;box-shadow:0 10px 28px rgba(167,139,250,.28);
}
.lbtn:hover{transform:translateY(-2px);box-shadow:0 14px 36px rgba(167,139,250,.38);}

/* ══ LAYOUT ══ */
.layout{display:flex;min-height:100vh;}

/* ══ SIDEBAR ══ */
.sidebar{
  width:var(--sw);
  background:rgba(19,21,30,.85);
  backdrop-filter:blur(30px);-webkit-backdrop-filter:blur(30px);
  border-right:1px solid var(--border);
  display:flex;flex-direction:column;
  position:fixed;top:0;left:0;height:100vh;z-index:100;
}
.sb-top{padding:22px 16px;border-bottom:1px solid var(--border);}
.sb-brand{display:flex;align-items:center;gap:10px;margin-bottom:20px;}
.sb-logo{
  width:36px;height:36px;border-radius:10px;
  background:linear-gradient(135deg,var(--purple),var(--accent));
  display:flex;align-items:center;justify-content:center;font-size:16px;
  box-shadow:0 4px 12px rgba(167,139,250,.3);flex-shrink:0;
}
.sb-bname{font-family:'Space Grotesk',sans-serif;font-size:14px;font-weight:700;}
.sb-bsub{font-size:10px;color:var(--muted);}
.sb-user{
  display:flex;align-items:center;gap:10px;
  background:rgba(255,255,255,.04);border:1px solid var(--border);
  border-radius:12px;padding:10px 12px;
}
.sb-av{
  width:32px;height:32px;border-radius:50%;
  background:linear-gradient(135deg,#667eea,#764ba2);
  display:flex;align-items:center;justify-content:center;
  font-size:13px;font-weight:600;flex-shrink:0;
}
.sb-un{font-size:12px;font-weight:500;}
.sb-ur{font-size:10px;color:var(--muted);}

.sb-nav{flex:1;padding:12px 10px;display:flex;flex-direction:column;gap:2px;overflow-y:auto;}
.sb-sec{font-size:9px;font-weight:700;color:var(--muted);letter-spacing:1.2px;text-transform:uppercase;padding:10px 8px 5px;}
.sb-item{
  display:flex;align-items:center;gap:9px;padding:9px 11px;border-radius:10px;
  color:var(--muted);text-decoration:none;font-size:13px;font-weight:500;
  transition:all .15s;border:1px solid transparent;
}
.sb-item:hover{background:rgba(255,255,255,.05);color:var(--text);}
.sb-item.on{background:linear-gradient(135deg,rgba(167,139,250,.15),rgba(45,212,191,.08));color:var(--accent);border-color:rgba(45,212,191,.18);}
.sb-ic{font-size:15px;width:18px;text-align:center;}
.sb-bot{padding:10px;border-top:1px solid var(--border);}

/* ══ MAIN ══ */
.main{margin-left:var(--sw);flex:1;min-width:0;}

/* ══ TOPBAR ══ */
.topbar{
  display:flex;align-items:center;justify-content:space-between;
  padding:16px 26px;
  background:rgba(12,14,20,.75);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  border-bottom:1px solid var(--border);
  position:sticky;top:0;z-index:50;
}
.tb-left h1{font-family:'Space Grotesk',sans-serif;font-size:20px;font-weight:700;}
.tb-left p{font-size:12px;color:var(--muted);margin-top:2px;}
.live-pill{
  display:flex;align-items:center;gap:7px;
  background:rgba(52,211,153,.08);border:1px solid rgba(52,211,153,.2);
  border-radius:20px;padding:6px 14px;font-size:12px;color:var(--green);font-weight:500;
}
.ldot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:pu 2s infinite;}
@keyframes pu{0%,100%{opacity:1;}50%{opacity:.3;}}

/* ══ CONTENT ══ */
.content{padding:24px 26px;}

/* ══ WELCOME ══ */
.welcome{margin-bottom:22px;}
.welcome h2{font-family:'Space Grotesk',sans-serif;font-size:24px;font-weight:700;}
.welcome p{font-size:13px;color:var(--muted);margin-top:3px;}

/* ══ STAT CARDS ══ */
.scards{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:22px;}
.sc{
  background:rgba(255,255,255,.04);
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  border:1px solid var(--border);border-radius:18px;padding:20px;
  position:relative;overflow:hidden;transition:all .2s;
}
.sc:hover{transform:translateY(-3px);border-color:rgba(255,255,255,.12);box-shadow:0 14px 40px rgba(0,0,0,.35);}
.sc-glow{position:absolute;top:-50px;right:-50px;width:130px;height:130px;border-radius:50%;opacity:.12;filter:blur(35px);}
.sc.ct .sc-glow{background:var(--orange);}
.sc.cb .sc-glow{background:var(--green);}
.sc.ca .sc-glow{background:var(--red);}
.sc-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;}
.sc-label{font-size:11px;font-weight:600;color:var(--muted);letter-spacing:.8px;text-transform:uppercase;}
.sc-badge{width:36px;height:36px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:16px;}
.sc.ct .sc-badge{background:rgba(251,146,60,.15);}
.sc.cb .sc-badge{background:rgba(52,211,153,.15);}
.sc.ca .sc-badge{background:rgba(248,113,113,.15);}
.sc-val{font-family:'Space Grotesk',sans-serif;font-size:34px;font-weight:700;line-height:1;margin-bottom:5px;}
.sc.ct .sc-val{color:var(--orange);}
.sc.cb .sc-val{color:var(--green);}
.sc.ca .sc-val{color:var(--red);}
.sc-sub{font-size:11px;color:var(--muted);}
.srow{display:flex;align-items:center;gap:8px;margin-bottom:5px;}
.sd{width:9px;height:9px;border-radius:50%;}
.sd-g{background:var(--green);box-shadow:0 0 8px var(--green);}
.sd-r{background:var(--red);box-shadow:0 0 8px var(--red);}

/* ══ 2-COL GRID ══ */
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:22px;}

/* ══ SECTION ══ */
.sec{
  background:rgba(255,255,255,.04);
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  border:1px solid var(--border);border-radius:18px;overflow:hidden;margin-bottom:18px;
}
.sec-h{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid var(--border);}
.sec-h h2{font-family:'Space Grotesk',sans-serif;font-size:14px;font-weight:600;}

/* ══ TABLE ══ */
table{width:100%;border-collapse:collapse;}
thead th{background:rgba(0,0,0,.25);padding:10px 16px;font-size:10px;font-weight:600;color:var(--muted);letter-spacing:1px;text-transform:uppercase;text-align:left;border-bottom:1px solid var(--border);}
tbody td{padding:12px 16px;font-size:13px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:middle;}
tbody tr:last-child td{border-bottom:none;}
tbody tr:hover td{background:rgba(255,255,255,.02);}

/* ══ BADGE ══ */
.b{display:inline-flex;align-items:center;padding:3px 9px;border-radius:20px;font-size:11px;font-weight:600;}
.bg{background:rgba(52,211,153,.12);color:var(--green);border:1px solid rgba(52,211,153,.2);}
.br{background:rgba(248,113,113,.12);color:var(--red);border:1px solid rgba(248,113,113,.2);}
.bo{background:rgba(251,146,60,.12);color:var(--orange);border:1px solid rgba(251,146,60,.2);}
.bp{background:rgba(167,139,250,.12);color:var(--purple);border:1px solid rgba(167,139,250,.2);}

/* ══ BUTTONS ══ */
.btn{display:inline-flex;align-items:center;gap:5px;padding:7px 14px;border-radius:9px;font-family:'Inter',sans-serif;font-size:12px;font-weight:500;cursor:pointer;border:none;transition:all .15s;text-decoration:none;}
.btn-t{background:rgba(45,212,191,.1);color:var(--accent);border:1px solid rgba(45,212,191,.2);}
.btn-t:hover{background:rgba(45,212,191,.18);}
.btn-g{background:rgba(52,211,153,.1);color:var(--green);border:1px solid rgba(52,211,153,.2);}
.btn-g:hover{background:rgba(52,211,153,.18);}
.btn-r{background:rgba(248,113,113,.1);color:var(--red);border:1px solid rgba(248,113,113,.2);}
.btn-r:hover{background:rgba(248,113,113,.18);}
.btn-gr{background:rgba(100,116,139,.1);color:var(--muted);border:1px solid rgba(100,116,139,.15);}
.btn-gr:hover{background:rgba(100,116,139,.18);color:var(--text);}
.btn-sm{padding:4px 9px;font-size:11px;border-radius:7px;}

/* ══ FORM ══ */
.fgrid{display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:20px;}
.fg{display:flex;flex-direction:column;gap:6px;}
.fg label{font-size:10px;font-weight:600;color:var(--muted);letter-spacing:.8px;text-transform:uppercase;}
.fg input{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:9px;padding:10px 12px;color:var(--text);font-family:'Inter',sans-serif;font-size:13px;outline:none;transition:all .2s;}
.fg input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(45,212,191,.1);}
.ffoot{padding:0 20px 20px;display:flex;align-items:center;gap:12px;}
.ck{display:flex;align-items:center;gap:7px;font-size:13px;color:var(--muted);}
.ck input{accent-color:var(--accent);width:14px;height:14px;}
</style>
</head>
<body>

<?php if (!isset($_SESSION['user'])): ?>
<!-- LOGIN -->
<div class="lp">
  <div class="orb o1"></div><div class="orb o2"></div><div class="orb o3"></div>
  <div class="lc">
    <div class="lbrand">
      <div class="lbicon"></div>
      <div><div class="lbn">SUPERVISION</div><div class="lbs">Système de monitoring</div></div>
    </div>
    <div class="ltitle">Bienvenue</div>
    <div class="lsub">Connectez-vous à votre espace de supervision</div>
    <?php if(isset($erreur)): ?><div class="err"> <?= $erreur ?></div><?php endif; ?>
    <form method="POST">
      <input type="hidden" name="action" value="login">
      <div class="ig">
        <label>Identifiant</label>
        <span class="ig-icon"></span>
        <input type="text" name="login" placeholder="Votre identifiant" autofocus>
      </div>
      <div class="ig">
        <label>Mot de passe</label>
        <span class="ig-icon"></span>
        <input type="password" name="mot_de_passe" placeholder="••••••••">
      </div>
      <button type="submit" class="lbtn">SE CONNECTER</button>
    </form>
  </div>
</div>

<?php else:
if ($page==='dashboard') {
    $dt = $pdo->query("SELECT m.valeur,m.date_heure FROM MESURE m JOIN CAPTEUR c ON m.id_capteur=c.id_capteur WHERE c.type='temperature' ORDER BY m.date_heure DESC LIMIT 1")->fetch(PDO::FETCH_ASSOC);
    $do = $pdo->query("SELECT m.valeur,m.date_heure FROM MESURE m JOIN CAPTEUR c ON m.id_capteur=c.id_capteur WHERE c.type='ouverture' ORDER BY m.date_heure DESC LIMIT 1")->fetch(PDO::FETCH_ASSOC);
    $na = $pdo->query("SELECT COUNT(*) FROM ALERTE WHERE statut='non_lu'")->fetchColumn();
    $ms = $pdo->query("SELECT m.id_mesure,c.emplacement,c.type,m.valeur,m.date_heure FROM MESURE m JOIN CAPTEUR c ON m.id_capteur=c.id_capteur ORDER BY m.date_heure DESC LIMIT 50")->fetchAll(PDO::FETCH_ASSOC);
    $al = $pdo->query("SELECT a.id_alerte,a.type,a.statut,a.date_heure,m.valeur,d.email FROM ALERTE a JOIN MESURE m ON a.id_mesure=m.id_mesure JOIN CAPTEUR c ON m.id_capteur=c.id_capteur JOIN DESTINATAIRE d ON a.id_destinataire=d.id_destinataire ORDER BY a.date_heure DESC LIMIT 20")->fetchAll(PDO::FETCH_ASSOC);
    $open = $do && $do['valeur']==1;
    $tv = $dt ? $dt['valeur'] : '--';
}
if ($page==='autorisations') {
    $auths = $pdo->query("SELECT * FROM AUTORISATION ORDER BY id_autorisation ASC")->fetchAll(PDO::FETCH_ASSOC);
}
if ($page==='statistiques') {
    // Temp moyenne/min/max sur 24h
    $stats_temp = $pdo->query("SELECT ROUND(AVG(m.valeur),1) as moy, MIN(m.valeur) as min, MAX(m.valeur) as max FROM MESURE m JOIN CAPTEUR c ON m.id_capteur=c.id_capteur WHERE c.type='temperature' AND m.date_heure >= NOW() - INTERVAL 24 HOUR")->fetch(PDO::FETCH_ASSOC);
    // Courbe température 24h (par heure)
    $courbe = $pdo->query("SELECT DATE_FORMAT(m.date_heure,'%H:%i') as heure, ROUND(AVG(m.valeur),1) as val FROM MESURE m JOIN CAPTEUR c ON m.id_capteur=c.id_capteur WHERE c.type='temperature' AND m.date_heure >= NOW() - INTERVAL 24 HOUR GROUP BY DATE_FORMAT(m.date_heure,'%Y-%m-%d %H'), DATE_FORMAT(m.date_heure,'%H:%i') ORDER BY MIN(m.date_heure) ASC")->fetchAll(PDO::FETCH_ASSOC);
    // Nombre d'alertes par type
    $alertes_type = $pdo->query("SELECT type, COUNT(*) as nb FROM ALERTE GROUP BY type")->fetchAll(PDO::FETCH_ASSOC);
    // Nb ouvertures baie aujourd'hui
    $nb_ouvertures = $pdo->query("SELECT COUNT(*) FROM MESURE m JOIN CAPTEUR c ON m.id_capteur=c.id_capteur WHERE c.type='ouverture' AND m.valeur=1 AND DATE(m.date_heure)=CURDATE()")->fetchColumn();
    // Total mesures
    $total_mesures = $pdo->query("SELECT COUNT(*) FROM MESURE")->fetchColumn();
    // Total alertes
    $total_alertes = $pdo->query("SELECT COUNT(*) FROM ALERTE")->fetchColumn();
}
if ($page==='gestion') {
    // Seuils depuis une table CONFIG (on crée si pas encore)
    try {
        $seuils = $pdo->query("SELECT * FROM CONFIG")->fetchAll(PDO::FETCH_KEY_PAIR);
    } catch(Exception $e) {
        $pdo->query("CREATE TABLE IF NOT EXISTS CONFIG (cle VARCHAR(50) PRIMARY KEY, valeur VARCHAR(255))");
        $pdo->query("INSERT IGNORE INTO CONFIG VALUES ('seuil_temp_haute','35'),('seuil_temp_basse','10'),('email_alerte',''),('intervalle_refresh','5')");
        $seuils = $pdo->query("SELECT * FROM CONFIG")->fetchAll(PDO::FETCH_KEY_PAIR);
    }
    // Destinataires
    $destinataires = $pdo->query("SELECT * FROM DESTINATAIRE")->fetchAll(PDO::FETCH_ASSOC);
    // Capteurs
    $capteurs = $pdo->query("SELECT * FROM CAPTEUR")->fetchAll(PDO::FETCH_ASSOC);
}
?>

<!-- DASHBOARD LAYOUT -->
<div class="layout">
  <!-- SIDEBAR -->
  <aside class="sidebar">
    <div class="sb-top">
      <div class="sb-brand">
        <div class="sb-logo"></div>
        <div><div class="sb-bname">SUPERVISION</div><div class="sb-bsub">Monitoring baie</div></div>
      </div>
      <div class="sb-user">
        <div class="sb-av"><?= strtoupper(substr($_SESSION['user'],0,1)) ?></div>
        <div><div class="sb-un"><?= htmlspecialchars($_SESSION['user']) ?></div><div class="sb-ur">Administrateur</div></div>
      </div>
    </div>
    <nav class="sb-nav">
      <div class="sb-sec">Menu</div>
      <a href="?page=dashboard"     class="sb-item <?= $page==='dashboard'?'on':'' ?>"><span class="sb-ic">▣</span>Tableau de bord</a>
      <a href="?page=statistiques"  class="sb-item <?= $page==='statistiques'?'on':'' ?>"><span class="sb-ic">◈</span>Statistiques</a>
      <a href="?page=gestion"       class="sb-item <?= $page==='gestion'?'on':'' ?>"><span class="sb-ic">◎</span>Gestion</a>
      <a href="?page=autorisations" class="sb-item <?= $page==='autorisations'?'on':'' ?>"><span class="sb-ic">◉</span>Autorisations</a>
    </nav>
    <div class="sb-bot">
      <a href="?logout=1" class="sb-item" style="color:var(--red)"><span class="sb-ic"></span>Déconnexion</a>
    </div>
  </aside>

  <!-- MAIN -->
  <div class="main">
    <!-- TOPBAR -->
    <div class="topbar">
      <div class="tb-left">
        <h1><?= match($page){'dashboard'=>'Tableau de bord','statistiques'=>'Statistiques','gestion'=>'Gestion','autorisations'=>'Autorisations',default=>'Dashboard'} ?></h1>
        <p><?= match($page){'dashboard'=>'Vue en temps réel · Rafraîchissement automatique','statistiques'=>'Analyse des données sur 24h','gestion'=>'Configuration du système','autorisations'=>'Gestion des accès utilisateurs',default=>''} ?></p>
      </div>
      <?php if($page==='dashboard'): ?>
      <div class="live-pill"><div class="ldot"></div><span id="last-update">En direct</span></div>
      <?php endif; ?>
    </div>

    <!-- CONTENT -->
    <div class="content">
    <?php if($page==='dashboard'): ?>

      <div class="welcome">
        <h2>Bonjour, <?= htmlspecialchars($_SESSION['user']) ?> </h2>
        <p>Voici l'état actuel de votre infrastructure</p>
      </div>

      <!-- 3 STAT CARDS -->
      <div class="scards">
        <div class="sc ct">
          <div class="sc-glow"></div>
          <div class="sc-head">
            <div class="sc-label">Température</div>
            <div class="sc-badge"></div>
          </div>
          <div class="sc-val" id="temp-val"><?= $tv ?>°C</div>
          <div class="sc-sub" id="temp-date"><?= $dt?date('d/m/Y H:i',strtotime($dt['date_heure'])):'Aucune mesure' ?></div>
        </div>
        <div class="sc cb">
          <div class="sc-glow"></div>
          <div class="sc-head">
            <div class="sc-label">État baie</div>
            <div class="sc-badge"></div>
          </div>
          <div class="srow">
            <div class="sd <?= $open?'sd-r':'sd-g' ?>" id="baie-dot"></div>
            <span class="sc-val" style="font-size:24px" id="baie-stat"><?= $open?'OUVERTE':'FERMÉE' ?></span>
          </div>
          <div class="sc-sub" id="baie-date"><?= $do?date('d/m/Y H:i',strtotime($do['date_heure'])):'Aucune mesure' ?></div>
        </div>
        <div class="sc ca">
          <div class="sc-glow"></div>
          <div class="sc-head">
            <div class="sc-label">Alertes</div>
            <div class="sc-badge"></div>
          </div>
          <div class="sc-val" id="nb-al"><?= $na ?></div>
          <div class="sc-sub" id="al-sub"><?= $na>0?'Action requise':'Tout est normal' ?></div>
        </div>
      </div>

      <!-- 2-COL: historique + alertes résumé -->
      <div class="grid2">
        <!-- Historique -->
        <div class="sec">
          <div class="sec-h">
            <h2> Mesures récentes</h2>
            <a href="?export=1" class="btn btn-t"> CSV</a>
          </div>
          <table>
            <thead><tr><th>Capteur</th><th>Type</th><th>Valeur</th><th>Heure</th></tr></thead>
            <tbody id="tb-mes">
            <?php foreach(array_slice($ms,0,8) as $m): ?>
            <tr>
              <td><?= htmlspecialchars($m['emplacement']) ?></td>
              <td><span class="b bp"><?= $m['type']==='temperature'?'Temp.':'Ouv.' ?></span></td>
              <td><?php if($m['type']==='temperature'): ?><span class="b <?= $m['valeur']>35?'br':($m['valeur']<10?'bo':'bg') ?>"><?= $m['valeur'] ?>°C</span><?php else: ?><span class="b <?= $m['valeur']==1?'br':'bg' ?>"><?= $m['valeur']==1?'Ouverte':'Fermée' ?></span><?php endif; ?></td>
              <td style="color:var(--muted);font-size:11px"><?= date('H:i:s',strtotime($m['date_heure'])) ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        </div>

        <!-- Alertes -->
        <div class="sec">
          <div class="sec-h">
            <h2> Alertes récentes</h2>
            <div style="display:flex;gap:8px;align-items:center">
              <a href="?test_alerte=1" class="btn btn-r btn-sm" onclick="return confirm('Créer une alerte de test ?')">+ Test alerte</a>
              <form method="POST"><input type="hidden" name="action" value="marquer_tout_lu"><button type="submit" class="btn btn-g"> Tout lu</button></form>
            </div>
          </div>
          <table>
            <thead><tr><th>Type</th><th>Valeur</th><th>Statut</th><th>Action</th></tr></thead>
            <tbody id="tb-al">
            <?php if(empty($al)): ?>
              <tr><td colspan="4" style="text-align:center;color:var(--muted);padding:20px">Aucune alerte</td></tr>
            <?php else: foreach(array_slice($al,0,8) as $a): ?>
            <tr>
              <td style="font-size:12px"><?= match($a['type']){'temperature_haute'=>'Temp. haute','temperature_basse'=>'Temp. basse','ouverture_baie'=>'Ouverture',default=>$a['type']} ?></td>
              <td><?= $a['valeur'] ?></td>
              <td><span class="b <?= $a['statut']==='non_lu'?'br':'bg' ?>"><?= $a['statut'] ?></span></td>
              <td><?php if($a['statut']==='non_lu'): ?><form method="POST"><input type="hidden" name="action" value="marquer_lu"><input type="hidden" name="id" value="<?= $a['id_alerte'] ?>"><button type="submit" class="btn btn-g btn-sm"> Lu</button></form><?php else: ?><span style="color:var(--muted);font-size:11px">—</span><?php endif; ?></td>
            </tr>
            <?php endforeach; endif; ?>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Historique complet -->
      <div class="sec">
        <div class="sec-h">
          <h2> Historique complet</h2>
          <a href="?export=1" class="btn btn-t"> Export CSV</a>
        </div>
        <table>
          <thead><tr><th>#</th><th>Capteur</th><th>Type</th><th>Valeur</th><th>Date / Heure</th></tr></thead>
          <tbody id="tb-full">
          <?php foreach($ms as $m): ?>
          <tr>
            <td style="color:var(--muted);font-size:11px"><?= $m['id_mesure'] ?></td>
            <td><?= htmlspecialchars($m['emplacement']) ?></td>
            <td><span class="b bp"><?= $m['type']==='temperature'?'Température':'Ouverture' ?></span></td>
            <td><?php if($m['type']==='temperature'): ?><span class="b <?= $m['valeur']>35?'br':($m['valeur']<10?'bo':'bg') ?>"><?= $m['valeur'] ?>°C</span><?php else: ?><span class="b <?= $m['valeur']==1?'br':'bg' ?>"><?= $m['valeur']==1?'Ouverte':'Fermée' ?></span><?php endif; ?></td>
            <td style="color:var(--muted);font-size:11px"><?= date('d/m/Y H:i:s',strtotime($m['date_heure'])) ?></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>

    <?php elseif($page==='autorisations'): ?>

      <div class="sec" style="margin-bottom:18px">
        <div class="sec-h"><h2> Ajouter un utilisateur</h2>
          <form method="POST" style="display:inline">
            <input type="hidden" name="action" value="import_ad">
            <button type="submit" class="btn btn-t">Importer depuis l'AD</button>
          </form>
        </div>
        <?php if(isset($_SESSION['notif'])): ?>
        <div style="margin:12px 20px;padding:10px 14px;border-radius:9px;font-size:13px;background:rgba(45,212,191,.1);border:1px solid rgba(45,212,191,.2);color:var(--accent)">
          <?= htmlspecialchars($_SESSION['notif']) ?>
        </div>
        <?php unset($_SESSION['notif']); endif; ?>
        <form method="POST">
          <input type="hidden" name="action" value="add_auth">
          <div class="fgrid">
            <div class="fg"><label>Nom</label><input type="text" name="nom" placeholder="Technicien" required></div>
            <div class="fg"><label>Prénom</label><input type="text" name="prenom" placeholder="Jean" required></div>
            <div class="fg"><label>Login</label><input type="text" name="login" placeholder="j.technicien" required></div>
            <div class="fg"><label>Email</label><input type="email" name="email" placeholder="jean@example.fr"></div>
          </div>
          <div class="ffoot">
            <div class="ck"><input type="checkbox" name="autorise" id="autorise" checked><label for="autorise">Autoriser l'accès</label></div>
            <button type="submit" class="btn btn-t">+ Ajouter</button>
          </div>
        </form>
      </div>

      <div class="sec">
        <div class="sec-h"><h2> Utilisateurs (<?= count($auths) ?>)</h2></div>
        <table>
          <thead><tr><th>Nom</th><th>Prénom</th><th>Login</th><th>Email</th><th>Accès</th><th>Actions</th></tr></thead>
          <tbody>
          <?php foreach($auths as $a): ?>
          <tr>
            <td><?= htmlspecialchars($a['nom']) ?></td>
            <td><?= htmlspecialchars($a['prenom']) ?></td>
            <td><code style="color:var(--accent);font-size:11px;background:rgba(45,212,191,.08);padding:2px 7px;border-radius:5px"><?= htmlspecialchars($a['login']) ?></code></td>
            <td style="color:var(--muted);font-size:12px"><?= htmlspecialchars($a['email']) ?></td>
            <td><span class="b <?= $a['autorise']?'bg':'br' ?>"><?= $a['autorise']?' Oui':' Non' ?></span></td>
            <td><div style="display:flex;gap:6px">
              <a href="?toggle_auth=<?= $a['id_autorisation'] ?>&page=autorisations" class="btn btn-sm <?= $a['autorise']?'btn-r':'btn-g' ?>"><?= $a['autorise']?'Refuser':'Autoriser' ?></a>
              <a href="?delete_auth=<?= $a['id_autorisation'] ?>&page=autorisations" class="btn btn-sm btn-gr" onclick="return confirm('Supprimer cet utilisateur ?')">Supprimer</a>
            </div></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>

    <?php elseif($page==='statistiques'): ?>

      <!-- STAT CARDS -->
      <div class="scards" style="grid-template-columns:repeat(4,1fr)">
        <div class="sc ct">
          <div class="sc-glow"></div>
          <div class="sc-head"><div class="sc-label">Temp. moyenne 24h</div><div class="sc-badge">~</div></div>
          <div class="sc-val"><?= $stats_temp['moy'] ?? '--' ?>°C</div>
          <div class="sc-sub">Dernières 24 heures</div>
        </div>
        <div class="sc ct">
          <div class="sc-glow"></div>
          <div class="sc-head"><div class="sc-label">Temp. max 24h</div><div class="sc-badge">▲</div></div>
          <div class="sc-val" style="color:var(--red)"><?= $stats_temp['max'] ?? '--' ?>°C</div>
          <div class="sc-sub">Pic enregistré</div>
        </div>
        <div class="sc ct">
          <div class="sc-glow"></div>
          <div class="sc-head"><div class="sc-label">Temp. min 24h</div><div class="sc-badge">▼</div></div>
          <div class="sc-val" style="color:var(--accent)"><?= $stats_temp['min'] ?? '--' ?>°C</div>
          <div class="sc-sub">Minimum enregistré</div>
        </div>
        <div class="sc cb">
          <div class="sc-glow"></div>
          <div class="sc-head"><div class="sc-label">Ouvertures aujourd'hui</div><div class="sc-badge">↑</div></div>
          <div class="sc-val"><?= $nb_ouvertures ?></div>
          <div class="sc-sub">Détections baie ouverte</div>
        </div>
      </div>

      <!-- GRAPHIQUE TEMPERATURE -->
      <div class="sec" style="margin-bottom:18px">
        <div class="sec-h"><h2>Courbe de température — 24h</h2></div>
        <div style="padding:20px">
          <canvas id="chartTemp" height="80"></canvas>
        </div>
      </div>

      <!-- 2 colonnes : alertes par type + totaux -->
      <div class="grid2">
        <div class="sec">
          <div class="sec-h"><h2>Alertes par type</h2></div>
          <table>
            <thead><tr><th>Type</th><th>Nombre</th></tr></thead>
            <tbody>
            <?php foreach($alertes_type as $at): ?>
            <tr>
              <td><?= match($at['type']){'temperature_haute'=>'Température haute','temperature_basse'=>'Température basse','ouverture_baie'=>'Ouverture baie',default=>$at['type']} ?></td>
              <td><span class="b br"><?= $at['nb'] ?></span></td>
            </tr>
            <?php endforeach; ?>
            <?php if(empty($alertes_type)): ?>
            <tr><td colspan="2" style="text-align:center;color:var(--muted);padding:16px">Aucune alerte</td></tr>
            <?php endif; ?>
            </tbody>
          </table>
        </div>
        <div class="sec">
          <div class="sec-h"><h2>Totaux</h2></div>
          <div style="padding:20px;display:flex;flex-direction:column;gap:16px">
            <div style="display:flex;justify-content:space-between;align-items:center;padding:14px 16px;background:rgba(255,255,255,.03);border-radius:10px;border:1px solid var(--border)">
              <span style="color:var(--muted);font-size:13px">Total mesures enregistrées</span>
              <span style="font-family:'Space Grotesk',sans-serif;font-size:22px;font-weight:700;color:var(--accent)"><?= $total_mesures ?></span>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center;padding:14px 16px;background:rgba(255,255,255,.03);border-radius:10px;border:1px solid var(--border)">
              <span style="color:var(--muted);font-size:13px">Total alertes générées</span>
              <span style="font-family:'Space Grotesk',sans-serif;font-size:22px;font-weight:700;color:var(--red)"><?= $total_alertes ?></span>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center;padding:14px 16px;background:rgba(255,255,255,.03);border-radius:10px;border:1px solid var(--border)">
              <span style="color:var(--muted);font-size:13px">Points sur le graphique</span>
              <span style="font-family:'Space Grotesk',sans-serif;font-size:22px;font-weight:700;color:var(--purple)"><?= count($courbe) ?></span>
            </div>
          </div>
        </div>
      </div>

    <?php elseif($page==='gestion'): ?>

      <?php if(isset($_GET['saved'])): ?>
      <div style="margin-bottom:16px;padding:12px 16px;background:rgba(52,211,153,.1);border:1px solid rgba(52,211,153,.2);border-radius:10px;color:var(--green);font-size:13px">
        Configuration sauvegardée avec succès !
      </div>
      <?php endif; ?>

      <!-- SEUILS D'ALERTE -->
      <div class="sec" style="margin-bottom:18px">
        <div class="sec-h"><h2>Seuils d'alerte</h2></div>
        <form method="POST" style="padding:20px">
          <input type="hidden" name="action" value="save_config">
          <div class="fgrid">
            <div class="fg">
              <label>Seuil température haute (°C)</label>
              <input type="number" name="seuil_temp_haute" value="<?= htmlspecialchars($seuils['seuil_temp_haute'] ?? '35') ?>" min="0" max="100">
            </div>
            <div class="fg">
              <label>Seuil température basse (°C)</label>
              <input type="number" name="seuil_temp_basse" value="<?= htmlspecialchars($seuils['seuil_temp_basse'] ?? '10') ?>" min="0" max="100">
            </div>
            <div class="fg">
              <label>Intervalle rafraîchissement (secondes)</label>
              <input type="number" name="intervalle_refresh" value="<?= htmlspecialchars($seuils['intervalle_refresh'] ?? '5') ?>" min="1" max="60">
            </div>
            <div class="fg">
              <label>Email d'alerte principal</label>
              <input type="email" name="email_alerte" value="<?= htmlspecialchars($seuils['email_alerte'] ?? '') ?>" placeholder="admin@example.fr">
            </div>
          </div>
          <div class="ffoot">
            <button type="submit" class="btn btn-t">Sauvegarder</button>
          </div>
        </form>
      </div>

      <!-- DESTINATAIRES -->
      <div class="sec" style="margin-bottom:18px">
        <div class="sec-h"><h2>Destinataires des alertes email</h2></div>
        <div style="padding:16px 20px;border-bottom:1px solid var(--border)">
          <form method="POST" style="display:flex;gap:10px;align-items:flex-end">
            <input type="hidden" name="action" value="add_dest">
            <div class="fg" style="flex:1">
              <label>Ajouter un email</label>
              <input type="email" name="email" placeholder="nouveau@example.fr" required>
            </div>
            <button type="submit" class="btn btn-t" style="margin-bottom:0">+ Ajouter</button>
          </form>
        </div>
        <table>
          <thead><tr><th>#</th><th>Email</th><th>Action</th></tr></thead>
          <tbody>
          <?php foreach($destinataires as $d): ?>
          <tr>
            <td style="color:var(--muted);font-size:11px"><?= $d['id_destinataire'] ?></td>
            <td><?= htmlspecialchars($d['email']) ?></td>
            <td><a href="?del_dest=<?= $d['id_destinataire'] ?>&page=gestion" class="btn btn-sm btn-r" onclick="return confirm('Supprimer ?')">Supprimer</a></td>
          </tr>
          <?php endforeach; ?>
          <?php if(empty($destinataires)): ?>
          <tr><td colspan="3" style="text-align:center;color:var(--muted);padding:16px">Aucun destinataire</td></tr>
          <?php endif; ?>
          </tbody>
        </table>
      </div>

      <!-- CAPTEURS -->
      <div class="sec">
        <div class="sec-h"><h2>Capteurs enregistrés</h2></div>
        <table>
          <thead><tr><th>#</th><th>Emplacement</th><th>Type</th></tr></thead>
          <tbody>
          <?php foreach($capteurs as $c): ?>
          <tr>
            <td style="color:var(--muted);font-size:11px"><?= $c['id_capteur'] ?></td>
            <td><?= htmlspecialchars($c['emplacement']) ?></td>
            <td><span class="b <?= $c['type']==='temperature'?'bo':'bp' ?>"><?= $c['type'] ?></span></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>

    <?php endif; ?>
    </div><!-- /content -->
  </div><!-- /main -->
</div><!-- /layout -->

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script>
<?php if($page==='dashboard'): ?>
function fmt(s){const d=new Date(s.replace(' ','T'));return d.toLocaleDateString('fr-FR')+' '+d.toLocaleTimeString('fr-FR');}
function fmtH(s){return new Date(s.replace(' ','T')).toLocaleTimeString('fr-FR');}
function refresh(){
  fetch('api/data.php').then(r=>r.json()).then(data=>{
    document.getElementById('last-update').textContent='MAJ '+new Date().toLocaleTimeString('fr-FR');
    if(data.temperature){document.getElementById('temp-val').textContent=data.temperature.valeur+'°C';document.getElementById('temp-date').textContent=fmt(data.temperature.date_heure);}
    if(data.ouverture){const o=data.ouverture.valeur==1;document.getElementById('baie-dot').className='sd '+(o?'sd-r':'sd-g');document.getElementById('baie-stat').textContent=o?'OUVERTE':'FERMÉE';document.getElementById('baie-date').textContent=fmt(data.ouverture.date_heure);}
    document.getElementById('nb-al').textContent=data.nb_alertes;
    document.getElementById('al-sub').textContent=data.nb_alertes>0?'Action requise':'Tout est normal';
    const tm=document.getElementById('tb-mes');tm.innerHTML='';
    data.mesures.slice(0,8).forEach(m=>{
      const b=m.type==='temperature'?`<span class="b ${parseFloat(m.valeur)>35?'br':parseFloat(m.valeur)<10?'bo':'bg'}">${m.valeur}°C</span>`:`<span class="b ${m.valeur==1?'br':'bg'}">${m.valeur==1?'Ouverte':'Fermée'}</span>`;
      tm.innerHTML+=`<tr><td>${m.emplacement}</td><td><span class="b bp">${m.type==='temperature'?'Temp.':'Ouv.'}</span></td><td>${b}</td><td style="color:var(--muted);font-size:11px">${fmtH(m.date_heure)}</td></tr>`;
    });
    const ta=document.getElementById('tb-al');ta.innerHTML='';
    const tp={temperature_haute:'Temp. haute',temperature_basse:'Temp. basse',ouverture_baie:'Ouverture'};
    if(!data.alertes.length){ta.innerHTML='<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:20px">Aucune alerte</td></tr>';}
    else{data.alertes.slice(0,8).forEach(a=>{
      const btn=a.statut==='non_lu'?`<form method="POST" style="display:inline"><input type="hidden" name="action" value="marquer_lu"><input type="hidden" name="id" value="${a.id_alerte}"><button type="submit" class="btn btn-g btn-sm"> Lu</button></form>`:'<span style="color:var(--muted);font-size:11px">—</span>';
      ta.innerHTML+=`<tr><td style="font-size:12px">${tp[a.type]||a.type}</td><td>${a.valeur}</td><td><span class="b ${a.statut==='non_lu'?'br':'bg'}">${a.statut}</span></td><td>${btn}</td></tr>`;
    });}
    const tf=document.getElementById('tb-full');tf.innerHTML='';
    data.mesures.forEach(m=>{
      const b=m.type==='temperature'?`<span class="b ${parseFloat(m.valeur)>35?'br':parseFloat(m.valeur)<10?'bo':'bg'}">${m.valeur}°C</span>`:`<span class="b ${m.valeur==1?'br':'bg'}">${m.valeur==1?'Ouverte':'Fermée'}</span>`;
      tf.innerHTML+=`<tr><td style="color:var(--muted);font-size:11px">${m.id_mesure}</td><td>${m.emplacement}</td><td><span class="b bp">${m.type==='temperature'?'Température':'Ouverture'}</span></td><td>${b}</td><td style="color:var(--muted);font-size:11px">${fmt(m.date_heure)}</td></tr>`;
    });
  }).catch(e=>console.log(e));
}
setInterval(refresh,5000);refresh();

<?php elseif($page==='statistiques'): ?>
const labels = <?= json_encode(array_column($courbe,'heure')) ?>;
const vals   = <?= json_encode(array_map(fn($r)=>floatval($r['val']),$courbe)) ?>;
const ctx = document.getElementById('chartTemp').getContext('2d');
new Chart(ctx, {
  type: 'line',
  data: {
    labels: labels,
    datasets: [{
      label: 'Température (°C)',
      data: vals,
      borderColor: '#fb923c',
      backgroundColor: 'rgba(251,146,60,0.08)',
      borderWidth: 2,
      pointBackgroundColor: '#fb923c',
      pointRadius: 4,
      tension: 0.4,
      fill: true
    }]
  },
  options: {
    responsive: true,
    plugins: {
      legend: { labels: { color: '#94a3b8', font: { size: 12 } } },
      tooltip: { backgroundColor: '#1a1d29', titleColor: '#f1f5f9', bodyColor: '#94a3b8' }
    },
    scales: {
      x: { ticks: { color: '#64748b', font: { size: 11 } }, grid: { color: 'rgba(255,255,255,0.05)' } },
      y: { ticks: { color: '#64748b', font: { size: 11 } }, grid: { color: 'rgba(255,255,255,0.05)' } }
    }
  }
});
<?php endif; ?>
</script>
<?php endif; ?>
</body>
</html>
