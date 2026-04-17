<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

require_once '../includes/db.php';
require_once '../includes/mailer.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    die(json_encode(['erreur' => 'Methode non autorisee']));
}

$data = json_decode(file_get_contents('php://input'), true);

if (!$data) {
    http_response_code(400);
    die(json_encode(['erreur' => 'Donnees invalides']));
}

$id_capteur = isset($data['id_capteur']) ? intval($data['id_capteur']) : null;
$valeur     = isset($data['valeur'])     ? floatval($data['valeur'])   : null;

if (!$id_capteur || $valeur === null) {
    http_response_code(400);
    die(json_encode(['erreur' => 'Champs id_capteur et valeur obligatoires']));
}

try {
    $stmt = $pdo->prepare("INSERT INTO MESURE (id_capteur, valeur) VALUES (:id_capteur, :valeur)");
    $stmt->execute([':id_capteur' => $id_capteur, ':valeur' => $valeur]);
    $id_mesure = $pdo->lastInsertId();

    $stmt = $pdo->prepare("SELECT * FROM SEUIL WHERE id_capteur = :id_capteur");
    $stmt->execute([':id_capteur' => $id_capteur]);
    $seuil = $stmt->fetch(PDO::FETCH_ASSOC);

    $alerte_declenchee = false;

    if ($seuil && ($valeur < $seuil['min'] || $valeur > $seuil['max'])) {
        $destinataires = $pdo->query("SELECT * FROM DESTINATAIRE")->fetchAll(PDO::FETCH_ASSOC);

        foreach ($destinataires as $dest) {
            $type_alerte = $valeur > $seuil['max'] ? 'temperature_haute' : 'temperature_basse';

            $stmt = $pdo->prepare("INSERT INTO ALERTE (type, statut, id_mesure, id_destinataire)
                                   VALUES (:type, 'non_lu', :id_mesure, :id_dest)");
            $stmt->execute([
                ':type'      => $type_alerte,
                ':id_mesure' => $id_mesure,
                ':id_dest'   => $dest['id_destinataire']
            ]);

            $sujet = $type_alerte === 'temperature_haute'
                ? '[ALERTE] Temperature trop haute dans la baie'
                : '[ALERTE] Temperature trop basse dans la baie';

            $msg = "Alerte detectee sur la baie Orange Bezannes.\n\n"
                 . "Type    : " . $type_alerte . "\n"
                 . "Valeur  : " . $valeur . "C\n"
                 . "Seuils  : min " . $seuil['min'] . "C / max " . $seuil['max'] . "C\n"
                 . "Heure   : " . date('d/m/Y H:i:s') . "\n\n"
                 . "Veuillez verifier la baie reseau.";

            envoyerAlerte($dest['email'], $sujet, $msg);
        }
        $alerte_declenchee = true;
    }

    if ($id_capteur == 1 && $valeur == 1) {
        $destinataires = $pdo->query("SELECT * FROM DESTINATAIRE")->fetchAll(PDO::FETCH_ASSOC);

        foreach ($destinataires as $dest) {
            $stmt = $pdo->prepare("INSERT INTO ALERTE (type, statut, id_mesure, id_destinataire)
                                   VALUES ('ouverture_baie', 'non_lu', :id_mesure, :id_dest)");
            $stmt->execute([
                ':id_mesure' => $id_mesure,
                ':id_dest'   => $dest['id_destinataire']
            ]);

            $msg = "Alerte detectee sur la baie Orange Bezannes.\n\n"
                 . "Type    : Ouverture de la baie\n"
                 . "Heure   : " . date('d/m/Y H:i:s') . "\n\n"
                 . "Veuillez verifier si cette ouverture est autorisee.";

            envoyerAlerte($dest['email'], '[ALERTE] Ouverture de la baie detectee', $msg);
        }
        $alerte_declenchee = true;
    }

    http_response_code(200);
    echo json_encode([
        'succes'            => true,
        'id_mesure'         => $id_mesure,
        'alerte_declenchee' => $alerte_declenchee
    ]);

} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['erreur' => 'Erreur serveur']);
}
?>
