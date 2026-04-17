<?php
session_start();
require_once '../includes/db.php';

if (!isset($_SESSION['user'])) {
    http_response_code(401);
    die(json_encode(['erreur' => 'Non autorise']));
}

header('Content-Type: application/json');

$derniere_temp = $pdo->query("
    SELECT m.valeur, m.date_heure FROM MESURE m
    JOIN CAPTEUR c ON m.id_capteur = c.id_capteur
    WHERE c.type = 'temperature'
    ORDER BY m.date_heure DESC LIMIT 1
")->fetch(PDO::FETCH_ASSOC);

$derniere_ouverture = $pdo->query("
    SELECT m.valeur, m.date_heure FROM MESURE m
    JOIN CAPTEUR c ON m.id_capteur = c.id_capteur
    WHERE c.type = 'ouverture'
    ORDER BY m.date_heure DESC LIMIT 1
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

echo json_encode([
    'temperature'  => $derniere_temp,
    'ouverture'    => $derniere_ouverture,
    'nb_alertes'   => $nb_alertes,
    'mesures'      => $mesures,
    'alertes'      => $alertes
]);
?>
