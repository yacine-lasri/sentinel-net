<?php
/*
 * login.php — SentinelNet Authentication
 *
 * Simple session-based login.
 * Credentials are defined as constants below — no database needed.
 * Change ADMIN_USER and ADMIN_PASS before deploying.
 */

session_start();

/* ── credentials ─────────────────────────────────────────────── */
define('ADMIN_USER', 'admin');
define('ADMIN_PASS', 'sentinel2026');   /* ← change this */

/* ── already logged in → go straight to dashboard ────────────── */
if (isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true) {
    header('Location: index.php');
    exit;
}

/* ── handle form submission ───────────────────────────────────── */
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = trim($_POST['username'] ?? '');
    $pass = trim($_POST['password'] ?? '');

    if ($user === ADMIN_USER && $pass === ADMIN_PASS) {
        /* success — create session and redirect */
        session_regenerate_id(true);   /* prevent session fixation */
        $_SESSION['authenticated'] = true;
        $_SESSION['user']          = $user;
        $_SESSION['login_time']    = time();
        header('Location: index.php');
        exit;
    } else {
        /* wrong credentials — small delay to slow brute force */
        sleep(1);
        $error = 'Identifiants incorrects. Veuillez réessayer.';
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelNet — Connexion</title>
    <link rel="stylesheet" href="assets/style.css">
    <style>
        /* ── Login page specific styles ──────────────────────── */
        .login-wrapper {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background-color: #0f172a;
        }

        .login-box {
            background-color: #1e293b;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 48px 40px;
            width: 100%;
            max-width: 400px;
        }

        .login-logo {
            text-align: center;
            margin-bottom: 32px;
        }

        .login-logo h1 {
            font-size: 28px;
            font-weight: 700;
            color: #38bdf8;
            letter-spacing: 2px;
            margin: 0;
        }

        .login-logo p {
            color: #64748b;
            font-size: 13px;
            margin-top: 6px;
        }

        .login-field {
            margin-bottom: 20px;
        }

        .login-field label {
            display: block;
            font-size: 13px;
            color: #94a3b8;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .login-field input {
            width: 100%;
            padding: 12px 14px;
            background-color: #0f172a;
            border: 1px solid #334155;
            border-radius: 8px;
            color: #f1f5f9;
            font-size: 15px;
            outline: none;
            box-sizing: border-box;
            transition: border-color 0.2s;
        }

        .login-field input:focus {
            border-color: #38bdf8;
        }

        .login-btn {
            width: 100%;
            padding: 13px;
            background-color: #2563eb;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 8px;
            transition: background-color 0.2s;
        }

        .login-btn:hover {
            background-color: #1d4ed8;
        }

        .login-error {
            background-color: rgba(239, 68, 68, 0.12);
            border: 1px solid #ef4444;
            border-radius: 8px;
            color: #fca5a5;
            font-size: 13px;
            padding: 12px 14px;
            margin-bottom: 20px;
            text-align: center;
        }

        .login-footer {
            text-align: center;
            margin-top: 24px;
            color: #475569;
            font-size: 12px;
        }
    </style>
</head>
<body>

<div class="login-wrapper">
    <div class="login-box">

        <div class="login-logo">
            <h1>⬡ SentinelNet</h1>
            <p>Système de détection d'intrusion réseau</p>
        </div>

        <?php if ($error): ?>
            <div class="login-error">
                <?= htmlspecialchars($error) ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="login.php">

            <div class="login-field">
                <label for="username">Identifiant</label>
                <input
                    type="text"
                    id="username"
                    name="username"
                    placeholder="admin"
                    autocomplete="username"
                    required
                    value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
                >
            </div>

            <div class="login-field">
                <label for="password">Mot de passe</label>
                <input
                    type="password"
                    id="password"
                    name="password"
                    placeholder="••••••••••"
                    autocomplete="current-password"
                    required
                >
            </div>

            <button type="submit" class="login-btn">
                Se connecter
            </button>

        </form>

        <div class="login-footer">
            SentinelNet &mdash; Accès restreint
        </div>

    </div>
</div>

</body>
</html>
