<?php
session_start();

// ===== DATABASE =====
$db = new SQLite3("secure_users.db");

$db->exec("
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    last_login TEXT
)
");

// ===== HELPERS =====
function loginLabel($date) {
    if (!$date) return "Never";
    $d = new DateTime($date);
    $now = new DateTime();

    if ($d->format("Y-m-d") === $now->format("Y-m-d")) return "Today";
    if ($d->format("Y-m-d") === $now->modify("-1 day")->format("Y-m-d")) return "Yesterday";

    return $d->format("Y-m-d");
}

$msg = "";

// ===== REGISTER (SECURE) =====
if (isset($_POST["register"])) {
    $u = trim($_POST["username"]);
    $p = $_POST["password"];

    $hash = password_hash($p, PASSWORD_BCRYPT);

    $stmt = $db->prepare("INSERT INTO users (username, password_hash) VALUES (:u, :p)");
    $stmt->bindValue(":u", $u, SQLITE3_TEXT);
    $stmt->bindValue(":p", $hash, SQLITE3_TEXT);

    if ($stmt->execute()) {
        $msg = "Account created.";
    } else {
        $msg = "Username already exists.";
    }
}

// ===== LOGIN (SECURE) =====
if (isset($_POST["login"])) {
    $u = trim($_POST["username"]);
    $p = $_POST["password"];

    $stmt = $db->prepare("SELECT * FROM users WHERE username = :u");
    $stmt->bindValue(":u", $u, SQLITE3_TEXT);
    $res = $stmt->execute();
    $user = $res->fetchArray(SQLITE3_ASSOC);

    if ($user && password_verify($p, $user["password_hash"])) {
        $_SESSION["uid"] = $user["id"];

        $now = date("Y-m-d H:i:s");
        $update = $db->prepare("UPDATE users SET last_login = :t WHERE id = :id");
        $update->bindValue(":t", $now);
        $update->bindValue(":id", $user["id"]);
        $update->execute();

        $msg = "Logged in securely.";
    } else {
        $msg = "Invalid credentials.";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Secure Login</title>
    <style>
        body { background:#111; color:#eee; font-family:Arial; }
        .box { border:1px solid #444; padding:15px; margin:10px 0; }
        input, button { padding:8px; margin:5px; }
    </style>
</head>
<body>

<h2>🔒 Secure Login System</h2>
<p><?= $msg ?></p>

<div class="box">
    <h3>Create Account</h3>
    <form method="post">
        <input name="username" required>
        <input name="password" type="password" required>
        <button name="register">Register</button>
    </form>
</div>

<div class="box">
    <h3>Login</h3>
    <form method="post">
        <input name="username" required>
        <input name="password" type="password" required>
        <button name="login">Login</button>
    </form>
</div>

<div class="box">
    <h3>Users</h3>
    <ul>
        <?php
        $r = $db->query("SELECT username, last_login FROM users");
        while ($row = $r->fetchArray(SQLITE3_ASSOC)) {
            echo "<li>{$row['username']} — ".loginLabel($row['last_login'])."</li>";
        }
        ?>
    </ul>
</div>

</body>
</html>
