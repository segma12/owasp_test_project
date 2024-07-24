<?php

class App
{
    private $db;

    public function __construct()
    {
        $this->connectToDatabase();
    }

    private function connectToDatabase()
    {
        $host = getenv('DB_HOST');
        $db   = getenv('DB_NAME');
        $user = getenv('DB_USER');
        $pass = getenv('DB_PASS');
        $charset = 'utf8mb4';

        $dsn = "mysql:host=$host;dbname=$db;charset=$charset";
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ];

        try {
            $this->db = new PDO($dsn, $user, $pass, $options);
        } catch (PDOException $e) {
            error_log($e->getMessage());
            if (getenv('APP_ENV') === 'development') {
                throw new PDOException($e->getMessage(), (int)$e->getCode());
            } else {
                throw new Exception('Database connection failed.');
            }
        }
    }

    public function run()
    {
        // Application logic here
        echo "Application is running.";

        $user = $this->getUserById(1);
        echo htmlspecialchars(json_encode($user), ENT_QUOTES, 'UTF-8');
    }

    public function getUserById($id)
    {
        if (!is_numeric($id)) {
            throw new InvalidArgumentException('Invalid user ID.');
        }

        $stmt = $this->db->prepare('SELECT * FROM users WHERE id = :id');
        $stmt->execute(['id' => $id]);
        return $stmt->fetch();
    }

    // Function to validate and sanitize input
    function sanitizeInput($data) {
        return htmlspecialchars(stripslashes(trim($data)));
    }

    // Function to validate password
    function validatePassword($password) {
        // Remove multiple spaces
        $password = preg_replace('/\s+/', ' ', $password);
        // Check if password length is at least 12 characters
        return strlen($password) >= 12;
    }

    // Function to handle user signup
    function signup($username, $password, $conn) {
        // Sanitize input
        $username = sanitizeInput($username);
        $password = sanitizeInput($password);

        // Validate password
        if (!validatePassword($password)) {
            return "Password must be at least 12 characters long after combining multiple spaces.";
        }

        // Hash the password
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        // Prepare and bind
        $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        $stmt->bind_param("ss", $username, $hashedPassword);

        // Execute the statement
        if ($stmt->execute()) {
            return "Signup successful!";
        } else {
            return "Error: " . $stmt->error;
        }

        // Close the statement
        $stmt->close();
    }

    // Function to handle password change
    function changePassword($username, $newPassword, $conn) {
        // Sanitize input
        $username = sanitizeInput($username);
        $newPassword = sanitizeInput($newPassword);

        // Validate new password
        if (!validatePassword($newPassword)) {
            return "New password must be at least 12 characters long after combining multiple spaces.";
        }

        // Hash the new password
        $hashedNewPassword = password_hash($newPassword, PASSWORD_DEFAULT);

        // Prepare and bind
        $stmt = $conn->prepare("UPDATE users SET password = ? WHERE username = ?");
        $stmt->bind_param("ss", $hashedNewPassword, $username);

        // Execute the statement
        if ($stmt->execute()) {
            return "Password changed successfully!";
        } else {
            return "Error: " . $stmt->error;
        }

        // Close the statement
        $stmt->close();
    }

    // Function to send email notification
    function sendEmailNotification($to, $subject, $body) {
        global $emailHost, $emailUsername, $emailPassword, $emailFrom, $emailFromName;

        $mail = new PHPMailer(true);
        try {
            // Server settings
            $mail->isSMTP();
            $mail->Host = $emailHost;
            $mail->SMTPAuth = true;
            $mail->Username = $emailUsername;
            $mail->Password = $emailPassword;
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port = 587;

            // Recipients
            $mail->setFrom($emailFrom, $emailFromName);
            $mail->addAddress($to);

            // Content
            $mail->isHTML(true);
            $mail->Subject = $subject;
            $mail->Body    = $body;

            $mail->send();
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    // Function to handle unknown login notification
    function notifyUnknownLogin($username, $conn) {
        // Sanitize input
        $username = sanitizeInput($username);

        // Get user's email
        $stmt = $conn->prepare("SELECT email FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($email);
        $stmt->fetch();
        $stmt->close();

        // Send notification email
        $subject = "Unknown Login Detected";
        $body = "Dear $username,<br><br>We detected a login to your account from an unknown or risky location. If this was not you, please change your password immediately.<br><br>Regards,<br>Your App Name";
        sendEmailNotification($email, $subject, $body);
    }
}