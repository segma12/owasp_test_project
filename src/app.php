<?php

class App
{
    private $db;

    // Configuration settings
    private $config = [
        'encryption' => [
            'algorithm' => 'AES-256-CBC',
            'key' => 'your-encryption-key', // Change to your actual encryption key (32 bytes for AES-256)
            'iv_length' => 16
        ],
        'hashing' => [
            'algorithm' => PASSWORD_DEFAULT,
            'options' => ['cost' => 12]
        ],
        'random' => [
            'guid_length' => 16,
            'file_name_length' => 16,
            'string_length' => 16
        ]
    ];

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

// Function to generate a secure random GUID
    function generateGuid($length) {
        $data = random_bytes($length);
        assert(strlen($data) == $length);

        // Set version to 0100
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        // Set bits 6-7 to 10
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

// Function to generate a secure random file name
    function generateRandomFileName($length) {
        return bin2hex(random_bytes($length / 2));
    }

// Function to generate a secure random string
    function generateRandomString($length) {
        return bin2hex(random_bytes($length / 2));
    }

// Function to encrypt data
    function encryptData($data, $config) {
        $iv = random_bytes($config['encryption']['iv_length']); // Generate a secure random IV
        $encryptedData = openssl_encrypt($data, $config['encryption']['algorithm'], $config['encryption']['key'], 0, $iv);
        return base64_encode($encryptedData . '::' . $iv);
    }

// Function to decrypt data
    function decryptData($data, $config) {
        list($encryptedData, $iv) = explode('::', base64_decode($data), 2);
        return openssl_decrypt($encryptedData, $config['encryption']['algorithm'], $config['encryption']['key'], 0, $iv);
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

// Function to handle user signup
    function signup($username, $password, $email, $conn, $config) {
        // Sanitize input
        $username = sanitizeInput($username);
        $password = sanitizeInput($password);
        $email = sanitizeInput($email);

        // Validate password
        if (!validatePassword($password)) {
            return "Password must be at least 12 characters long after combining multiple spaces.";
        }

        // Hash the password with a randomly generated salt
        $hashedPassword = password_hash($password, $config['hashing']['algorithm'], $config['hashing']['options']);

        // Encrypt email
        $encryptedEmail = encryptData($email, $config);

        // Generate TOTP secret
        $totp = TOTP::create();
        $secret = $totp->getSecret();

        // Prepare and bind
        $stmt = $conn->prepare("INSERT INTO users (username, password, email, totp_secret) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssss", $username, $hashedPassword, $encryptedEmail, $secret);

        // Execute the statement
        if ($stmt->execute()) {
            // Send notification email
            $subject = "Signup Successful";
            $body = "Dear $username,<br><br>Your account has been successfully created.<br><br>Regards,<br>Your App Name";
            sendEmailNotification($email, $subject, $body);

            // Display QR code for TOTP
            $qrCodeUrl = $totp->getProvisioningUri();
            echo "<p>Scan this QR code with your authenticator app:</p>";
            echo "<img src='https://api.qrserver.com/v1/create-qr-code/?data=" . urlencode($qrCodeUrl) . "'>";

            return "Signup successful!";
        } else {
            return "Error: " . $stmt->error;
        }

        // Close the statement
        $stmt->close();
    }

// Function to handle password change
    function changePassword($username, $newPassword, $conn, $config) {
        // Sanitize input
        $username = sanitizeInput($username);
        $newPassword = sanitizeInput($newPassword);

        // Validate new password
        if (!validatePassword($newPassword)) {
            return "New password must be at least 12 characters long after combining multiple spaces.";
        }

        // Hash the new password with a randomly generated salt
        $hashedNewPassword = password_hash($newPassword, $config['hashing']['algorithm'], $config['hashing']['options']);

        // Prepare and bind
        $stmt = $conn->prepare("UPDATE users SET password = ? WHERE username = ?");
        $stmt->bind_param("ss", $hashedNewPassword, $username);

        // Execute the statement
        if ($stmt->execute()) {
            // Get user's encrypted email
            $stmt = $conn->prepare("SELECT email FROM users WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $stmt->bind_result($encryptedEmail);
            $stmt->fetch();
            $stmt->close();

            // Decrypt email
            $email = decryptData($encryptedEmail, $config);

            // Send notification email
            $subject = "Password Changed Successfully";
            $body = "Dear $username,<br><br>Your password has been successfully changed.<br><br>Regards,<br>Your App Name";
            sendEmailNotification($email, $subject, $body);

            return "Password changed successfully!";
        } else {
            return "Error: " . $stmt->error;
        }

        // Close the statement
        $stmt->close();
    }

// Function to handle unknown login notification
    function notifyUnknownLogin($username, $conn, $config) {
        // Sanitize input
        $username = sanitizeInput($username);

        // Get user's encrypted email
        $stmt = $conn->prepare("SELECT email FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($encryptedEmail);
        $stmt->fetch();
        $stmt->close();

        // Decrypt email
        $email = decryptData($encryptedEmail, $config);

        // Send notification email
        $subject = "Unknown Login Attempt";
        $body = "Dear $username,<br><br>We detected a login attempt from an unknown location.<br><br>Regards,<br>Your App Name";
        sendEmailNotification($email, $subject, $body);

        return "Unknown login notification sent!";
    }

// Function to verify TOTP code
    function verifyTotp($username, $totpCode, $conn) {
        // Get user's TOTP secret
        $stmt = $conn->prepare("SELECT totp_secret FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($secret);
        $stmt->fetch();
        $stmt->close();

        // Verify the TOTP code
        $totp = TOTP::create($secret);
        return $totp->verify($totpCode);
    }

// Function to handle user login
    function login($username, $password, $totpCode, $conn, $config) {
        // Sanitize input
        $username = sanitizeInput($username);
        $password = sanitizeInput($password);

        // Prepare and bind
        $stmt = $conn->prepare("SELECT password, totp_secret FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($hashedPassword, $secret);
        $stmt->fetch();
        $stmt->close();

        // Verify password
        if (password_verify($password, $hashedPassword)) {
            // Verify TOTP code
            $totp = TOTP::create($secret);
            if ($totp->verify($totpCode)) {
                return "Login successful!";
            } else {
                notifyUnknownLogin($username, $conn, $config);
                return "Invalid TOTP code.";
            }
        } else {
            return "Invalid username or password.";
        }
    }
}