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
}