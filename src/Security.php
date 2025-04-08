<?php
namespace LazarusPhp\SecurityFramework;

use LazarusPhp\SecurityFramework\CoreFiles\SecurityCore;
use LazarusPhp\SecurityFramework\Interface\SecurityInterface;
use LazarusPhp\SessionManager\Sessions;
use LazarusPhp\SessionManager\SessionsFactory;

class Security extends SecurityCore
{
    private $token;

    public function __construct()
    {
        
    }

    public function setPassword($password,$hash=PASSWORD_DEFAULT)
    {
        return password_hash($password,$hash);
    }

    public function validatePassword($password,$hashedPassword)
    {
       return password_verify($password,$hashedPassword) ? true : false;
    }

    // Csrf token

    private function newToken()
    {    $session = new Sessions();
        $session->csrfToken = bin2hex(random_bytes(32));
    }

    public function generateToken():void
    {
        $session = new Sessions(); 
        if (!isset($session->csrfToken)) {
            $this->newToken();
        }
    }

    public function validateToken(string $token): bool
    {
        if(hash_equals($token,SessionsFactory::get("csrfToken")))
        {
            $this->newToken();
            return true;
        }
        else
        {
            return false;
        }
    }

}