<?php
namespace LazarusPhp\SecurityFramework;

class SecurityCall
{
    private $token;
    private static $key = "";
    private static $cipher = 'AES-256-CBC';

    public function __construct()
    {
        // Generate a New Token
        $this->token = bin2hex(random_bytes(32));
    }

    public function getToken():string
    {
        return $this->token;
    }

    public function verifyToken($session, $token):bool
    {
        return (hash_equals($session, $token)) ? true : false;
    }


    public function genetateKey($key=null):mixed
    {
       return  is_null($key) ? self::$key = bin2hex(random_bytes(32)) : self::$key = $key;
    }

    public function tokenInput():void
    {
        echo '<input type="text" name="csrf_token" value="' . $this->GetToken() . '">';
    }

    public function hash($password, $encryption = PASSWORD_DEFAULT):string
    {
        return password_hash($password, $encryption);
    }

    public function VerifyHash($local, $remote):bool
    {
        return (password_verify($local, $remote) == true) ? true : false;
    }

}