<?php
namespace LazarusPhp\SecurityFramework;

use LazarusPhp\SecurityFramework\CoreFiles\SecurityCore;
use LazarusPhp\SecurityFramework\Interface\SecurityInterface;
use LazarusPhp\SessionManager\Sessions;
use LazarusPhp\DateManager\Date;
use LazarusPhp\SessionManager\SessionsFactory;
use LazarusPhp\FileCrafter\FileCrafter;
use LazarusPhp\FileCrafter\Writers\JsonWriter;
use LazarusPhp\SecurityFramework\Traits\AesEncryption;

class Security
{
    private $token;
    private static $filename = ROOT."/Storage/EncryptionKey.json";
    use AesEncryption;





    // Generate Security Key

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

    public static function setEnckey()
    {
    
        FileCrafter::bind("SecurityKey",self::$filename,[JsonWriter::class]);
        FileCrafter::generate("SecurityKey",function($writer)
        {
            $date = Date::withAddedTime("now","P3D")->format("Y-m-d H:i:s");
            $now = Date::create()->format("Y-m-d H:i:s");
            $writer->preventOverwrite("EncryptionKey","Key","Created");
            $writer->set("EncryptionKey","Key",bin2hex(random_bytes(32)));
            $writer->set("EncryptionKey","Created",$now);
            
                $writer->save(); 
            self::setkey($writer->fetch()->EncryptionKey->Key);
        });
    }

}