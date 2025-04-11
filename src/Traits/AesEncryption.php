<?php

namespace LazarusPhp\SecurityFramework\Traits;

trait AesEncryption
{
    private static $key = "";
    private static $cipher = 'AES-256-CBC';

    public static function generateKey(?string $key=null)
    {
        FileCrafter::bind("SecurityKey",self::$filename,[JsonWriter::class]);
        FileCrafter::generate("SecurityKey",function($writer)
        {
            $key = $key ?? self::setPassword(bin2hex(random_bytes(32)));
            $date = Date::withAddedTime("now","P3D")->format("Y-m-d H:i:s");
            $now = Date::create()->format("Y-m-d H:i:s");
            $writer->preventOverwrite("EncryptionKey","Key","Created");
            $writer->set("EncryptionKey","Key",$key);
            $writer->set("EncryptionKey","Created",$now);
            
                $writer->save(); 
            self::setkey($writer->fetch()->EncryptionKey->Key);
        });
    }

    private static function setKey($key):void
    {
         self::$key = $key;
    }

    public static function encrypt($value):string
    {
        if (!empty(self::$key)) {
            $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(self::$cipher));
            $encrypted = openssl_encrypt($value, self::$cipher, self::$key, 0, $iv);

            // Combine IV and encrypted value for decryption later
            return base64_encode($iv . $encrypted);
        } else {
            trigger_error("Encryption key Incorrect or empty");
        }
    }
    
    public static function decscrypt($value):bool|string
    {
        $decoded = base64_decode($value);
        // Extract IV and encrypted data
        $iv_length = openssl_cipher_iv_length(self::$cipher);
        $iv = substr($decoded, 0, $iv_length);
        $encrypted = substr($decoded, $iv_length);
        return openssl_decrypt($encrypted, self::$cipher, self::$key, 0, $iv);
    }
}