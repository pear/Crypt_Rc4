<?php

require_once( "Crypt/Rc4.php");

$key = "PEAR";
$message = "PEAR Rulez!";
	
//Test Rc4 class with 'key' property call
$rc4 = new Crypt_Rc4();
$rc4->key = $key;
echo "Current message: " . $message . "\n";

$message = $rc4->encrypt($message);
echo "Current message: " . $message . "\n";
	
$message = $rc4->decrypt($message);
echo "Current message: " . $message . "\n";


?>