<?php

require_once( "Crypt/Rc4.php");

$key = "PEAR";
$message = "PEAR Rulez!";
	
//Test encryption and than decryption of the encrypted string. The result must be the same as the message at the start
//This test is based on the usage example in the Rc4 class. It also test fix for PHP issue #22316
$rc4 = new Crypt_Rc4();
$rc4->key($key);
echo "Current message: " . $message . "\n";

$message = $rc4->encrypt($message);
echo "Current message: " . $message . "\n";
	
$message = $rc4->decrypt($message);
echo "Current message: " . $message . "\n";

?>