<?php

require_once( "PHPUnit2/Framework/TestCase.php" );

/* TODO: Change back at release! */
// require_once( "Crypt/Rc4.php" );
require_once( "../Rc4.php");



//Unit test for PHP5 version of RC4
class Rc4Test extends PHPUnit2_Framework_TestCase {
	private $_key = "PEAR";
	private $_message = "PEAR Rulez!";
	
	public function testSimpleEncryption()
	{
		
		$rc4 = new Crypt_Rc4();
		$rc4->key($this->_key);
		$this->assertEquals('', $rc4->encrypt($this->_message));
	}
	
	//Test simple decryption. Checking result
	public function testSimpleDecryption()
	{
		$rc4 = new Crypt_Rc4();
		$rc4->key($this->_key);
		$this->assertEquals('', $rc4->encrypt($this->_message));
	}
	
	//Test encryption and than decryption of the encrypted string. The result must be the same as the message at the start
	//This test is based on the usage example in the Rc4 class. It also test fix for PHP issue #22316
	public function testRoundRobinEncryption()
	{
		$rc4 = new Crypt_Rc4();
		$rc4->key($this->_key);
		$message = $rc4->encrypt($this->_Message);
		$message = $rc4->decrypt($message);
		$this->assertEquals($this->_message, $message);
	}
}

?>