<?php
/* vim: set expandtab tabstop=4 shiftwidth=4: */
// +----------------------------------------------------------------------+
// | PHP Version 5                                                        |
// +----------------------------------------------------------------------+
// | Copyright (c) 1997-2004 The PHP Group                                |
// +----------------------------------------------------------------------+
// | This source file is subject to version 2.0 of the PHP license,       |
// | that is bundled with this package in the file LICENSE, and is        |
// | available at through the world-wide-web at                           |
// | http://www.php.net/license/2_02.txt.                                 |
// | If you did not receive a copy of the PHP license and are unable to   |
// | obtain it through the world-wide-web, please send a note to          |
// | license@php.net so we can mail you a copy immediately.               |
// +----------------------------------------------------------------------+
// | Authors: Dave Mertens <zyprexia@php.net>                             |
// +----------------------------------------------------------------------+
//
// $Id$


/**
* RC4 stream cipher routines implementation. 
*
* in PHP5(!) based on code written by Damien Miller <djm@mindrot.org>
* This class <b><u>BREAKS</u></b> with <b><u>COMPABILITY</u></b> with earlier PHP 4 version of the RC4 class. 
* PHP 4 versions are available at http://pear.php.net/package/Crypt_RC4, download version 1.x
* 
*
* Usage:<br />
* $key = "pear";<br />
* $message = "PEAR rulez!";<br />
*
* $rc4 = new Crypt_Rc4;<br />
* $rc4->setKey($key);<br />
* echo "Original message: $message &lt;br /&gt;\n";<br /><br />
*
* $message = $rc4->encrypt($message);<br />
* echo "Encrypted message: $message &lt;br /&gt;\n";<br /><br />
*
* $message $rc4->decrypt($message);<br />
* echo "Decrypted message: $message &lt;br /&gt;>\n";<br />
*
* @version $Revision$
* @access public
* @package Crypt
* @author Dave Mertens <zyprexia@php.net>
 */

/* sealed */ class Crypt_Rc4 {

    /**
    * Contains salt key used by en(de)cryption function
    * @var array
    * @access private
    */
    private var $s= array();
    
    /**
    * First Part of encryption matrix
    * @var array
    * @access private
    */
    private var $i= 0;
    
    /**
    * Second part of encryption matrix
    * @var array
    * @access private
    */
    private var $j= 0;

    /**
    * Used provided key for encryption. 
    * @var string
    * @access private
    */
    private var $_key;

    /**
    * Constructor for encryption class
    * Pass encryption key to key()
    *
    * @see    setKey() 
    * @param  string key    - Optional key which will be used for encryption
    * @return void
    * @access public
    */
    function __construct($key = null) {
        if ($key != null) {
            $this->setKey($key);
        }
    }

    /**
    * Encrypt function
    *
    * @param  string paramstr 	- string that will decrypted
    * @return Encrypted string
    * @access public    
    */
    public function encrypt($paramstr) {
        //Decrypt is exactly the same as encrypting the string. Reuse (en)crypt code
        return $this->crypt($paramstr);
    }

    /**
    * Decrypt function
    *
    * @param  string paramstr 	- string that will decrypted
    * @return Decrypted string
    * @access public    
    */
    public function decrypt($paramstr) {
        //Decrypt is exactly the same as encrypting the string. Reuse (en)crypt code
        return $this->crypt($paramstr);
    }

    /**
    * Assign encryption key to class
    *
    * @param  string key	- Key which will be used for encryption
    * @return void
    * @access public    
    */
    public function key(&$key) {
        $len= strlen($key);
        
        //Create array matrix
        for ($this->i = 0; $this->i < 256; $this->i++) {
            $this->s[$this->i] = $this->i;
        }

	//Initialize encryption matrix
        $this->j = 0;
        for ($this->i = 0; $this->i < 256; $this->i++) {
            $this->j = ($this->j + $this->s[$this->i] + ord($key[$this->i % $len])) % 256;
            $t = $this->s[$this->i];
            $this->s[$this->i] = $this->s[$this->j];
            $this->s[$this->j] = $t;
        }
        $this->i = $this->j = 0;
    }

    // PROTECTED FUNCTIONS

    /**
    * (en/de) crypt function. 
    * Function canm be used for encrypting and decrypting a message
    *
    * @param  string paramstr 	- string that will encrypted
    * @return void
    * @access private
    */
    final protected private function crypt($paramstr) {

        //Init key for every call, Bugfix for PHP issue #22316
        $this->key($this->_key);

	//length of message
        $len= strlen($paramstr);
        
        //Encrypt message
        for ($c= 0; $c < $len; $c++) {
            $this->i = ($this->i + 1) % 256;
            $this->j = ($this->j + $this->s[$this->i]) % 256;
            $t = $this->s[$this->i];
            $this->s[$this->i] = $this->s[$this->j];
            $this->s[$this->j] = $t;

            $t = ($this->s[$this->i] + $this->s[$this->j]) % 256;

            $paramstr[$c] = chr(ord($paramstr[$c]) ^ $this->s[$t]);
        }
        
        return $paramstr;
    }

    /**
    * This method prevents changes to the key during the encryption procedure.
    *
    * @param  string key    - key which will be used for encryption
    * @return void
    * @access private
    */
    final protected function setKey($key) {
        if (strlen($key) > 0)
            $this->_key = $key;
    }

}	//end of RC4 class
?>
