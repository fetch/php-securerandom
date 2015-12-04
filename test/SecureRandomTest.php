<?php

use PhpSecureRandom\SecureRandom;

class SecureRandomTest extends PHPUnit_Framework_TestCase {
	/**
	 * @covers PhpSecureRandom\SecureRandom::random_bytes
	 */
	public function testRandom_bytes(){
		for($i = 1; $i < 100; $i++){
			$this->assertRegExp('/^[\x00-\xff]{' . $i . '}$/', SecureRandom::random_bytes($i));
		}
	}

	/**
	 * @covers PhpSecureRandom\SecureRandom::hex
	 */
	public function testHex(){
		$this->assertRegExp('/^[a-f0-9]{16}$/', SecureRandom::hex(8));
	}

	/**
	 * @covers PhpSecureRandom\SecureRandom::base64
	 */
	public function testBase64(){
		for($i = 0; $i < 100; $i++){
			$this->assertRegExp('/^[A-Za-z0-9\+\/\=]+$/', SecureRandom::base64());
		}
	}

	/**
	 * @covers PhpSecureRandom\SecureRandom::urlsafe_base64
	 */
	public function testUrlsafe_base64(){
		for($i = 0; $i < 100; $i++){
			$this->assertRegExp('/^[A-Za-z0-9_\-]+$/', SecureRandom::urlsafe_base64());
		}
	}

	/**
	 * @covers PhpSecureRandom\SecureRandom::random_number
	 */
	public function testRandom_number(){
		for($i = 0; $i < 100; $i++){
			$this->assertLessThan(1, SecureRandom::random_number());
		}
		
		for($i = 1; $i < 100; $i++){
			$this->assertLessThan($i, SecureRandom::random_number($i));
		}
	}

	/**
	 * @covers PhpSecureRandom\SecureRandom::uuid
	 */
	public function testUuid(){
		for($i = 0; $i < 100; $i++){
			$this->assertRegExp('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', SecureRandom::uuid());
		}
	}
}
