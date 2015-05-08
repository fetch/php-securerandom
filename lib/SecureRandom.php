<?php

namespace PhpSecureRandom;

/**
 * = Secure random number generator interface.
 *
 * This library is an interface for secure random number generator which is
 * suitable for generating session key in HTTP cookies, etc.
 *
 * It currently supports the following secure random number generators.
 *
 * * openssl
 *
 * == Example
 *
 * # random hexadecimal string.
 * echo SecureRandom::hex(10); //=> "52750b30ffbc7de3b362"
 * echo SecureRandom::hex(10); //=> "92b15d6c8dc4beb5f559"
 * echo SecureRandom::hex(11); //=> "6aca1b5c58e4863e6b81b8"
 * echo SecureRandom::hex(12); //=> "94b2fff3e7fd9b9c391a2306"
 * echo SecureRandom::hex(13); //=> "39b290146bea6ce975c37cfc23"
 * ...
 *
 * # random base64 string.
 * echo SecureRandom::base64(10); //=> "EcmTPZwWRAozdA=="
 * echo SecureRandom::base64(10); //=> "9b0nsevdwNuM/w=="
 * echo SecureRandom::base64(10); //=> "KO1nIU+p9DKxGg=="
 * echo SecureRandom::base64(11); //=> "l7XEiFja+8EKEtY="
 * echo SecureRandom::base64(12); //=> "7kJSM/MzBJI+75j8"
 * echo SecureRandom::base64(13); //=> "vKLJ0tXBHqQOuIcSIg=="
 * ...
 *
 * # random binary string.
 * echo SecureRandom::random_bytes(10); //=> "\016\t{\370g\310pbr\301"
 * echo SecureRandom::random_bytes(10); //=> "\323U\030TO\234\357\020\a\337"
 * ...
 *
 * @package default
 * @author Koen Punt
 */
class SecureRandom {

	/**
	 * SecureRandom::random_bytes generates a random binary string.
	 *
	 * The argument $n specifies the length of the result string.
	 *
	 * If $n is not specified, 16 is assumed.
	 * It may be larger in future.
	 *
	 * The result may contain any byte: "\x00" - "\xff".
	 *
	 *   echo SecureRandom::random_bytes(); //=> "\xD8\\\xE0\xF4\r\xB2\xFC*WM\xFF\x83\x18\xF45\xB6"
	 *   echo SecureRandom::random_bytes(); //=> "m\xDC\xFC/\a\x00Uf\xB2\xB2P\xBD\xFF6S\x97"
	 *
	 * If secure random number generator is not available, an error is raised.
	 *
	 * @param int $n
	 * @return string random bytes
	 * @author Koen Punt
	 */
	public static function random_bytes($n=16){
		$random_bytes = static::openssl_random_pseudo_bytes($n);

		if($random_bytes === false){
			return trigger_error("No suitable random device", E_USER_ERROR);
		}
		return $random_bytes;
	}

	// @codeCoverageIgnoreStart
	protected static function openssl_random_pseudo_bytes($n){
		if(function_exists('openssl_random_pseudo_bytes')){
			return openssl_random_pseudo_bytes($n);
		}
		return false;
	}
	// @codeCoverageIgnoreEnd

	/**
	 * SecureRandom::hex generates a random hex string.
	 *
	 * The argument $n specifies the length of the random length.
	 * The length of the result string is twice of $n.
	 *
	 * If $n is not specified, 16 is assumed.
	 * It may be larger in future.
	 *
	 * The result may contain 0-9 and a-f.
	 *
	 *   echo SecureRandom::hex(); //=> "eb693ec8252cd630102fd0d0fb7c3485"
	 *   echo SecureRandom::hex(); //=> "91dc3bfb4de5b11d029d376634589b61"
	 *
	 * If secure random number generator is not available, an error is raised.
	 *
	 * @param integer $n
	 * @return string hex string of $n * 2 length
	 * @author Koen Punt
	 */
	public static function hex($n=16){
		$h = unpack("H*", self::random_bytes($n));
		return $h[1];
	}

	/**
	 * SecureRandom::base64 generates a random base64 string.
	 *
	 * The argument $n specifies the length of the random length.
	 * The length of the result string is about 4/3 of $n.
	 *
	 * If $n is not specified, 16 is assumed.
	 * It may be larger in future.
	 *
	 * The result may contain A-Z, a-z, 0-9, "+", "/" and "=".
	 *
	 *   echo SecureRandom::base64(); //=> "/2BuBuLf3+WfSKyQbRcc/A=="
	 *   echo SecureRandom::base64(); //=> "6BbW0pxO0YENxn38HMUbcQ=="
	 *
	 * If secure random number generator is not available, an error is raised.
	 *
	 * See RFC 3548 for the definition of base64.
	 *
	 * @param string $n
	 * @return string
	 * @author Koen Punt
	 */
	public static function base64($n=16){
		return str_replace("\n", "", base64_encode(self::random_bytes($n)));
	}

	/**
	 * SecureRandom::urlsafe_base64 generates a random URL-safe base64 string.
	 *
	 * The argument $n specifies the length of the random length.
	 * The length of the result string is about 4/3 of $n.
	 *
	 * If $n is not specified, 16 is assumed.
	 * It may be larger in future.
	 *
	 * The boolean argument $padding specifies the padding.
	 * If it is false or nil, padding is not generated.
	 * Otherwise padding is generated.
	 * By default, padding is not generated because "=" may be used as a URL delimiter.
	 *
	 * The result may contain A-Z, a-z, 0-9, "-" and "_".
	 * "=" is also used if $padding is true.
	 *
	 *   echo SecureRandom::urlsafe_base64(); //=> "b4GOKm4pOYU_-BOXcrUGDg"
	 *   echo SecureRandom::urlsafe_base64(); //=> "UZLdOkzop70Ddx-IJR0ABg"
	 *
	 *   echo SecureRandom::urlsafe_base64(null, true); #=> "i0XQ-7gglIsHGV2_BNPrdQ=="
	 *   echo SecureRandom::urlsafe_base64(null, true); #=> "-M8rLhr7JEpJlqFGUMmOxg=="
	 *
	 * If secure random number generator is not available, an error is raised.
	 *
	 * See RFC 3548 for the definition of URL-safe base64.
	 *
	 * @param string $n
	 * @param string $padding
	 * @return string
	 * @author Koen Punt
	 */
	public static function urlsafe_base64($n=16, $padding=false){
		$s = base64_encode(self::random_bytes($n));
		$s = str_replace("\n", "", $s);
		$s = strtr($s, '+/', '-_');
		if(!$padding){
			$s = str_replace("=", "", $s);
		}
		return $s;
	}

	/**
	 * SecureRandom::random_number generates a random number.
	 *
	 * If a positive integer is given as $n,
	 * SecureRandom.random_number returns an integer:
	 * 0 <= SecureRandom::random_number($n) < $n.
	 *
	 *   echo SecureRandom::random_number(100); //=> 15
	 *   echo SecureRandom::random_number(100); //=> 88
	 *
	 * If 0 is given or an argument is not given,
	 * SecureRandom::random_number returns a float:
	 * 0.0 <= SecureRandom::random_number() < 1.0.
	 *
	 *   echo SecureRandom::random_number(); //=> 0.596506046187744
	 *   echo SecureRandom::random_number(); //=> 0.350621695741409
	 *
	 * @param string $n
	 * @return float
	 * @author Koen Punt
	 */
	public static function random_number($n=0){
		if($n > 0){
			// $length = (int) (log($n,2) / 8) + 1;
			return hexdec(bin2hex(static::random_bytes(1))) % $n;
		}
		return mt_rand() / mt_getrandmax();
	}

	/**
	 * SecureRandom::uuid generates a v4 random UUID (Universally Unique IDentifier).
	 *
	 *   echo SecureRandom::uuid(); //=> "2d931510-d99f-494a-8c67-87feb05e1594"
	 *   echo SecureRandom::uuid(); //=> "bad85eb9-0713-4da7-8d36-07a8e4b00eab"
	 *   echo SecureRandom::uuid(); //=> "62936e70-1815-439b-bf89-8492855a7e6b"
	 *
	 * The version 4 UUID is purely random (except the version).
	 * It doesn't contain meaningful information such as MAC address, time, etc.
	 *
	 * See RFC 4122 for details of UUID.
	 *
	 * @return void
	 * @author Koen Punt
	 */
	public static function uuid(){
		$ary = unpack("v*", self::random_bytes(16));
		$ary[4] = $ary[4] & 0x0fff | 0x4000;
		$ary[5] = $ary[5] & 0x3fff | 0x8000;
		return vsprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x', $ary);
	}
}
