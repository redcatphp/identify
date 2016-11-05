<?php
namespace RedCat\Identify;
use RandomLib\Factory as RandomLibFactory;
class Random{
	static function getString($length=40){
		if(function_exists('random_bytes')){
			return bin2hex(random_bytes($length));
		}
		return self::hex2setstring(bin2hex((new RandomLibFactory())->getMediumStrengthGenerator()->generate($length)));
	}
	static function hex2setstring($hex){
		$chars = 'abcdefghijklmnopqrstuwvxyzABCDEFGHIJKLMNOPQRSTUWVXYZ0123456789';
		$setbase=strlen($chars);    
		$answer = '';   
		while (!empty($hex) && ($hex !== 0) && ($hex !== dechex(0))) {  
			$hex_result = '';
			$hex_remain = '';       
			// divide by base in hex:
			for ($i=0;$i<strlen($hex);$i+=1){
				$hex_remain = $hex_remain . $hex[$i];           
				$dec_remain = hexdec($hex_remain);
				// small partial divide in decimals:
				$dec_result = (int)($dec_remain/$setbase);          
				if (!empty($hex_result) || ($dec_result > 0))
					$hex_result = $hex_result . dechex($dec_result);

				$dec_remain = $dec_remain - $setbase*$dec_result;
				$hex_remain = dechex($dec_remain);
			}
			$answer = $chars[$dec_remain] . $answer;
			$hex = $hex_result;
		}
		return $answer;
	}
}