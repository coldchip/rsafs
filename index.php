<?php


class ColdChipMath {
	
	public function Addition($a, $b){
		return gmp_add($a, $b);
	}
	
	public function PowerMod($a, $b, $c){
		return gmp_powm($a, $b, $c);
	}
	
	public function Multiply($a, $b){
		return gmp_mul($a, $b);
	}
	
	public function Subtract($a, $b){
		return gmp_sub($a, $b);
	}
	
	public function Modulus($a, $b){
		return gmp_mod($a, $b);
	}
	
	public function Divide($a, $b){
		return gmp_div($a, $b);
	}
	
	public function Compare($a, $b){
		return gmp_cmp($a, $b);
	}
	
}

class RSA extends ColdChipMath {
	
	public $publicKey;
	public $privateKey;
	
	private $defaultExponent = 65537;
	
	function __construct()
	{
		if (!extension_loaded('gmp')) {
			die("[FATAL_ERROR] This Library Requires PHP GMP Library, Please Enable It If You Had Installed It. ");
		}
	}
	
	private function textDec($text)
	{
		$result = '0';
		$n = strlen($text);
		do {
			$result = bcadd(gmp_mul($result, '256'), ord($text{--$n}));
		} while ($n > 0);
		return $result;
	}
	
	private function decText($num)
	{
		$result = '';
		do {
			$result .= chr(bcmod($num, '256'));
			$num = gmp_div($num, '256');
		} while (bccomp($num, '0'));
		return $result;
	}
	
	public function Encrypt($msg)
	{
		$this->data = base64_decode($this->publicKey);
		$this->exp = base64_decode(json_decode($this->data, true)["exp"]);
		$this->mod = base64_decode(json_decode($this->data, true)["mod"]);
		$this->encryptData = array();
		$this->encryptData["msg"] = $msg;
		$this->encryptData["nounce"] = hash("crc32", rand(100000, 999999));
		$this->encodedMsg = $this->textDec(json_encode($this->encryptData));
		if(strlen($this->encodedMsg) <= strlen($this->mod)) {
			$this->encryptedData = $this->PowerMod($this->encodedMsg, $this->exp, $this->mod);
			return base64_encode($this->encryptedData);
		} else {
			return false;
		}
		
	}
	
	public function Decrypt($encryptedMsg) {
		$this->data = base64_decode($this->privateKey);
		$this->exp = base64_decode(json_decode($this->data, true)["exp"]);
		$this->mod = base64_decode(json_decode($this->data, true)["mod"]);
		$this->decryptedMsg = $this->PowerMod(base64_decode($encryptedMsg), $this->exp, $this->mod);
		$this->decodedMsg = json_decode($this->decText($this->decryptedMsg), true);
		return $this->decodedMsg["msg"];
		
	}
	
	public function generateKeys($bitLen)
	{	
		$this->size = ceil((($bitLen/2)/8)*2.421875);
		for($i = 0; $i < $this->size; $i++)
		{
			$this->randp .= mt_rand(1, 9);
			$this->randq .= mt_rand(1, 9);
		}

		$this->p = gmp_nextprime($this->randp);
		$this->q = gmp_nextprime($this->randq);
		
		$this->n = $this->Multiply($this->p, $this->q);
		$this->phi_n = $this->Multiply($this->Subtract($this->p, 1), $this->Subtract($this->q, 1));
		
		$this->d = $this->genPrivateKey($this->defaultExponent, $this->phi_n);
		
		$this->publicKey =  $this->rsabase64encode($this->defaultExponent, $this->n);
		$this->privateKey = $this->rsabase64encode($this->d, $this->n);
		
		return true;
		
	}
	
	private function rsabase64encode($exponent, $modulus)
	{
		$this->packer = array();
		$this->packer["type"] = "COLDCHIPRSA";
		$this->packer["version"] = "1.2";
		$this->packer["exp"] = base64_encode($exponent);
		$this->packer["mod"] = base64_encode($modulus);
		$this->packer["sign"] = hash("SHA512", $exponent . $modulus);
		return base64_encode(json_encode($this->packer));
	}
	
	private function genPrivateKey($exponent, $phi_n)
	{
		$x = 1;
		$y = 0;
		$this->Exponent = $exponent;
		$this->Phi_n = $phi_n;
		do {
			$tmp = $this->Modulus($this->Exponent, $this->Phi_n);
			$q = $this->Divide($this->Exponent, $this->Phi_n);
			$this->Exponent = $this->Phi_n;
			$this->Phi_n = $tmp;
			$tmp = $this->Subtract($x, $this->Multiply($y, $q));
			$x = $y;
			$y = $tmp;
		} while ($this->Compare($this->Phi_n, '0') !== 0);
		if ($this->Compare($x, '0') < 0) {
			$x = $this->Addition($x, $phi_n);
		}

		return $x;
	}
	
	
}


class Compile extends RSA{
	
	private $outFol;
	private $MAGIC_HEADER = "f643484950";
	private $FILE_NAME_IDENTIFIER = "fe";
	private $DATA_IDENTIFIER = "eb";
	private $SUBDIR_IDENTIFIER = "b2";
	private $CHUNK_SEPERATOR = "fb";
	
	public function setPath($dirPath) {
		$this->folDir = $dirPath;
	}
	
	public function setOutput($file) {
		$this->outFile = $file;
	}
	
	public function compress($srcFol, $destFile) {
		if(!empty($srcFol)) {
			if(is_dir($srcFol)) {
				if(!empty($destFile)) {
					echo("Started compressing 0%");
					unlink($destFile);
					$fileHandler = fopen($destFile, "a");
					$header = hex2bin($this->MAGIC_HEADER . "00") . "V1.0" . hex2bin("00") . "FILESYS-V1.0";
					$header = str_pad($header, 64, hex2bin("00"));
					fwrite($fileHandler, $header);
					$this->recurseCompile($fileHandler, $srcFol, "");
				} else {
					echo("Error compressing, Output has not been defined. ");
				}
			} else {
				echo("Error compressing, Specified is NOT a directory. ");
			}
		}
	}
	
	private function encryptd($data) {
		$this->publicKey = "eyJ0eXBlIjoiQ09MRENISVBSU0EiLCJ2ZXJzaW9uIjoiMS4yIiwiZXhwIjoiTmpVMU16Yz0iLCJtb2QiOiJNVGszTXpnMU16azROVFF6TnpBM05ESXhOelUxTXpjNU9UWTVOekV3TmpFMk56azJNRGszT1RZeU5qY3hOakF3T1RBek5EQTVOVFUzT0RFd056a3pPVEExTlRBM01qZzVPVGt4TXpReE1qQTFOakkxTmpnMk5qUXdNVGt5TXpZd05Ua3dOVGMxTnpVNU16ZzNOakV3TWprMU5EQTFPRFF6T1RjeE1qY3dNVFEzT1RVNU1qYzNPRFE1TVRFeU56STJOREEwTmpZeU5qVTNPVE01T1Rjd05qTXdOVFEzTlRrek5UVTBPVEE1TVRrM05qVTVNamcyTWpNd09EWTRNekF3TmpNd01EYzFNemN3TlRFeU1UQXpNVFV3TWpVMU5qYzJPVEEzTXpFMU1UYzNOekkzT0RFeE5UQTJPREF5T0RFeU1qQTJOemt3T1RBMU1qVTRORGd4TURjNE56ZzFOVGczTlRVME9UY3hNVGt3TlRneE5qVTJNak16T0RrNE56VTROVFkzTlRVMU5EQXpPVGcwTVRneU9EQTBNRFE1TVE9PSIsInNpZ24iOiI2ZGIzNWEzMjY3NGY0MzM5NTA5ZTdkM2IxMmUzNTFlYjA0ZGEwMzM4MzU1NTFmODk1NGY3YTQyZjc5NjQ3YzU0ZGRhZjAzNGU4NTM5ZDllOGZiOTIzY2EwYTQyMzdlNWU5YzAzNTI3NWM3NDA4OWMzODRmYjgyMTkyMGU3ZmE4NyJ9";
		
		return gzdeflate(RSA::encrypt($data), 9);
	}
	
	private function decryptd($data) {
		$this->privateKey = "eyJ0eXBlIjoiQ09MRENISVBSU0EiLCJ2ZXJzaW9uIjoiMS4yIiwiZXhwIjoiTVRZd09EQXdPRFkzTVRFM01ESTJNRGsxT1RBM09UVTJNelk1TkRJeU5qRXpOalE1TkRRME9EazNNVGc0TkRBNU1UYzJPVGs1T0RBMk1EZzJPVEUzTVRBNU5qUTROVEEzTVRRek1UQTFOVEkzTmpreU1EY3pNekk0TXpRMk9Ea3dNRE13TlRJNU9USTJOVEV3TWpnME5EYzFOVEV6TXpRek56VTBNekE0TkRVME56VTVNRGd3TWpnd09ESXdOREk1TVRFeU5EZzFNVFV3TkRjM01UWTVORGs1TVRVMU5ESXlNVFkyTnpnNE5URTJOemsyT1RVek16STVOalU0TXpneE1UUXhNREk1T0RreU9ESTNOekF5TURjMU5UQTFNamd6TlRRME1ETTJNekF5TXpVek16RXdOelUxTmpVeE56STVPRGd4TVRrNE5URXpNelUzTWpFek1qazRNRGMxTURBek5EQTVNelU0TVRjeE5EazRORFl3TkRjMk1qRTNOVFExT1RZM09EZzNNelUwTnpNek9URTJOemd5TVRJeCIsIm1vZCI6Ik1UazNNemcxTXprNE5UUXpOekEzTkRJeE56VTFNemM1T1RZNU56RXdOakUyTnprMk1EazNPVFl5TmpjeE5qQXdPVEF6TkRBNU5UVTNPREV3Tnprek9UQTFOVEEzTWpnNU9Ua3hNelF4TWpBMU5qSTFOamcyTmpRd01Ua3lNell3TlRrd05UYzFOelU1TXpnM05qRXdNamsxTkRBMU9EUXpPVGN4TWpjd01UUTNPVFU1TWpjM09EUTVNVEV5TnpJMk5EQTBOall5TmpVM09UTTVPVGN3TmpNd05UUTNOVGt6TlRVME9UQTVNVGszTmpVNU1qZzJNak13T0RZNE16QXdOak13TURjMU16Y3dOVEV5TVRBek1UVXdNalUxTmpjMk9UQTNNekUxTVRjM056STNPREV4TlRBMk9EQXlPREV5TWpBMk56a3dPVEExTWpVNE5EZ3hNRGM0TnpnMU5UZzNOVFUwT1RjeE1Ua3dOVGd4TmpVMk1qTXpPRGs0TnpVNE5UWTNOVFUxTkRBek9UZzBNVGd5T0RBME1EUTVNUT09Iiwic2lnbiI6Ijg2ODFmZWZkMzBhODFhYTQ1MzFlOTYxZWYxYTUwNjJkMjQzOTBmOTRhMTQ5NDZkMDg3ODFjZGU5N2NlMzliOWViODM2MjcyOTlkZTA0ZjYzMDlmZmM1NDliNTkzMjhjYjg0ZGU1ZjY5N2VhZGNmOTA0ZGU2M2M2YTdmNDdhZDkwIn0=";
		
		return RSA::decrypt(gzinflate($data));
	}
	
	private function recurseCompile($handler, $dir, $sd) {	
		$scan = scandir($dir);
		foreach($scan as $scans) {
			
			if($scans !== "." && $scans !== "..") {
				echo("<br> Please wait... Compressing: " . $dir . "/" . $scans . "<br>");
				if(is_file($dir . "/" . $scans)) {

					$fileDataHandler = fopen($dir . "/" . $scans, "r");
					
					fwrite($handler, hex2bin($this->FILE_NAME_IDENTIFIER) . $sd . "/" . $scans . hex2bin($this->FILE_NAME_IDENTIFIER));

					fwrite($handler, hex2bin($this->DATA_IDENTIFIER));
					while(!feof($fileDataHandler)) {
						$dataChunk = $this->encryptd(fread($fileDataHandler, 50));
						$compressedLength += (strlen($dataChunk));
						$fileSize = fstat($fileDataHandler)["size"];
						error_log("Compressing: " . $scans . " " . round(($compressedLength / $fileSize) * 100, 1) . "%");

						fwrite($handler, hex2bin($this->CHUNK_SEPERATOR) . strlen($dataChunk) . hex2bin($this->CHUNK_SEPERATOR) . $dataChunk);
	
					}
					fwrite($handler, hex2bin($this->DATA_IDENTIFIER));
				} if(is_dir($dir . "/" . $scans)) {
					fwrite($handler, hex2bin($this->SUBDIR_IDENTIFIER) . $sd . "/" . $scans . hex2bin($this->SUBDIR_IDENTIFIER));
				
					$this->recurseCompile($handler, $dir . "/" . $scans, $sd . "/" . $scans);
					
				}
			}
		}
		return $data;
	}
	
	public function decompress($path, $out) {
		$data = fopen($path, "r");
		
		$header = fread($data, 64);
		
		if(!empty($out) && is_dir($out)) {
			$this->outFol = $out;
			$this->decdd($data, "");
			fclose($data);
		} else {
			echo("Empty out");
		}

	}
	
	private function decdd($data, $subdir) {
		
		while(!feof($data)) {
			
			$bit = fread($data, 1);
			if($bit == hex2bin($this->FILE_NAME_IDENTIFIER)) {
				$fileName = $this->freadUntil($data, $this->FILE_NAME_IDENTIFIER);
			}
			if($bit == hex2bin($this->SUBDIR_IDENTIFIER)) {
				$subDir = $this->freadUntil($data, $this->SUBDIR_IDENTIFIER);
				echo("Making DIR: " . $this->outFol . "/" . $subDir . "<br>");
				if(!is_dir($this->outFol . "/" . $subDir)) {
					mkdir($this->outFol . "/" . $subDir);
				}
			}
			if($bit == hex2bin($this->DATA_IDENTIFIER)) {
				$writeData = fopen($this->outFol . "/" . $fileName, "w");
				echo("Writing File: " . $fileName . "<br>");
				if($writeData) {
					$this->fcopyUntil($data, $writeData);
				} else {
					die("Opps. Error");
				}
			}
			
			
		}

	}
	
	private function freadUntil($handler, $until) {
		while(true){
			$bit = fread($handler, 1);
			if($bit == hex2bin($until)) {
				break;
			} else {
				$data .= $bit;
			}
		}
		return $data;
	}
	
	private function fcopyUntil($handler, $copyHandler) {
		while(!feof($handler)){
			$header = fread($handler, 1);
			if($header == hex2bin($this->CHUNK_SEPERATOR)) {
				$length = "";
				$length = $this->freadUntil($handler, $this->CHUNK_SEPERATOR);

				$bit = fread($handler, $length);

				fwrite($copyHandler, $this->decryptd($bit));
			} else {
				break;
			}
		}
		fclose($copyHandler);
		return $data;
	}
	
}

$test = new Compile();

$test->compress($_SERVER["DOCUMENT_ROOT"] . "/login", $_SERVER["DOCUMENT_ROOT"] . "/compile/compressedData.cdat");

//$test->listData($_SERVER["DOCUMENT_ROOT"] . "/compile/compressedData.cdat", "data");

$test->decompress($_SERVER["DOCUMENT_ROOT"] . "/compile/compressedData.cdat", $_SERVER["DOCUMENT_ROOT"] . "/testfol");

?>