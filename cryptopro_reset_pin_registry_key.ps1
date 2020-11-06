#Created By U.G. 2020
	
#import CrytoAPI from advapi32.dll
$signature = @"
[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
[return : MarshalAs(UnmanagedType.Bool)]
	public static extern bool CryptAcquireContext(
		ref IntPtr hProv,
		string pszContainer,
		string pszProvider,
		uint dwProvType,
		long dwFlags
	);

[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool CryptSetProvParam(
		IntPtr hProv,
		uint dwParam,
		[In] byte[] pbData,
		uint dwFlags
	);

[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
[return : MarshalAs(UnmanagedType.Bool)]
	public static extern bool CryptReleaseContext(
		IntPtr hProv,
		uint dwFlags
	);
"@

$CryptoAPI = Add-Type -member $signature -name Advapi32 -Namespace CryptoAPI -passthru

#Struct Pin conatainer
add-type @"
using System;
using System.Runtime.InteropServices;
namespace Structs {
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
	public struct CRYPT_PIN_PARAM {
		public byte type;
		[MarshalAs(UnmanagedType.LPStr)]
		public string passwd;
	};
}
"@

#Algoritmic brute-force
add-type @"
public class Brute
{
	private int min_len;
	private int counter;
	private int i_base;
	private int whole_partition;
	private int remainder_of_division;
	private int max_combinations_for_length;
	private string alphabet;
	private string result;
	private char[] alphabet_array;
	
	private void Init()
	{
		i_base = alphabet.Length;
		alphabet_array = alphabet.ToCharArray();
		min_len = 1;
		counter = 0;
		result = "";
		max_combinations_for_length = rpow(i_base,min_len);
	}
	
	public Brute()
	{
		alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
		Init();
	}
	
	public Brute(string _alphabet)
	{
		if(_alphabet.Length > 0)
		{
			alphabet = _alphabet;
		} 
		else 
		{
			alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
		}
		Init();
	}
	
	private int rpow(int n, int p)
	{
		if(p == 0)
		{
			return 1;
		}
		return n*(rpow(n,(p-1)));
	}
	
	public void Reset()
	{
		Init();
	}
	
	public int Length
	{
		get
        {
            return min_len;
        }
        set
        {
			if(min_len>0)
			{
				min_len = value;
			}
			else 
			{
				min_len = 1;
			}
			counter = 0;
        }
	}
	
	public int Counter
	{
		get
        {
            return counter;
        }
        //set
        //{
        //    counter = value;
        //}
	}
	
	public string Alphabet
	{
		get
        {
            return alphabet;
        }
        set
        {
            alphabet = value;
			Init();
        }
	}
	
	public string Next()
	{	
		result = "";
		whole_partition = counter;
		while(whole_partition > 0)
		{
			remainder_of_division = whole_partition % i_base;
			whole_partition = (whole_partition-remainder_of_division) / i_base;
			result = alphabet_array[remainder_of_division] + result;
		}
		while(result.Length < min_len)
		{
			result = '0' + result;
		}
		if(counter == (max_combinations_for_length-1))
		{
			min_len++;
			max_combinations_for_length = rpow(i_base,min_len);
			counter = 0;
		} 
		else 
		{
			counter++;
		}
	 return result;
	}
}
"@

# set path to registry for current OS

$IsArchX64 = $false
$PathToRegCPro = "HKEY_LOCAL_MACHINE\Software\Crypto Pro\Settings\Users"
If([IntPtr]::Size -eq 8) 
{
	$IsArchX64 = $true
	$PathToRegCPro = "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Crypto Pro\Settings\Users"
}

$SID = (Get-WmiObject win32_useraccount -Filter "Name='$($env:USERNAME)'").SID
If($SID.length -eq 0) {
	$SID = (Get-WmiObject win32_useraccount -Filter "Name='$($env:USERNAME)' AND domain = '$env:USERDOMAIN'").SID
} 
If($SID.length -eq 0) {
	$NtAccountObj = New-Object System.Security.Principal.NTAccount('$env:USERDOMAIN','$env:USERNAME')
	$SID = $($NtAccountObj.Translate([System.Security.Principal.SecurityIdentifier])).Value
}

$FullPathToReg = "$PathToRegCPro\$SID\Keys"

# set some constants for CryptoAPI

$PP_KEYEXCHANGE_PIN = 32 #(0x20)
$PP_CHANGE_PIN = 108
$CRYPT_SILENT = 0x00000040
$CRYPT_PIN_PASSWD = 0

$providers = @{
    p2001 = @{
        type  = 75
        name = "Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider"
    }
    p2012 = @{
        type  = 80
        name = "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider"
    }
}

$encUTF8 = [System.Text.Encoding]::UTF8
$encASCII = [System.Text.Encoding]::ASCII

function ChangePin {
Param(
        [Parameter(Mandatory = $True)]
        [Byte[]] $old,

        [Parameter(Mandatory = $True)]
        [Byte[]] $new,
		
	[Parameter(Mandatory = $True)]
	$provider
    )
	[System.IntPtr]$hProv=0	
	
	$pinIsCorrect = $false
	if($CryptoAPI::CryptAcquireContext([ref]$hProv,$container,$provider.name,$provider.type,$CRYPT_SILENT)) {
		if($CryptoAPI::CryptSetProvParam($hProv, $PP_KEYEXCHANGE_PIN, $oldPinBytes, 0)) {
			if($CryptoAPI::CryptSetProvParam($hProv, $PP_CHANGE_PIN, $newPinBytes, 0)) {
				#Write-Host "CryptSetProvParam is success. [PP_CHANGE_PIN]" -f Yellow
				#Write-Host "Pin reset is success: $($oldPin)" -f Yellow
				$pinIsCorrect = $true
			}
			else {
				#Write-Host "Pin reset is fail: $($oldPin)" -f Yellow
			}
		}
	}
	$ret = $CryptoAPI::CryptReleaseContext($hProv,0)
	$hProv = 0
 [bool] $pinIsCorrect
}

function CryptoPROResetPin {
Param(
        [Parameter(Mandatory = $True)]
	[ValidateLength(1,255)]
        [string] $container,

	[Parameter(Mandatory = $False)]
	[ValidateRange(1,12)]
        [int] $min_len=1,
		
	[Parameter(Mandatory = $False)]
	[ValidateRange(1,12)]
        [int] $max_len=12,
		
        [Parameter(Mandatory = $False)]
	[ValidateSet(2001,2012)]
        [int] $alg=2012,
		
	[Parameter(Mandatory = $False)]
	[ValidateLength(1,255)]
        [string] $alphabet="0123456789"
    )
	try {
	
		$container = "\\.\REGISTRY\$container"
		$provider = $providers['p2012']
		if($alg -eq 2001){
			$provider = $providers['p2001']
		}
		$newPin = "1"
		
		#{ Initial struct
		$newCryptPinParam = New-Object Structs.CRYPT_PIN_PARAM
		$newCryptPinParam.type = $CRYPT_PIN_PASSWD
		$newCryptPinParam.passwd = $newPin
		#}
		$ptrStructSize = [System.Runtime.InteropServices.Marshal]::SizeOf($newCryptPinParam)
		$ptrStruct = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ptrStructSize)
		#if set 3rd parameter "true" it would crashing "powershell" (ntdll 0xc0000374)
		#https://docs.microsoft.com/ru-ru/dotnet/api/system.runtime.interopservices.marshal.structuretoptr?view=netcore-3.1
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($newCryptPinParam, $ptrStruct, $false) 
		$newPinBytes = New-Object Byte[] $ptrStructSize
		[System.Runtime.InteropServices.Marshal]::Copy($ptrStruct, $newPinBytes, 0, $ptrStructSize)
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptrStruct)

		#start calc time running
		$StartTime = (Get-Date)
		$r = 0
		$brute = New-Object Brute($alphabet)
		$brute.Length = $min_len
		while( $brute.Length -le $max_len ){
			$oldPinStr = $brute.Next()
			$oldPinBytes = $encASCII.GetBytes($oldPinStr)
			$ret = ChangePin $oldPinBytes $newPinBytes $provider
			$r++
			if($r -eq 1000) {
				$EndTime = (Get-Date)
				$DiffTime = $EndTime-$StartTime
				Write-Host "time: $($DiffTime)" -f Yellow
				$r = 0
			}
			if($ret){
				$EndTime = (Get-Date)
				$DiffTime = $EndTime-$StartTime
				Write-Host "$($oldPinStr)" -f Yellow
				Write-Host "$($oldPinStr)" -f Yellow
				Write-Host "time: $($DiffTime)" -f Yellow
				exit
			}
			else {
				Write-Host "$($oldPinStr)" -f Red
			}
			
		}

	} 
	catch {
		Write-Host "Error:$($error[0].Exception.Message) `r`nLine:$($error[0].InvocationInfo.ScriptLineNumber) `r`nSymbol:$($error[0].InvocationInfo.OffsetInLine) `r`nBlock:$($error[0].InvocationInfo.Line)"
	} 
	finally {
		$EndTime = (Get-Date)
		$DiffTime = $EndTime-$StartTime
		Write-Host "time: $($DiffTime)" -f Green
		Remove-Variable -Name * -Force -Scope Script -ErrorAction SilentlyContinue
	}
}

#Parse script args 
if($args.count -gt 0) {
	$n = ""
	$mn = 1
	$mx = 8
	$a = 2012
	$s = "0123456789"
	$isSetName = $false
	$p=$args
	0..($args.count-1) | % {
		if($p[$_] -eq '-n'){
			$n = $p[$_+1]
			$isSetName = $true
		}
		if($p[$_] -eq '-mn'){
			$mn = $p[$_+1]
		}
		if($p[$_] -eq '-mx'){
			$mx = $p[$_+1]
		}
		if($p[$_] -eq '-a'){
			$a = $p[$_+1]
		}
		if($p[$_] -eq '-s'){
			$s = $p[$_+1]
		}
	}
	if($isSetName -eq $true){
		$FullPathToReg += "\$n"
		$FullPathToRegExist = Test-Path -Path Registry::"$FullPathToReg"
		if($FullPathToRegExist) { 
			CryptoPROResetPin -container $n -min_len $mn -max_len $mx -alg $a -alphabet $s
		} else {
			Write-Host "-n %container name% - the parameter is not found in a system registry. check the script launch parameters" -f Red
			GotoHelp
		}
	} else {
		Write-Host "-n %container name% - the parameter is required and not defined. check the script launch parameters" -f Red
		GotoHelp
	}
} else {
	Write-Host "The parameters is not defined. check the script launch parameters" -f Red
	GotoHelp
}

function GoToHelp(){
	Write-Host "#your ps script path#\cryptopro_reset_pin_registry_key.ps1 -n %1 [-mn %2] [-mx %3] [-a %4] [-s %5]" -f Blue
	Write-Host "-n %1-#your container registry name#" -f Blue
	Write-Host "-mn %2-#min length brute password#" -f Blue
	Write-Host "-mx %2-#max length brute password#" -f Blue
	Write-Host "-a %3-#algorithm keys crypto provider (GOST 2001\2012)#" -f Blue
	Write-Host "-s %4-#alphabet for your brute#" -f Blue
	Write-Host "This script will brute-force a password from a given alphabet until it iterates over all combinations to length." -f Blue
	Write-Host "example: ./cryptopro_reset_pin_registry_key.ps1 -n 'RegistryKeyName' -mn 3 -mx 6 -a 2001 -s '0123a'" -f Yellow
}
