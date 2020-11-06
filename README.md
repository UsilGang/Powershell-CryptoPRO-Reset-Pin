# Powershell-CryptoPRO-Reset-Pin
(RU) Данный скрипт был написан для сброса забытого пин-кода от контейнера закрытого ключа "Крипто ПРО" расположенного в реестре. Автор не несет ответственности за любые последствия в результате установки и использования данного скрипта, пользователь использует его "как есть" на свой страх и риск.

(EN) This script was written to reset the forgotten PIN code from the Crypto PRO private key container located in the registry. The author is not responsible for any consequences as a result of the installation and use of the script described below, the user uses it "as is" at his own peril and risk.

----
**This script will brute-force a password from a given alphabet until it iterates over all combinations to length.**

| **%your_ps_script_path%\cryptopro_reset_pin_registry_key.ps1 -n %1 [-mn %2] [-mx %3] [-a %4] [-s %5]**|
|---|

| arg | description | 
| --- | --- |
|-n  %1 | your container registry name |
|-mn %2 | min length brute password |
|-mx %3 | max length brute password |
|-a  %4 | algorithm keys crypto provider (GOST 2001\2012) |
|-s  %5 | alphabet for your brute |


*example: ./cryptopro_reset_pin_registry_key.ps1 -n 'RegistryKeyName' -mn 3 -mx 6 -a 2001 -s '0123a'*
