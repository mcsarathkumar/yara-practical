/*
Title       : Malware Analysis - Lab 3
Author      : Sarathkumar MC - MT20ACS531
Created On  : August 21, 2021
*/

rule AgentTesla
{
    meta:
        description = "AgentTesla"
        os = "mswindows"
        filetype = "pe"
        maltype = "trojan"

    strings:
        $noDos = "This program cannot be run in DOS mode"
        $hash1 = "46599D29C9831138B75ED7B25049144259139724"
        $hash2 = "92C47DC4F08DC5D2560CAA66BD2B9E7B16370916"
        $a4ExeFile = "a4attempt4"
        $publicToken1 = "b03f5f7f11d50a3a"
        $publicToken2 = "b77a5c561934e089"
    
    condition:
        $noDos and $hash1 and $hash2 and $a4ExeFile and $publicToken1 and $publicToken2
}
