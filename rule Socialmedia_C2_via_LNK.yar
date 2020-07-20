rule Socialmedia_C2_via_LNK
{
meta:

description = "Detect C2 channels in lnk file"
author = "Raj"
date = "2019-07-16"
Reference_1 = "https://www.welivesecurity.com/2020/07/09/more-evil-deep-look-evilnum-toolset/"
Reference_2 = "https://github.com/eset/malware-ioc/tree/master/evilnum"

strings:
$cmdline_1 = "C:\\Windows\\System32\\cmd.exe" ascii wide
$lnkmagic = {4C 00 00 00 01 14 02 00}
$URL_1 = "gitlab.com/" ascii wide
$URL_2 = "raw.githubusercontent.com" ascii wide
$URL_3 = "digitalpoint.com/members" ascii wide
$URL_4 = "reddit.com/user/" ascii wide
$URL_5 = "facebook.com/" ascii wide
$URL_6 = "twitter.com" ascii wide
$URL_7 = "wechat.com"  ascii wide
$URL_8 = "telegram.com" ascii wide
$URL_9= "t.me/" ascii wide
$URL_10 = "youtube.com" ascii wide

condition:
    $cmdline_1 and $lnkmagic and ( 1 of ($URL_*) )
}
