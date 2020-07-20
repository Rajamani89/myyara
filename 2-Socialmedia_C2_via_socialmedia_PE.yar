rule Socialmedia_C2_via_socialmedia_PE
{
meta:

description = "Detect social media C2 channels in PE file"
author = "Raj"
date = "2019-07-20"

strings:
$lnkmagic = {4D 5A}
/*
    Magic number for PE files
*/
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
/*
    All social media urls in the content github,digital point ,reddit,facebook,twitter,telegram,wechat,youtube
*/

condition:
    $lnkmagic and ( 1 of ($URL_*) )
}
