<?php

/**
 * @license http://www.gnu.org/licenses/gpl-2.0.html GNU General Public License, version 2
 * @license
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * @link http://phpwhois.pw
 * @copyright Copyright (C)1999,2005 easyDNS Technologies Inc. & Mark Jeftovic
 * @copyright Maintained by David Saez
 * @copyright Maintained by Kevin Lucich since 2023-06-01
 * @copyright Copyright (c) 2014 Dmitry Lukashin
 */

namespace phpWhois;

use DateTime;
use DateTimeZone;
use phpWhois\IpTools;
use phpWhois\Utils\Countries;


/**
 * phpWhois basic class
 *
 * This is the basic client class
 */
class WhoisClient
{
    /**
     * @var bool Perform a "deep whois request", but will be slower
     */
    public $deepWhois = true;

    /** @var boolean Is recursion allowed? */
    public $gtldRecurse = false;

    /** @var int Default WHOIS port */
    public $port = 43;

    /** @var int Maximum number of retries on connection failure */
    public $retry = 0;

    /** @var int Time to wait between retries */
    public $sleep = 2;

    /** @var int Read buffer size (0 == char by char) */
    public $buffer = 1024;

    /** @var int Communications timeout */
    public $stimeout = 10;

    /** @var string[] List of servers and handlers (loaded from servers.whois) */
    public $DATA = [];

    /** @var string[] Non UTF-8 servers */
    public $NON_UTF8 = [];

    /** @var string[] List of Whois servers with special parameters */
    public $WHOIS_PARAM = [];

    /** @var string[] TLD's that have special whois servers or that can only be reached via HTTP */
    public $WHOIS_SPECIAL = [];

    /** @var string[] Handled gTLD whois servers */
    public $WHOIS_GTLD_HANDLER = [];

    /** @var $query array Array to contain all query publiciables */
    public $query = [
        'tld' => '',
        'type' => 'domain',
        'query' => '',
        'status' => '',
        'server' => '',
        'errstr' => []
    ];

    /** @var string Current release of the package */
    public $codeVersion = null;

    /** @var string Full code and data version string (e.g. 'Whois2.php v3.01:16') */
    public $version;

    protected const IANA_REGISTRAR_IDS = [
        1 => 'Reserved',
        2 => 'Network Solutions, LLC',
        3 => 'Registry Installation',
        4 => 'Advanced Systems Consulting, Inc.',
        6 => 'asf',
        8 => 'Test Registrar',
        9 => 'register.com, Inc.',
        10 => 'AT&T Corporation',
        11 => 'Edge, Inc.',
        12 => 'Bazillion, Inc.',
        13 => 'Melbourne IT, Ltd',
        14 => 'ORANGE',
        15 => 'Corehub, S.R.L.',
        16 => 'AOL LLC',
        18 => 'CADVision Development Corporation dba GetDomain.com',
        19 => 'CommuniTech.Net, Inc.',
        22 => 'eXtraActive, Inc.',
        25 => 'FloridaNet, Inc. d/b/a ValueWeb',
        26 => 'HKNet Company Limited',
        27 => 'Identity Defense, Inc.',
        28 => 'InfoBack Corporation',
        30 => 'NameSecure L.L.C.',
        31 => 'DSTR Acquisition PA I, LLC dba DomainBank.com',
        44 => 'Prodigy Communications Corporation',
        45 => 'RCN Corporation',
        47 => 'REACTO.com Limited',
        48 => 'eNom, Inc.',
        49 => 'GMO Internet Inc.',
        50 => 'Telepartner A/S',
        51 => 'Verio, Inc.',
        52 => 'Deluxe Small Business Sales, Inc. d/b/a Aplus.net',
        53 => 'A Technology Company, Inc.',
        54 => 'Signature Domains, LLC',
        56 => 'Inquent Technologies, Inc. f/k/a WebHosting.com, Inc.',
        57 => 'Advanced Internet Technologies, Inc. (AIT)',
        58 => 'AW Registry, Inc.',
        59 => 'Tech Dogs, Inc.',
        60 => 'Internet Domain Registrars d/b/a Registrars.com',
        61 => 'Hosting.com, Inc.',
        62 => 'WebTrends Corporation',
        63 => 'eNom401, Incorporated',
        64 => 'Domain Registration Services, Inc. dba dotEarth.com',
        65 => 'DomainPeople, Inc.',
        66 => 'Enameco, LLC',
        67 => 'CASDNS Inc.',
        68 => 'NordNet SA',
        69 => 'Tucows Domains Inc.',
        70 => 'Group NBT plc aka NetNames',
        71 => 'Jiva Online Pty Ltd.',
        72 => 'Dotster, Inc.',
        73 => 'Domaininfo AB, aka domaininfo.com',
        74 => 'Online SAS',
        75 => 'Tech Electro Industries, Inc.',
        76 => 'Nominalia Internet S.L.',
        78 => 'PSI-Japan, Inc.',
        79 => 'Easyspace LTD',
        80 => 'Virtualis Systems Inc.',
        81 => 'Gandi SAS',
        82 => 'OnlineNIC, Inc.',
        83 => '1&1 Internet AG',
        84 => 'UK-2 Limited',
        85 => 'EPAG Domainservices GmbH',
        86 => 'TierraNet Inc. d/b/a DomainDiscover',
        87 => 'HANGANG Systems, Inc. d/b/a doregi.com',
        88 => 'Namebay SAM',
        89 => 'Computer Data Networks dba Shop4domain.com and Netonedomains.com',
        91 => '007Names, Inc.',
        93 => 'GKG.NET, INC.',
        94 => 'Parava Networks, Inc. dba 10-Domains.com',
        97 => 'DomainZoo.com, Inc.',
        98 => 'EnetRegistry.com Corporation',
        99 => 'pair Networks, Inc. d/b/a pairNIC',
        100 => 'Whois Networks Co., Ltd.',
        101 => '#1 Domain Names International, Inc. dba 1dni.com',
        103 => 'PacNames Ltd',
        104 => 'Domainsite.com, Inc.',
        105 => 'MyDomain, Inc.',
        106 => 'Ascio Technologies, Inc. Danmark - Filial af Ascio technologies, Inc. USA',
        108 => 'InfoBack Corporation',
        109 => 'MS Intergate, Inc.',
        110 => 'Shaver Communications, Inc.',
        111 => 'Secura GmbH',
        112 => 'Catalog.com',
        113 => 'CSL Computer Service Langenbach GmbH d/b/a joker.com',
        119 => 'Reserved for Internal Registry Use',
        120 => 'Xin Net Technology Corporation',
        121 => 'Dotregistrar, LLC',
        122 => 'Free Yellow.Com, Inc.',
        123 => 'The Registry at Info Avenue, LLC d/b/a Spirit Communications',
        124 => 'NameEngine, Inc.',
        125 => 'Talk.com, Inc.',
        127 => 'I.D.R. Internet Domain Registry Ltd.',
        128 => 'DomainRegistry.com, Inc.',
        129 => 'Eastern Communications Co., Ltd.',
        130 => 'Netpia.com, Inc.',
        131 => 'Total Web Solutions Ltd. trading as TotalRegistrations',
        132 => 'NETPLEX LLC',
        133 => '1stDomain LLC',
        134 => 'BB Online Ltd',
        136 => 'iDirections.com, Inc.',
        139 => '2Day Internet Limited dba 2day.comd',
        140 => 'Acens Technologies, S.L.U.',
        141 => 'Cronon AG',
        142 => 'Innerwise, Inc. d/b/a ItsYourDomain.com',
        143 => 'Omnis Network, LLC',
        144 => 'Alldomains, LLC',
        145 => 'Site Leader, Inc.',
        146 => 'GoDaddy.com, LLC',
        148 => 'I.net',
        151 => 'PSI-USA, Inc. dba Domain Robot',
        152 => 'FullWeb, Inc. d/b/a FullNic',
        165 => 'TT',
        166 => '7ways',
        167 => 'DEXT Co., Ltd.',
        168 => 'Register.it SPA',
        186 => 'NameScout Corp.',
        206 => 'Antelecom, Inc. f/k/a Hughes Electronic Commerce, Inc.',
        226 => 'Deutsche Telekom AG',
        228 => 'Moniker Online Services LLC',
        230 => 'Centergate Research Group, LLC',
        232 => 'Datasource Network Australia Limited',
        239 => '7DC, Inc.',
        240 => 'PlanetDomain Pty Ltd',
        241 => 'Ranger Registration (Madeira) LLC',
        242 => 'iRegisterDomainsHere.Com, Inc.',
        243 => 'INTERNEXT',
        244 => 'Gabia, Inc.',
        245 => '123 Registration, Inc.',
        246 => 'nondotcom, Inc.',
        247 => 'Active 24 AS',
        249 => 'Visesh Infotecnics Ltd. d/b/a Signdomains.com',
        250 => 'Echo, Inc.',
        255 => 'Hi-Tech Information and Marketing Pvt. Ltd.',
        256 => 'New Era Information Systems Incorporation d/b/a WebYourCompany.com',
        257 => 'GlobalHosting, Inc. d/b/a SiteRegister',
        258 => 'Marksonline, Inc.',
        268 => 'pAsia, Inc.',
        269 => 'Key-Systems GmbH',
        270 => 'Address Creation, LLC',
        274 => 'American Domain Name Registry',
        275 => 'Alice\'s Registry, Inc.',
        276 => 'Globedom Datenkommunikations GmbH, d/b/a Globedom',
        277 => 'Interlink Co., Ltd.',
        278 => '4Domains, Inc.',
        279 => 'NameRepublic.com',
        280 => 'Affinity Internet, Inc.',
        281 => 'Research Institute of Computer Science, Inc.',
        282 => 'Central Registrar, Inc. d/b/a DomainMonger.Com',
        291 => 'DNC Holdings, Inc.',
        292 => 'MarkMonitor Inc.',
        293 => 'Yellowiz Corp. d/b/a Yellowname.com',
        295 => 'British Telecommunications (BT plc)',
        298 => 'Netblue Communications Co., Ltd.',
        299 => 'CSC Corporate Domains, Inc.',
        300 => 'Wooho Technology CO., Ltd d/b/a RGNames.com',
        301 => '000domains, LLC',
        303 => 'PDR Ltd. d/b/a PublicDomainRegistry.com',
        304 => 'freenet Cityline GmbH d/b/a freenet Datenkommunikations GmbH',
        305 => 'Unassigned',
        306 => 'Unassigned',
        317 => 'Philippine Registry.com, Inc.',
        320 => 'TLDs LLC dba SRSplus',
        321 => 'Registration Technologies, Inc.',
        345 => 'VeriSign Global Registry Services',
        347 => 'NameTree, Inc.',
        353 => 'Bombora Technologies Pty Ltd',
        360 => 'Abu-Ghazaleh Intellectual Property dba TAGIdomains.com',
        363 => 'Funpeas Media Ventures, LLC dba DomainProcessor.com',
        364 => 'Triara.com S.A. de C.V.',
        365 => 'Educause',
        376 => 'RESERVED-Internet Assigned Numbers Authority',
        377 => 'Venture.com, Inc. d/b/a DomainCity.com',
        378 => '2030138 Ontario Inc. dba NamesBeyond.com and dba GoodLuckDomain.com',
        379 => 'Arsys Internet, S.L. dba NICLINE.COM',
        380 => 'Tuonome.it.srl d/b/a APIsrs.com',
        381 => 'DomReg Ltd. d/b/a LIBRIS.COM',
        400 => '@Com Technology LLC',
        401 => 'Misk.com, Inc.',
        402 => 'Adgrafix Corporation',
        403 => 'AZC, Inc. d/b/a AZC.com',
        404 => 'C I Host, Inc.',
        405 => 'CADVision Development Corp d/b/a GetDomain.com',
        406 => 'CommuniTech.Net, Inc.',
        407 => 'Concentric Network Corporation',
        408 => 'Cydian Technologies, LLC',
        409 => 'DevelopersNetwork.com., Inc. dba DomainInvestigator.com (Canada)',
        410 => 'Apex Registry, Inc.',
        411 => 'Fabulous.com Pty Ltd.',
        412 => 'Domain-It!, Inc.',
        413 => 'Domain Pro, LLC',
        414 => 'Eastern Counties Newspaper Group Ltd. d/b/a Eastern Counties Network',
        415 => 'Equitron, Inc. d/b/a DomainNameRegistration.com',
        416 => 'eWindowShop.com',
        417 => 'ExtremeNames.com',
        418 => 'CommuniGal Communication Ltd.',
        419 => 'HDFC WebNet Services Ltd.',
        420 => 'HiChina Zhicheng Technology Limited',
        421 => 'InfoNetworks, Inc.',
        422 => 'InfoUSA.com',
        423 => 'Internetplaza City Co., Ltd.',
        424 => 'Internetters Limited',
        425 => 'Intuit, Inc.',
        426 => 'iTool.com, Inc.',
        427 => 'Lightrealm',
        428 => 'Name.Space, Incorporated',
        429 => 'Neomode Co., Ltd.',
        430 => 'CORPORATION SERVICE COMPANY (UK) LIMITED',
        431 => 'DreamHost, LLC',
        432 => 'Nobel Networks',
        433 => 'OVH sas',
        434 => 'PRIMUS Telecommunications Canada Inc.',
        435 => 'Professo, LLC',
        436 => 'PSINet Inc.',
        437 => 'SiteName Ltd.',
        438 => 'Direct Connection Ltd.',
        439 => 'USA Webhost, Inc.',
        440 => 'Wild West Domains, LLC',
        441 => 'HANILNETWORKS Co., Ltd.',
        442 => 'IKANO Communications',
        443 => 'Vayala Corporation dba Demand.com',
        444 => 'Inames Co. Ltd.',
        445 => 'Bondi, LLC',
        446 => 'Hosting-Network, Inc.',
        447 => 'SafeNames Ltd.',
        448 => 'Universal Registration Services, Inc. dba NewDentity.com',
        449 => 'Korea Information Certificate Authority, Inc. dba DomainCA.com',
        450 => 'DomainName, Inc.',
        451 => 'AAAQ.COM, Inc.',
        452 => 'Name105, Inc.',
        453 => 'AllGlobalNames, S.A. dba Cyberegistro.com',
        454 => 'Unassigned',
        455 => 'EnCirca, Inc.',
        456 => 'Webnames.ca Inc.',
        457 => 'Cydentity, Inc. dba Cypack.com',
        458 => '#1 Accredited Registrar',
        459 => 'Domain Monkeys LLC',
        460 => 'Web Commerce Communications Limited dba WebNic.cc',
        461 => 'DotForce Corp. dba DotForce.com',
        462 => 'Personal Names Limited',
        463 => 'Regional Network Information Center, JSC dba RU-CENTER',
        464 => 'Name 2 Host, Inc. dba name2host.com',
        465 => 'Domains.coop Limited',
        466 => 'DomainSite, Inc.',
        467 => 'Techorus Inc.',
        468 => 'Amazon Registrar, Inc.',
        469 => 'easyDNS Technologies, Inc.',
        470 => 'Nom-iq Ltd. dba COM LAUDE',
        471 => 'Bizcn.com, Inc.',
        472 => 'Dynadot, LLC',
        473 => 'Best Registration Services, Inc. dba BestRegistrar.com',
        474 => 'Firstserver, Inc.',
        475 => 'R. Lee Chambers Company LLC dba DomainsToBeSeen.com',
        484 => 'Unassigned',
        500 => 'Terminated Registrar',
        600 => 'Rebel Ltd',
        601 => 'French Connexion SARL dba Domaine.fr',
        602 => 'LCN.COM Ltd.',
        603 => 'Inic GmbH',
        604 => 'In2net Network, Inc.',
        605 => 'rockenstein AG',
        606 => 'Namezero, LLC',
        607 => 'Annulet LLC',
        608 => 'EnetRegistry, Inc.',
        609 => 'NameKing.com Inc.',
        610 => 'Server-Service GmbH',
        611 => 'Inter China Network Software (Beijing) Co., Ltd. (aka 3721)',
        612 => 'Blue Razor Domains, LLC',
        613 => 'Unassigned',
        614 => 'ESoftwiz, Inc.',
        615 => 'Vivid Domains, Inc.',
        616 => 'Acropolis Telecom',
        617 => 'Epik Inc.',
        618 => 'Enetica Pty Ltd.',
        619 => 'Domainducks, LLC',
        620 => 'Fiducia LLC, Latvijas Parstavnieciba',
        621 => 'Unassigned',
        622 => 'Nameview, Inc.',
        623 => 'eNom623, Inc.',
        624 => 'eNom625, Inc.',
        625 => 'Name.com, Inc.',
        626 => 'NeoNIC OY',
        627 => 'Name Trance LLC',
        628 => 'Vedacore.com, Inc.',
        629 => 'Domainz Limited',
        630 => 'Answerable.com (I) Pvt Ltd',
        631 => 'Web.com Holding Company, Inc.',
        632 => 'Asadal, Inc.',
        633 => 'Beijing Innovative Linkage Technology Ltd. dba dns.com.cn',
        634 => 'NetTuner Corp. dba Webmasters.com',
        635 => 'eNom635, Inc.',
        636 => 'Brandon Gray Internet Services, Inc. (dba NameJuice.com)',
        637 => 'Dot Holding Inc.',
        638 => 'Nordreg AB',
        639 => 'Sipence, Inc.',
        640 => 'Mobile Name Services, Inc.',
        641 => 'H. J. Linnen Associates Ltd.',
        642 => 'Ladas Domains LLC',
        643 => 'DNS:NET Internet Service GmbH',
        644 => 'Aim High!, Inc.',
        645 => 'GMO Internet Pte. Ltd',
        646 => 'eNom646, Inc.',
        647 => 'eNom647, Inc.',
        648 => 'Webagentur.at Internet Services GmbH d/b/a domainname.at',
        649 => 'Nictrade Internet Identity Provider AB.',
        650 => 'eNom650, Inc.',
        651 => 'Total Calories, Inc. dba Slim Names',
        652 => 'eNom652, Inc.',
        653 => 'NamePal.com #8028',
        654 => 'eNom654, Inc.',
        655 => 'eNom655, Inc.',
        656 => 'eNom656, Inc.',
        657 => 'Unassigned',
        658 => 'Register Names, LLC',
        659 => 'eNom659, Inc.',
        660 => 'Vista.com, Inc.',
        661 => 'eNom661, Inc.',
        662 => 'eNom662, Inc.',
        663 => 'eNom663, Inc.',
        664 => 'Web4Africa Inc',
        665 => 'iRegistry Corp.',
        666 => 'eNom666, Inc.',
        667 => 'Name Share, Inc.',
        668 => 'Lead Networks Domains Pvt. Ltd.',
        669 => 'ResellerSRS Inc dba ResellerSRS.com',
        670 => '$$$ Private Label Internet Service Kiosk, Inc. dba PLISK.co',
        671 => 'eBrandSecure, LLC',
        672 => 'eNom672, Inc.',
        673 => 'NJ Tech Solutions Inc. dba Expertsrs.com',
        674 => 'CVO.ca Inc.',
        675 => 'Super Registry Ltd',
        676 => 'ExtremeDomains.ca Inc.',
        677 => 'NetRegistry Pty Ltd.',
        678 => 'Ace of Domains, Inc.',
        679 => 'Compana LLC',
        680 => 'SearchName.ca Internet Services Corporation',
        681 => 'DomainPlaza.ca Inc.',
        682 => 'NamePal.com #8008',
        683 => 'WorldNames.ca Inc.',
        684 => 'Domainscape.ca Inc.',
        685 => 'Domainscostless.com Inc.',
        686 => 'PriceDomain.ca Internet Services Corporation',
        687 => 'GoName-WA.com, Inc.',
        688 => 'PrimeDomain.ca Inc.',
        689 => 'Domains2be.com Inc.',
        690 => 'GotNames.ca Inc.',
        691 => 'DomainMarketPlace.ca Inc.',
        692 => 'Unassigned',
        693 => 'IPXcess.com Sdn Bhd',
        694 => 'Whoistoolbar Corp.',
        695 => '!#No1Registrar, LLC',
        696 => 'Entorno Digital, S.A.',
        697 => 'Todaynic.com Inc.',
        698 => 'Dagnabit, Incorporated',
        699 => 'Internet Internal Affairs Corporation',
        700 => 'Blisternet, Inc.',
        701 => 'Domainnovations, Inc.',
        702 => 'Dropoutlet, Incorporated',
        703 => 'Nom Infinitum, Incorporated',
        704 => 'eNombre Corporation',
        705 => 'Extra Threads Corporation',
        706 => 'Indirection Identity Corporation',
        707 => 'Fushi Tarazu, Incorporated',
        708 => 'Gunga Galunga Corporation',
        709 => 'DomainAllies.com, Inc.',
        710 => '! ! ! $0 Cost Domain and Hosting Services, Inc.',
        711 => 'DomainSystems, Inc. dba DomainsSystems.com',
        712 => 'Tahoe Domains, Inc.',
        713 => '3597245 Canada Inc. dba Nic-Name Internet Service Corp.',
        714 => '3684458 Canada Inc. dba Quark.ca Internet Services Corporation',
        715 => 'GoNames.ca Inc.',
        716 => 'DomainsFirst.ca Inc.',
        717 => 'BeMyDomain.net, Inc.',
        718 => 'DomainBuzz.ca Inc.',
        719 => 'NamePal.com #8001',
        720 => 'PopularDomains.ca Inc.',
        721 => 'LuckyDomains.ca Inc.',
        722 => 'GoName-FL.com, Inc.',
        723 => 'SecureDomain.ca Internet Services Corporation',
        724 => 'South America Domains Ltd. dba namefrog.com.',
        725 => 'NameStream.com, Inc.',
        726 => 'EntertheDomain.com, Inc.',
        727 => 'Hostmaster.ca Inc.',
        728 => 'YourDomainCo.com Inc.',
        729 => 'Regnow.ca Inc.',
        730 => 'ZippyDomains.ca Inc.',
        731 => 'Domus Enterprises LLC',
        733 => 'UsefulDomains.net Inc.',
        734 => 'NamePal.com #8004',
        735 => 'Rebel.ca Corp.',
        736 => 'Romel Corporation',
        737 => 'Matchnames.ca Inc.',
        738 => 'DomainMall.ca Inc.',
        739 => 'DomainAuthority.ca Inc.',
        740 => 'GoName-HI.com, Inc.',
        741 => 'Abdomainations.ca Inc.',
        742 => 'DomainStreet.ca Inc.',
        743 => 'NamePal.com #8002',
        744 => 'Crazy8Domains.com Inc.',
        745 => 'Domains2Go.ca Inc.',
        746 => 'MyNameOnline.ca Inc',
        747 => 'Intersolved-WA.com Inc.',
        748 => 'NamePal.com #8023',
        749 => 'DomainCentral.ca Inc.',
        750 => 'Nerd Names Corporation',
        751 => 'SicherRegister. Incorporated',
        752 => 'Mark Barker, Incorporated',
        753 => 'Name Thread Corporation',
        754 => 'Sssasss, Incorporated',
        755 => 'Name Nelly Corporation',
        756 => '2003300 Ontario Inc. dba GetDomainsIWant.ca Internet Services Corp.',
        757 => '3349608 Canada Inc. dba GetYourDotInfo.com Inc.',
        758 => '6230644 Canada Inc. dba Megabyte.ca Internet Services Corp.',
        759 => 'AvailableDomains.ca Inc.',
        760 => 'Intersolved-TX.com, Inc.',
        761 => 'Coolhosting.ca Inc.',
        762 => 'NamePal.com #8024',
        763 => 'NamePal.com #8025',
        764 => 'Domainestic.com Inc.',
        765 => 'Domainfighter.ca Inc.',
        766 => 'Intersolved-TN.com, Inc.',
        767 => 'DomainHeadz.ca Inc.',
        768 => 'DomainIdeas.ca Inc.',
        769 => 'Domainlink.ca Inc.',
        770 => 'DomainLuminary.ca Inc.',
        771 => 'NamePal.com #8026',
        772 => 'MyManager, Inc.',
        773 => 'DomainParadise.ca Inc.',
        774 => 'Domainreign.ca Inc.',
        775 => 'Domains4u.ca Inc.',
        776 => 'NamePal.com #8003',
        777 => 'NamePal.com #8005',
        778 => 'NamePal.com #8022',
        779 => 'DomainVentures.ca Internet Services Corporation',
        780 => 'NamePal.com #8006',
        781 => 'NamePal.com #8007',
        782 => 'NamePal.com #8021',
        783 => 'Grabton.ca Inc.',
        784 => 'Hipsearch.com Inc.',
        785 => 'NamePal.com #8009',
        786 => 'Maindomain.ca Inc.',
        787 => 'GoName-TN.com, Inc.',
        788 => 'NamePal.com #8020',
        789 => 'Notablenames.ca Inc.',
        790 => 'Premierename.ca Inc.',
        791 => 'PrimeRegistrar.ca Inc.',
        792 => 'NamePal.com #8019',
        793 => 'Redomainder Internet Services Corporation',
        794 => 'RegisterMyDomains.ca Inc.',
        795 => 'Registerone.ca Inc.',
        796 => 'ScoopDomain.ca Inc.',
        797 => 'Securadomain.ca Inc.',
        798 => 'Submit.ca Inc.',
        799 => 'TheDomainNameStore.ca Inc.',
        800 => 'TheDomainShop.ca Inc.',
        801 => 'WeRegisterIt.ca Inc.',
        802 => 'WhatsYourName.ca Inc.',
        803 => 'Wisdomain.ca Inc.',
        804 => 'Zidodomain.ca Inc.',
        805 => 'Domainiac.ca Inc.',
        806 => 'Unassigned',
        807 => 'Simply Named Inc. dba SimplyNamed.com',
        808 => 'Registrar Company, Inc.',
        809 => 'Ledl.net GmbH',
        810 => 'About Domain Dot Com Solutions Pvt. Ltd. d/b/a www.aboutdomainsolutions.com',
        811 => 'Atlas Advanced Internet Solutions Ltd. dba Atlas Internet',
        812 => 'CoolHandle Hosting, LLC',
        813 => 'Basic Fusion, Inc.',
        814 => 'Internet.bs Corp.',
        815 => 'Planet Online Corp.',
        816 => '0101 Internet, Inc.',
        817 => 'MAFF Inc.',
        818 => 'Interdominios, Inc.',
        819 => 'Reg2C.com Inc.',
        820 => 'ELB Group Inc.',
        821 => 'RegisterFly.com, Inc.',
        822 => 'Registrar Label, Inc.',
        823 => 'Internet Service Registrar, Inc.',
        824 => 'Unassigned',
        825 => 'BP Holdings Group, Inc. dba IS.COM',
        826 => 'Name.net, Inc.',
        827 => 'Mouzz Interactive, Inc.',
        828 => 'Hetzner Online GmbH',
        829 => 'Anytime Sites, Inc.',
        830 => 'IPNIC, Inc.',
        831 => 'Crisp Names, Inc.',
        832 => 'EstDomains, Inc.',
        833 => 'Dotted Ventures, Inc.',
        834 => 'Domain Jingles, Inc.',
        835 => 'KuwaitNET General Trading Co.',
        836 => 'Bottle Domains, Inc.',
        837 => 'Freeparking Domain Registrars, Inc.',
        838 => 'BatDomains.com Ltd.',
        839 => 'Realtime Register B.V.',
        840 => 'Nicco Ltd.',
        841 => 'Tiger Technologies LLC',
        842 => 'SoftLayer Technologies, Inc.',
        843 => 'Incuborn Solutions Inc.',
        844 => 'Minds and Machines Registrar UK Limited',
        845 => '1800-website, LLC',
        846 => '123domainrenewals, LLC',
        847 => 'Hostlane, Inc.',
        848 => 'PrivacyPost, Inc.',
        849 => 'Allindomains, LLC',
        850 => 'Allaccessdomains, LLC',
        851 => 'Addressontheweb, LLC',
        852 => 'Atozdomainsmarket, LLC',
        853 => 'Austriadomains, LLC',
        854 => '995discountdomains, LLC',
        855 => '24x7domains, LLC',
        856 => '1st-for-domain-names, LLC',
        857 => 'Capitoldomains, LLC',
        858 => 'Chinesedomains, LLC',
        859 => 'Cocoislandsdomains, LLC',
        860 => 'Belgiumdomains, LLC',
        861 => 'Bidfordomainnames, LLC',
        862 => 'Capitaldomains, LLC',
        863 => 'Deutchdomains, LLC',
        864 => 'Domaincamping, LLC',
        865 => 'Domaindoorman, LLC',
        866 => 'Domainhostingweb, LLC',
        867 => 'Domaininternetname, LLC',
        868 => 'Domainnamebidder, LLC',
        869 => 'Domainnamelookup, LLC',
        870 => 'Niuedomains, LLC',
        871 => 'Samoandomains, LLC',
        872 => 'Tuvaludomains, LLC',
        873 => 'Unitedkingdomdomains, LLC',
        874 => 'Chocolatecovereddomains, LLC',
        875 => 'Claimeddomains, LLC',
        876 => 'Department-of-domains, LLC',
        877 => 'Decentdomains, LLC',
        878 => 'Columbiadomains, LLC',
        879 => 'Domainbusinessnames, LLC',
        880 => 'Domainclub.com, LLC',
        881 => 'Domainbulkregistration, LLC',
        882 => 'Domain-A-Go-Go, LLC',
        883 => 'Discountdomainservices, LLC',
        884 => 'Diggitydot, LLC',
        885 => 'Austriandomains, LLC',
        886 => 'Domain.com, LLC',
        887 => 'Netdorm, Inc. dba DnsExit.com',
        888 => 'Pheenix, Inc.',
        889 => 'Domainclip Domains, Inc.',
        890 => 'IP Mirror Pte Ltd dba IP MIRROR',
        891 => 'Iron Mountain Intellectual Property Management, Inc.',
        892 => 'Netfirms, Inc.',
        893 => 'NetraCorp LLC dba Global Internet',
        894 => 'Domain Jamboree, LLC',
        895 => 'Google, Inc.',
        896 => 'Aruba SpA',
        897 => '21Company, Inc. dba 21-domain.com',
        898 => 'Alantron Bilisim Ltd Sti.',
        899 => 'Naugus Limited LLC',
        900 => 'TPP Wholesale Pty Ltd.',
        901 => 'AirNames.com Inc.',
        902 => 'Arab Internet Names, Incorporated',
        903 => 'AsiaDomains, Incorporated',
        904 => 'AvidDomains.com Inc.',
        905 => 'CodyCorp.com Inc.',
        906 => 'CSIRegistry.com Inc.',
        907 => 'DNSvillage.com, Inc.',
        908 => 'DomainHip.com Inc.',
        909 => 'DynaNames.com Inc.',
        910 => 'Entertainment Names, Incorporated',
        911 => 'BrandNames.com SARL',
        912 => 'Kingdomains, Incorporated',
        913 => 'PocketDomain.com Inc.',
        914 => 'PostalDomains, Incorporated',
        915 => 'Private Domains, Incorporated',
        916 => 'RallyDomains.com Inc.',
        917 => 'SBSNames, Incorporated',
        918 => 'Small Business Names and Certs, Incorporated',
        919 => 'Traffic Names, Incorporated',
        920 => 'TravelDomains, Incorporated',
        921 => 'Whiteglove Domains, Incorporated',
        922 => 'Afterdark Domains, Incorporated',
        923 => 'One Putt, Inc.',
        924 => 'Ynot Domains Corp.',
        925 => 'Everyones Internet, Ltd. dba SoftLayer',
        926 => 'Reseller Services, Inc., dba ResellServ.com',
        927 => 'Nomer Registro de Dominio e Hospedagem de sites Ltda DBA Nomer.com.br',
        928 => 'Hostway Services, Inc.',
        929 => 'AfterGen, Inc. dba JumpingDot',
        930 => 'Zipa, L.L.C.',
        931 => 'UdomainName.com LLC',
        932 => 'FindUAName.com LLC',
        933 => 'YouDamain.com LLC',
        934 => 'GoServeYourDomain.com LLC',
        935 => 'Commerce Island, Inc.',
        936 => 'Ground Internet, Inc.',
        937 => 'Blue Fractal, Inc.',
        938 => 'Sibername Internet and Software Technologies Inc.',
        939 => 'Desert Devil, Inc.',
        940 => 'Above.com Pty Ltd.',
        941 => 'Dynamic Dolphin, Inc.',
        942 => 'Autica Domain Services Inc.',
        943 => 'DotSpeedy LLC dba dotspeedy.com',
        944 => 'IServeYourDomain.com LLC',
        945 => 'Udamain.com LLC',
        946 => 'FindYouADomain.com LLC',
        947 => 'FindYouAName.com LLC',
        948 => 'Kontent GmbH',
        949 => 'Verza Domain Depot BV',
        950 => 'A Rite Tern, LLC',
        951 => 'Humeia Corporation',
        952 => 'SaveMoreNames.com Inc.',
        953 => 'Nanjing Imperiosus Technology Co. Ltd.',
        954 => 'INDOM SAS',
        955 => 'Launchpad, Inc.',
        956 => 'Hosting365 Inc.',
        957 => 'Titanic Hosting, Inc.',
        958 => 'Virtual Registrar, Inc.',
        959 => 'Tropic Management Systems, Inc.',
        960 => 'WebZero, Inc.',
        961 => 'Rank USA, Inc.',
        962 => 'Red Register, Inc.',
        963 => 'Nom d\'un Net ! Sarl',
        964 => 'Unassigned',
        965 => 'Domain Central Australia Pty Ltd.',
        966 => 'Web Business, LLC',
        967 => '!  #1 Host Australia, Inc.',
        968 => '!  #1 Host Germany, Inc.',
        969 => '!  #1 Host Brazil, Inc.',
        970 => '!  #1 Host China, Inc.',
        971 => '!  #1 Host Canada, Inc.',
        972 => 'TPP Domains Pty Ltd. dba TPP Internet',
        973 => 'Haveaname, LLC',
        974 => 'Netestate, LLC',
        975 => 'Topsystem, LLC',
        976 => 'http.net Internet GmbH',
        977 => 'Broadspire Inc.',
        978 => '!  #1 Host Israel, Inc.',
        979 => '!  #1 Host United Kingdom, Inc.',
        980 => '!  #1 Host Japan, Inc.',
        981 => '!  #1 Host Korea, Inc.',
        982 => '!  #1 Host Kuwait, Inc.',
        983 => '!  #1 Host Malaysia, Inc.',
        984 => 'ID Genesis, LLC',
        985 => 'Own Identity, Inc.',
        986 => 'Mighty Bay, Inc.',
        987 => 'Imperial Registrations, Inc.',
        988 => 'R.B. Data Net LTD.',
        989 => 'Tarton Domain Names Ltd.',
        990 => 'The Black Cow Corp.',
        991 => 'Jaz Domain Names Ltd.',
        992 => 'MojoNIC, L.L.C. dba MojoNIC.com',
        993 => 'CareerBuilder, LLC dba CareerBuilder.com',
        994 => '$ PPC Marketing LLC',
        995 => 'Europe Domains LLC',
        996 => 'DomainAdministration.com, LLC',
        997 => 'NamePal.com, LLC',
        998 => 'Tzolkin Corporation dba: TZO.COM',
        999 => 'Mobiline USA dba domainbonus.com',
        1000 => '******nondotcom, Inc.',
        1001 => 'Domeneshop AS dba  domainnameshop.com',
        1002 => 'Maxim Internet, Inc.',
        1003 => 'Ekados, Inc., d/b/a groundregistry.com',
        1004 => 'Netlynx Inc.',
        1005 => 'NetEarth One Inc. d/b/a NetEarth',
        1006 => 'Az.pl, Inc.',
        1007 => 'Net 4 India Limited',
        1008 => 'eNom1008, Inc.',
        1009 => 'eNom1009, Inc.',
        1010 => 'eNom1010, Inc.',
        1011 => '101domain, Inc.',
        1012 => 'eNom1012, Inc.',
        1013 => 'eNom1013, Inc.',
        1014 => 'eNom1014, Inc.',
        1015 => 'MOBILE.CO DOMAINS CORP.',
        1016 => 'Gee Whiz Domains, Inc.',
        1017 => 'Black Ice Domains, Inc.',
        1018 => 'Backslap Domains, Inc.',
        1019 => 'Threadagent.com, Inc.',
        1020 => 'Threadwalker.com, Inc.',
        1021 => 'Threadwatch.com, Inc.',
        1022 => 'NamePal.com #8010',
        1023 => 'NamePal.com #8011',
        1024 => 'NamePal.com #8012',
        1025 => 'NamePal.com #8013',
        1026 => 'NamePal.com #8014',
        1027 => 'NamePal.com #8015',
        1028 => 'NamePal.com #8016',
        1029 => 'NamePal.com #8017',
        1030 => 'Threadwise.com, Inc.',
        1031 => 'NamePal.com #8018',
        1032 => 'DNGLOBE LLC',
        1033 => 'eNom1033, Inc.',
        1034 => 'eNom1034, Inc.',
        1035 => 'eNom1035, Inc.',
        1036 => 'eNom1036, Inc.',
        1037 => 'eNom1037, Inc.',
        1038 => 'eNom1038, Inc.',
        1039 => 'Cheapies.com Inc.',
        1040 => 'Dynamic Network Services, Inc.',
        1041 => 'Good Luck Internet Services PVT, LTD.',
        1042 => 'Big House Services, Inc.',
        1043 => 'Domain Rouge, Inc.',
        1044 => 'Enom Corporate, Inc.',
        1045 => 'Enom GMP Services, Inc.',
        1046 => 'Enom World, Inc.',
        1047 => 'Enom1, Inc.',
        1048 => 'Enom2, Inc.',
        1049 => 'Enom3, Inc.',
        1050 => 'Enom4, Inc.',
        1051 => 'Enom5, Inc.',
        1052 => 'EuroDNS S.A.',
        1053 => 'EnomX, Inc.',
        1054 => 'Retail Domains, Inc.',
        1055 => 'Searchnresq, Inc.',
        1056 => 'Fenominal, Inc.',
        1057 => 'Enoma1, Inc.',
        1058 => 'EnomTen, Inc.',
        1059 => 'EnomToo, Inc.',
        1060 => 'EnomV, Inc.',
        1061 => 'EnomAte, Inc.',
        1062 => 'eNomsky, Inc.',
        1063 => 'EnomMx, Inc.',
        1064 => 'Enomnz, Inc.',
        1065 => 'EnomAU, Inc.',
        1066 => 'EnomEU, Inc.',
        1067 => 'Enomfor, Inc.',
        1068 => 'NameCheap, Inc.',
        1069 => 'DropExtra.com, Inc.',
        1070 => 'DropFall.com, Inc.',
        1071 => 'DropHub.com, Inc.',
        1072 => 'DropJump.com, Inc.',
        1073 => 'DropLabel.com, Inc.',
        1074 => 'DropLimited.com, Inc.',
        1075 => 'DropSave.com, Inc.',
        1076 => 'Domain Guardians, Inc.',
        1077 => 'DropWalk.com, Inc.',
        1078 => 'DropWeek.com, Inc.',
        1079 => 'Internet Solutions (Pty) Ltd.',
        1080 => 'Locaweb Servicos de Internet S/A dba Locaweb',
        1081 => 'Bargin Register, Inc.',
        1082 => 'Register4Less, Inc.',
        1083 => 'Curious Net, Inc.',
        1084 => 'AsiaRegister, Inc.',
        1085 => 'Click Registrar, Inc. d/b/a publicdomainregistry.com',
        1086 => 'Marcaria.com International, Inc.',
        1087 => 'MOOZOOY MEDIA INC.',
        1088 => 'Globe Hosting, Inc.',
        1089 => 'Blue Gravity Communications, Inc.',
        1090 => 'Active Registrar, Inc.',
        1091 => 'IHS Telekom, Inc.',
        1092 => 'Best Bulk Register, Inc.',
        1093 => 'Cool Ocean, Inc.',
        1094 => 'HooYoo (US) Inc.',
        1095 => 'European NIC Inc.',
        1096 => 'Find Good Domains, Inc.',
        1097 => 'Nettica Domains, Inc.',
        1098 => 'Domain Mantra, Inc.',
        1099 => 'Domain Band, Inc.',
        1100 => 'Net Juggler, Inc.',
        1101 => 'Power Carrier, Inc.',
        1102 => 'Network Savior, Inc.',
        1103 => 'Name For Name, Inc.',
        1104 => 'Name To Fame, Inc.',
        1105 => 'Unpower, Inc.',
        1106 => 'Unified Servers, Inc.',
        1107 => 'Tech Tyrants, Inc.',
        1108 => 'Ultra Registrar, Inc.',
        1109 => 'Trade Starter, Inc.',
        1110 => 'FBS Inc.',
        1111 => 'DomainContext, Inc.',
        1112 => 'Internet Invest, Ltd. dba Imena.ua',
        1113 => 'Instinct Solutions, Inc.',
        1114 => 'Media Elite Holdings Limited',
        1115 => 'Visual Monster, Inc.',
        1116 => 'Domerati, Inc.',
        1117 => 'Platinum Registrar, Inc.',
        1118 => 'Crystal Coal, Inc.',
        1119 => 'Extremely Wild',
        1120 => 'Game For Names, Inc.',
        1121 => 'Go Full House, Inc.',
        1122 => 'Key Registrar, Inc.',
        1123 => 'Magic Friday, Inc.',
        1124 => 'Need Servers, Inc.',
        1125 => 'Name Perfections, Inc.',
        1126 => 'Yellow Start, Inc.',
        1127 => 'Zone Casting, Inc.',
        1128 => 'Power Namers, Inc.',
        1129 => 'Extend Names, Inc.',
        1130 => 'Ever Ready Names, Inc.',
        1131 => 'Experian Services Corp.',
        1132 => 'Dotname Korea Corp.',
        1133 => 'The Names Registration, Inc.',
        1134 => 'General Names, Inc.',
        1135 => 'Best Site Names, Inc.',
        1136 => 'Specific Name, Inc.',
        1137 => 'Naming Associate, Inc.',
        1138 => 'Names Real, Inc.',
        1139 => 'Names Bond, Inc.',
        1140 => 'Global Names Online, Inc.',
        1141 => 'Get Real Names, Inc.',
        1142 => 'Genuine Names, Inc.',
        1143 => 'Your Domain King, Inc.',
        1144 => 'The Registrar Service, Inc.',
        1145 => 'Big Domain Shop, Inc.',
        1146 => 'Western United Domains, Inc.',
        1147 => 'Super Name World, Inc.',
        1148 => 'Jumbo Name, Inc.',
        1149 => 'Go China Domains, LLC',
        1150 => 'Go Canada Domains, LLC',
        1151 => 'Go Australia Domains, LLC',
        1152 => 'Go Montenegro Domains, LLC',
        1153 => 'Go France Domains, LLC',
        1154 => 'FastDomain Inc.',
        1155 => 'Power Brand Center Corp.',
        1156 => 'Identify.com Web Services LLC',
        1157 => 'AtlanticFriendNames.com LLC',
        1158 => 'Adomainofyourown.com LLC',
        1159 => 'Allearthdomains.com LLC',
        1160 => 'Atomicdomainnames.com LLC',
        1161 => 'Baronofdomains.com LLC',
        1162 => 'Beartrapdomains.com LLC',
        1163 => 'Belmontdomains.com LLC',
        1164 => 'Betterthanaveragedomains.com LLC',
        1165 => 'Biglizarddomains.com LLC',
        1166 => 'BullRunDomains.com LLC',
        1167 => 'Allworldnames.com LLC',
        1168 => 'Burnsidedomains.com LLC',
        1169 => 'Columbianames.com LLC',
        1170 => 'Compuglobalhypermega.com LLC',
        1171 => 'Deschutesdomains.com LLC',
        1172 => 'Domainamania.com LLC',
        1173 => 'Domainarmada.com LLC',
        1174 => 'DomainCannon.com LLC',
        1175 => 'Domaincapitan.com LLC',
        1176 => 'Domaincomesaround.com LLC',
        1177 => 'Domaingazelle.com LLC',
        1178 => 'Domainhawks.net LLC',
        1179 => 'Domainhysteria.com LLC',
        1180 => 'Domaininthebasket.com LLC',
        1181 => 'Domaininthehole.com LLC',
        1182 => 'Domainjungle.net LLC',
        1183 => 'DomainParkBlock.com LLC',
        1184 => 'Domainraker.net LLC',
        1185 => 'Domainroyale.com LLC',
        1186 => 'DomainSails.net LLC',
        1187 => 'Domainsalsa.com LLC',
        1188 => 'Domainsareforever.net LLC',
        1189 => 'Domainsinthebag.com LLC',
        1190 => 'Domainsofcourse.com LLC',
        1191 => 'Domainsoftheday.net LLC',
        1192 => 'Domainsoftheworld.net LLC',
        1193 => 'Domainsofvalue.com LLC',
        1194 => 'Domainsouffle.com LLC',
        1195 => 'Domainsoverboard.com LLC',
        1196 => 'Domainsovereigns.com LLC',
        1197 => 'DomainSprouts.com LLC',
        1198 => 'Domainstreetdirect.com LLC',
        1199 => 'Domainsurgeon.com LLC',
        1200 => 'Domaintimemachine.com LLC',
        1201 => 'Domainyeti.com LLC',
        1202 => 'DuckBilledDomains.com LLC',
        1203 => 'EUNameFlood.com LLC',
        1204 => 'EunamesOregon.com LLC',
        1205 => 'EuropeanConnectiononline.com LLC',
        1206 => 'EurotrashNames.com LLC',
        1207 => 'EUTurbo.com LLC',
        1208 => 'Flancrestdomains.com LLC',
        1209 => 'Freshbreweddomains.com LLC',
        1210 => 'FrontStreetDomains.com LLC',
        1211 => 'Godomaingo.com LLC',
        1212 => 'Gozerdomains.com LLC',
        1213 => 'Gradeadomainnames.com LLC',
        1214 => 'Heavydomains.net LLC',
        1215 => 'Imminentdomains.net LLC',
        1216 => 'Interlakenames.com LLC',
        1217 => 'Mypreciousdomain.com LLC',
        1218 => 'Namearsenal.com LLC',
        1219 => 'Namecroc.com LLC',
        1220 => 'Nameemperor.com LLC',
        1221 => 'Namefinger.com LLC',
        1222 => 'NotSoFamousNames.com LLC',
        1223 => 'Octopusdomains.net LLC',
        1224 => 'OldTownDomains.com LLC',
        1225 => 'OldWorldAliases.com LLC',
        1226 => 'OregonEU.com LLC',
        1227 => 'OregonURLs.com LLC',
        1228 => 'PDXPrivateNames.com LLC',
        1229 => 'PearlNamingService.com LLC',
        1230 => 'PortlandNames.com LLC',
        1231 => 'Protondomains.com LLC',
        1232 => 'Skykomishdomains.com LLC',
        1233 => 'ThirdFloorDNS.com LLC',
        1234 => 'WillametteNames.com LLC',
        1235 => 'ZigZagNames.com LLC',
        1236 => 'iCrossing, Inc.',
        1237 => 'Sundance Group, Inc.',
        1238 => 'OOO Russian Registrar',
        1239 => 'CPS-Datensysteme GmbH',
        1240 => 'Digirati Informatica Servicos e Telecomunicacoes LTDA dba Hostnet.com',
        1241 => 'Alfena, LLC',
        1242 => 'Ignitela, LLC',
        1243 => 'yenkos, LLC',
        1244 => 'Intersolved-HI.com, Inc.',
        1245 => 'WhiteCowDomains.com Inc.',
        1246 => 'Dontaskwhy.ca Inc.',
        1247 => 'Intersolved-FL.com, Inc.',
        1248 => 'GoName-TX.com, Inc.',
        1249 => 'Dotalliance Inc.',
        1250 => 'Trunkoz Technologies Pvt Ltd. d/b/a OwnRegistrar.com',
        1251 => 'Nameshield SAS',
        1252 => 'OPENNAME LLC',
        1253 => 'NICREG LLC',
        1254 => 'NEUDOMAIN LLC',
        1255 => 'MISTERNIC LLC',
        1256 => 'INSTANTNAMES LLC',
        1257 => 'Variomedia AG dba puredomain.com',
        1258 => 'Namehouse, Inc.',
        1259 => 'SBNames Ltd.',
        1260 => 'ISPREG LTD',
        1261 => 'ABSYSTEMS INC dba yournamemonkey.com',
        1262 => 'Dinahosting s.l.',
        1263 => 'enom371, Incorporated',
        1264 => 'enom373, Incorporated',
        1265 => 'enom375, Incorporated',
        1266 => 'enom377, Incorporated',
        1267 => 'enom381, Incorporated',
        1268 => 'enom383, Incorporated',
        1269 => 'enom385, Incorporated',
        1270 => 'enom387, Incorporated',
        1271 => 'enom389, Incorporated',
        1272 => 'enom391, Incorporated',
        1273 => 'enom393, Incorporated',
        1274 => 'enom395, Incorporated',
        1275 => 'enom397, Incorporated',
        1276 => 'enom399, Incorporated',
        1277 => 'enom403, Incorporated',
        1278 => 'enom405, Incorporated',
        1279 => 'enom407, Incorporated',
        1280 => 'enom411, Incorporated',
        1281 => 'enom431, Incorporated',
        1282 => 'enom433, Incorporated',
        1283 => 'enom435, Incorporated',
        1284 => 'enom437, Incorporated',
        1285 => 'enom439, Incorporated',
        1286 => 'enom441, Incorporated',
        1287 => 'enom449, Incorporated',
        1288 => 'enom451, Incorporated',
        1289 => 'enom453, Incorporated',
        1290 => 'Mailclub SAS',
        1291 => 'Crazy Domains FZ-LLC',
        1292 => 'enom419, Incorporated',
        1293 => 'enom427, Incorporated',
        1294 => 'enom425, Incorporated',
        1295 => 'enom379, Incorporated',
        1296 => 'enom445, Incorporated',
        1297 => 'enom459, Incorporated',
        1298 => 'Corporation Service Company (DBS) Inc.',
        1299 => 'enom465.com, Incorporated',
        1300 => 'enom455, Incorporated',
        1301 => 'enom443, Incorporated',
        1302 => 'enom409, Incorporated',
        1303 => 'enom461, Incorporated',
        1304 => 'enom413, Incorporated',
        1305 => 'enom421, Incorporated',
        1306 => 'enom463, Incorporated',
        1307 => 'enom423, Incorporated',
        1308 => 'enom429, Incorporated',
        1309 => 'enom415, Incorporated',
        1310 => 'enom417, Incorporated',
        1311 => 'enom469, Incorporated',
        1312 => 'enom447, Incorporated',
        1313 => 'enom467, Incorporated',
        1314 => 'enom457, Incorporated',
        1315 => 'USA Intra Corp.',
        1316 => '35 Technology Co., Ltd.',
        1317 => 'documentdata Anstalt',
        1318 => 'Kaunas University of Technology, Information Technology Development Institute dba Domreg.lt',
        1319 => 'Mister Name SARL',
        1320 => 'NGI SpA',
        1321 => 'ATXDOMAINS Inc.',
        1322 => 'GPDOMAINS Inc.',
        1323 => 'IDNDOMAINS Inc.',
        1324 => 'TLDOMAINS Inc.',
        1325 => 'VentureDomains, Inc.',
        1326 => 'Webair Internet Development, Inc.',
        1327 => 'Vitalwerks Internet Solutions, LLC DBA No-IP',
        1328 => 'RegistryGate GmbH',
        1329 => 'Intermedia.NET, Inc.',
        1330 => 'Microsoft Corporation',
        1331 => 'eName Technology Co., Ltd.',
        1332 => 'Experinom Inc.',
        1333 => 'Samjung Data Service Co., Ltd.',
        1334 => '#1 Internet Services International, Inc. dba 1ISI',
        1335 => 'Volusion, Inc.',
        1336 => 'Net-Chinese Co., Ltd.',
        1337 => 'Web Werks India Pvt. Ltd d/b/a ZenRegistry.com',
        1338 => 'UltraRPM, Inc. dba metapredict.com',
        1339 => 'M. G. Infocom Pvt. Ltd. dba MindGenies',
        1340 => 'Arctic Names, Inc.',
        1341 => 'Hawthornedomains.com LLC',
        1342 => 'Namevolcano.com LLC',
        1343 => 'Namesalacarte.com LLC',
        1344 => 'Namepanther.com LLC',
        1345 => 'Key-Systems, LLC',
        1346 => 'Sitefrenzy.com LLC',
        1347 => 'Silverbackdomains.com LLC',
        1348 => 'Savethename.com LLC',
        1349 => 'Santiamdomains.com LLC',
        1350 => 'Sammamishdomains.com LLC',
        1351 => 'Rainydaydomains.com LLC',
        1352 => 'GateKeeperDomains.net LLC',
        1353 => 'Soyouwantadomain.com LLC',
        1354 => 'Snoqulamiedomains.com LLC',
        1355 => 'Snappyregistrar.com LLC',
        1356 => 'Mvpdomainnames.com LLC',
        1357 => 'Microbreweddomains.com LLC',
        1358 => 'Masterofmydomains.net LLC',
        1359 => 'Lakeodomains.com LLC',
        1360 => 'Klaatudomains.com LLC',
        1361 => 'IBI.Net, Inc.',
        1362 => 'Regtime Ltd.',
        1363 => 'FarStar Domains, Inc.',
        1364 => 'Kheweul.com SA',
        1365 => 'Open System Ltda - Me',
        1366 => 'Xiamen ChinaSource Internet Service Co., Ltd.',
        1367 => 'Paknic (Private) Limited',
        1368 => '1 Domain Source Ltd. dba Domain One Source, Inc.',
        1369 => 'Discount Domains Ltd.',
        1370 => 'Internet Viennaweb Service GmbH',
        1371 => 'AB NameISP',
        1372 => 'Sedo.com LLC',
        1373 => 'DotArai Co., Ltd.',
        1374 => 'Standard Names, LLC',
        1375 => 'Register.ca Inc.',
        1376 => 'Instra Corporation Pty Ltd.',
        1377 => 'Alibaba (China) Technology Co., Ltd.',
        1378 => 'Hosteur SARL',
        1379 => 'Service Development Center of the State Commission Office for Public Sector Reform',
        1380 => 'Oi Internet S/A',
        1381 => 'AFRIREGISTER S.A.',
        1382 => 'Add2Net Inc.',
        1383 => 'Soluciones Corporativas IP, SLU',
        1384 => 'DevStart, Inc.',
        1385 => 'Relevad Corporation',
        1386 => 'Premium Registrations Sweden AB',
        1387 => '1API GmbH',
        1388 => 'Dattatec.com SRL',
        1389 => 'Universo Online S/A (UOL)',
        1390 => 'Mesh Digital Limited',
        1391 => 'Azdomainz LLC',
        1392 => 'Azprivatez LLC',
        1393 => 'New Great Domains, Inc.',
        1394 => 'Names In Motion, Inc.',
        1395 => 'www.com',
        1396 => 'Abansys & Hostytec S.L.',
        1397 => 'HooYoo Information Technology Company Ltd.',
        1398 => 'Net Enforcers, Inc.',
        1399 => 'Clertech.com Inc.',
        1400 => 'Ordipat',
        1401 => 'Domainfactory GmbH',
        1402 => 'Hu Yi Global Information Resources (Holding) Company',
        1403 => '10dencehispahard, S.L.',
        1404 => 'Web Site Source, Inc.',
        1405 => 'Internet NAYANA Inc.',
        1406 => 'Thought Convergence, Inc.',
        1407 => 'SW Hosting & Communications Technologies SL dba Serveisweb',
        1408 => 'united-domains AG',
        1409 => 'Verelink, Inc.',
        1410 => 'Alisoft (Shanghai) Co., Ltd.',
        1411 => 'DomainName Highway LLC',
        1412 => 'China Springboard, Inc.',
        1413 => 'Blueweb, Inc.',
        1414 => 'Desto! Inc.',
        1415 => 'Hosting Art, B.V.',
        1416 => 'Minds and Machines LLC',
        1417 => 'Guangzhou Ming Yang Information Technology Co., Ltd.',
        1418 => 'EvoPlus Ltd.',
        1419 => 'Bharti Airtel Services Limited',
        1420 => 'InterNetworX Ltd. & Co. KG',
        1421 => 'Lime Labs LLC',
        1422 => 'Deviation, LLC, d/b/a Domoden',
        1423 => 'Uber Australia E1 Pty Ltd',
        1424 => 'Interplanet, S.A. De C.V.',
        1425 => 'Baidu.Com, Inc.',
        1426 => 'CJSC Registrar R01',
        1427 => 'Zog Media, Inc. DBA Zog Names',
        1428 => 'Homestead Limited dba Namevault.com',
        1429 => 'Hebei Guoji Maoyi (Shanghai) LTD dba HebeiDomains.com',
        1430 => 'PURENIC JAPAN Inc.',
        1431 => 'GLOBIX Kft.',
        1432 => 'Alpine Domains Inc.',
        1433 => 'Digitrad France SAS',
        1434 => 'Brights Consulting Inc.',
        1435 => 'AB RIKTAD',
        1436 => 'Center of Ukrainian Internet Names dba UKRNAMES',
        1437 => 'Sync Intertainment S.L.',
        1438 => 'Beijing RITT - Net Technology Development Co., Ltd.',
        1439 => 'Porting Access B.V.',
        1440 => 'NetClient AS',
        1441 => 'TurnCommerce, Inc. DBA NameBright.com',
        1442 => 'Internet Networks S.A. De C.V.',
        1443 => 'Vautron Rechenzentrum AG',
        1444 => 'TWT S.p.A.',
        1445 => 'VocalSpace, LLC dba DesktopDomainer.com',
        1446 => 'Larsen Data ApS',
        1447 => 'World Biz Domains, LLC',
        1448 => 'Blacknight Internet Solutions Ltd.',
        1449 => 'URL Solutions, Inc.',
        1450 => 'Domain Services Rotterdam BV',
        1451 => 'iWelt AG',
        1452 => 'Interweb Advertising D.B.A. Profile Builder',
        1453 => 'Directi Web Services Pvt. Ltd.',
        1454 => 'Nics Telekomunikasyon Ticaret Ltd. Sti.',
        1455 => 'Mijndomein.nl BV',
        1456 => 'NetArt Registrar Sp. z o.o.',
        1457 => 'Times Internet Limited',
        1458 => 'Telefonica Brasil S.A.',
        1459 => 'Domainmonster.com, Inc.',
        1460 => 'Server Plan Srl',
        1461 => 'Asusa Corporation',
        1462 => 'One.com A/S',
        1463 => 'Global Domains International, Inc. DBA DomainCostClub.com',
        1464 => 'NameWeb BVBA',
        1465 => 'Hang Zhou E-Business Services Co., Ltd',
        1466 => 'Lexsynergy Limited',
        1467 => 'Register NV dba Register.eu',
        1468 => 'Virtucom Networks S.A.',
        1469 => 'Jiangsu Bangning Science and technology Co. Ltd.',
        1470 => 'Shanghai Yovole Networks, Inc.',
        1471 => 'Astutium Limited',
        1472 => 'LiquidNet Ltd.',
        1473 => 'Jungbonet Co., Ltd',
        1474 => 'Wixi Incorporated',
        1475 => 'April Sea Information Technology Corporation',
        1476 => 'World4You Internet Services GmbH',
        1477 => 'Name108, Inc.',
        1478 => 'CV. Jogjacamp',
        1479 => 'Namesilo, LLC',
        1480 => 'The Registrar Company B.V.',
        1481 => 'Hu Yi Global Information Hong Kong Limited',
        1482 => 'SARL VIADUC',
        1483 => 'Neubox Internet S.A. de C.V.',
        1484 => 'Infocom Network Ltd.',
        1485 => 'Japan Registry Services Co., Ltd.',
        1486 => 'IT Boost Corp.',
        1487 => 'IndiaLinks Web Hosting Pvt Ltd.',
        1488 => 'Demys Limited',
        1489 => 'Megazone Corp., dba HOSTING.KR',
        1490 => 'dm3 Digital Media Marketing and Monitoring FZ-LLC',
        1491 => 'Koreacenter.com co., Ltd.',
        1492 => 'Neen Srl',
        1493 => 'Ilait AB',
        1494 => 'Beijing Guoxu Network Technology Co., Ltd.',
        1495 => 'BigRock Solutions Ltd.',
        1496 => 'DomainRegi, LLC',
        1497 => 'ELSERVER SRL',
        1498 => 'NetBulk NV',
        1499 => 'Ghana Dot Com Ltd.',
        1500 => 'Tirupati Domains And Hosting Pvt. Ltd.',
        1501 => 'DotRoll Kft.',
        1502 => 'Gabia C&S',
        1503 => 'PT Ardh Global Indonesia',
        1504 => 'camPoint AG',
        1505 => 'Gransy s.r.o. d/b/a subreg.cz',
        1506 => 'Gesloten Domain N.V.',
        1507 => 'RIDE Co., Ltd.',
        1508 => 'TOGLODO S.A.',
        1509 => 'Cosmotown, Inc.',
        1510 => 'Name118, Inc.',
        1511 => 'Name113, Inc.',
        1512 => 'Name112, Inc.',
        1513 => 'Name104, Inc.',
        1514 => 'Name111, Inc.',
        1515 => 'Webfusion Ltd.',
        1516 => 'Guangzhou Ehost Tech. Co. Ltd.',
        1517 => 'HOAPDI, Inc.',
        1518 => 'Shanghai Best Oray Information S&T Co., Ltd',
        1519 => 'NETIM SARL',
        1520 => 'Adknowledge, Inc.',
        1521 => 'Yexa.com Pty Ltd.',
        1522 => 'home.pl S.A.',
        1523 => 'Tong Ji Ming Lian (Beijing) Technology Corporation Ltd.',
        1524 => 'Networking4all B.V.',
        1525 => 'Guangdong JinWanBang Technology Investment Co., Ltd.',
        1526 => 'Hogan Lovells International LLP',
        1527 => 'DOMAIN NAME NETWORK PTY LTD',
        1528 => 'Groupe MIT SARL',
        1529 => 'DomainLocal LLC',
        1530 => 'Pacific Online Inc.',
        1531 => 'Automattic Inc.',
        1532 => 'Kinx Co., Ltd.',
        1533 => 'Good Domain Registry Pvt Ltd.',
        1534 => 'Aerotek Bilisim Taahut Sanayi Ve Ticaret Ltd Sti.',
        1535 => 'TheNameCo LLC',
        1536 => 'BoteroSolutions.com S.A.',
        1537 => 'NameJolt.com LLC',
        1538 => 'NameTell.com LLC',
        1539 => 'Nameling.com LLC',
        1540 => 'Domainwards.com LLC',
        1541 => 'DomainPrime.com LLC',
        1542 => 'Korea Server Hosting Inc.',
        1543 => 'Name110, Inc.',
        1544 => 'Name114, Inc.',
        1545 => 'Name115, Inc.',
        1546 => 'Name116, Inc.',
        1547 => 'Name117, Inc.',
        1548 => 'Name119, Inc.',
        1549 => 'Name120, Inc.',
        1550 => 'Name109, Inc.',
        1551 => 'Name107, Inc.',
        1552 => 'Name106, Inc.',
        1553 => 'Small World Communications, Inc.',
        1554 => 'DomainSnap, LLC',
        1555 => 'Hangzhou AiMing Network Co., LTD',
        1556 => 'Chengdu West Dimension Digital Technology Co., Ltd.',
        1557 => 'Netowl, Inc.',
        1558 => 'SiliconHouse.Net Pvt. Ltd.',
        1559 => 'Dynadot2 LLC',
        1560 => 'Genious Communications SARL/AU',
        1561 => 'Purity Names Incorporated',
        1562 => 'Badger Inc.',
        1563 => 'Foshan YiDong Network Co., LTD',
        1564 => 'TLD Registrar Solutions Ltd.',
        1565 => 'DreamScape Networks FZ-LLC',
        1566 => 'NameSector LLC',
        1567 => 'NameSay LLC',
        1568 => 'DomainFalcon LLC',
        1569 => 'DomainHood LLC',
        1570 => 'DomainExtreme LLC',
        1571 => 'WorthyDomains LLC',
        1572 => 'GlamDomains LLC',
        1573 => 'NameStrategies LLC',
        1574 => 'DotNamed LLC',
        1575 => 'ZoomRegistrar LLC',
        1576 => 'DomainDelights LLC',
        1577 => 'NameForward LLC',
        1578 => 'TradeNamed LLC',
        1579 => 'ProNamed LLC',
        1580 => 'NameBrew LLC',
        1581 => 'Binero AB',
        1582 => 'Tecnologia, Desarrollo Y Mercado, S. de R.L de C.V.',
        1583 => 'Web Drive Ltd',
        1584 => 'Tsukaerunet Co., Ltd.',
        1586 => 'Mat Bao Trading & Service Company Limited d/b/a Mat Bao',
        1587 => 'Mijn InternetOplossing B.V.',
        1588 => 'Beijing Sanfront Information Technology Co., Ltd',
        1589 => 'XYZ.COM LLC',
        1590 => 'ChinaNet Technology (SuZhou) CO., LTD',
        1591 => 'Promo People inc.',
        1593 => 'Powered by Domain.com LLC',
        1594 => 'Anessia Inc.',
        1595 => 'DanCue Inc.',
        1596 => 'BraveNames Inc.',
        1597 => 'GreenZoneDomains Inc.',
        1598 => 'EastNames Inc.',
        1599 => 'Alibaba Cloud Computing Ltd. d/b/a HiChina (www.net.cn)',
        1600 => 'Estrategias WebSite S.L.',
        1601 => 'Atak Domain Hosting Internet ve Bilgi Teknolojileri Limited Sirketi d/b/a Atak Teknoloji',
        1603 => 'TransIP B.V.',
        1604 => 'DanDomains A/S',
        1605 => 'Chengdu Fly-Digital Technology Co., Ltd',
        1606 => 'Limited Liability Company "Registrar of domain names REG.RU"',
        1607 => 'CCI REG S.A.',
        1608 => 'Beijing Tong Guan Xin Tian Technology Ltd (Novaltel)',
        1609 => 'Synergy Wholesale Pty Ltd',
        1610 => 'NamesHere LLC',
        1611 => 'DomainGetter LLC',
        1612 => 'DomainCritics LLC',
        1613 => 'AccentDomains LLC',
        1614 => 'DomainAhead LLC',
        1615 => 'VisualNames LLC',
        1616 => 'NameTurn LLC',
        1617 => 'PresidentialDomains LLC',
        1618 => 'DomainTact LLC',
        1619 => 'GuangDong NaiSiNiKe Information Technology Co Ltd.',
        1620 => 'EJEE Group Holdings Limited',
        1621 => 'Shanghai Meicheng Technology Information Co., Ltd',
        1622 => 'Swedish Domains AB',
        1623 => 'Registrar Manager, Inc.',
        1624 => 'Shanghai Oweb Network Co., Ltd',
        1625 => 'LEMARIT Domain Management GmbH',
        1626 => 'Domainbox Limited',
        1627 => 'Domainmonster Limited',
        1628 => 'ZNet Technologies Pvt Ltd.',
        1629 => 'Hangzhou Duomai E-Commerce Co., Ltd',
        1630 => 'Ligne Web Services SARL',
        1631 => 'Fujian Litian Network Technology Co., Ltd',
        1632 => 'Century Oriental International Co., Ltd.',
        1633 => 'NamePal.com #8027',
        1634 => 'Web IP Pty Ltd',
        1635 => 'Beijing Midwest Taian Technology Services Ltd.',
        1636 => 'Hostinger, UAB',
        1637 => 'Dynadot0 LLC',
        1638 => 'Dynadot1 LLC',
        1639 => 'eBrand Services S.A.',
        1640 => 'Beijing Wangzun Technology Co., Ltd',
        1641 => 'Brennercom Limited',
        1642 => 'EmpireStateDomains Inc.',
        1643 => 'NorthNames Inc',
        1644 => 'SouthNames Inc',
        1645 => 'DiaMatrix C.C.',
        1646 => 'Vigson Inc',
        1647 => 'Hosting Concepts B.V. dba Openprovider',
        1649 => 'P.A. Viet Nam Company Limited',
        1651 => 'Dynadot3 LLC',
        1652 => 'Dynadot4 LLC',
        1653 => 'Dynadot5 LLC',
        1654 => 'Ourdomains Limited',
        1655 => 'Xiamen Nawang Technology Co., Ltd',
        1656 => 'Kagoya Japan Inc.',
        1657 => 'WHT Co., Ltd',
        1658 => 'Rethem Hosting LLC',
        1659 => 'Uniregistrar Corp',
        1660 => 'Domainshype.com, Inc.',
        1661 => 'Domdrill.com, Inc.',
        1662 => 'Enset Registrar, Inc.',
        1663 => 'Hotdomaintrade.com, Inc.',
        1664 => 'Namware.com, Inc.',
        1665 => 'Vertex names.com, Inc.',
        1666 => 'OpenTLD B.V.',
        1667 => 'Seymour Domains, LLC',
        1668 => 'EastEndDomains, LLC',
        1669 => 'InlandDomains, LLC',
        1670 => 'AtlanticDomains, LLC',
        1671 => 'MidWestDomains, LLC',
        1672 => 'PacificDomains, LLC',
        1673 => 'BDL Systemes SAS dba ProDomaines',
        1674 => 'Domainia Inc.',
        1675 => 'CV. Rumahweb Indonesia',
        1676 => 'Net Logistics Pty. Ltd.',
        1677 => 'AcquiredNames LLC',
        1678 => 'BlastDomains LLC',
        1679 => 'BlockHost LLC',
        1680 => 'ComfyDomains LLC',
        1681 => 'DomainCraze LLC',
        1682 => 'DomainCreek LLC',
        1683 => 'DomainLadder LLC',
        1684 => 'DomainPicking LLC',
        1685 => 'EchoDomain LLC',
        1686 => 'InsaneNames LLC',
        1687 => 'LiteDomains LLC',
        1688 => 'NameBake LLC',
        1689 => 'NameChild LLC',
        1690 => 'NoticedDomains LLC',
        1691 => 'ReclaimDomains LLC',
        1692 => 'RegistrarDirect LLC',
        1693 => 'TotallyDomain LLC',
        1694 => 'WhatIsYourDomain LLC',
        1695 => 'AvidDomain LLC',
        1696 => 'HOSTPOINT AG',
        1697 => 'DNSPod, Inc.',
        1698 => 'GoName.com, Inc.',
        1699 => 'Hostserver GmbH',
        1700 => 'ingenit GmbH & Co. KG',
        1701 => 'DOMAINOO SAS',
        1702 => 'Alexander the Great, LLC',
        1703 => 'Cyrus the Great, LLC',
        1704 => 'Julius Caesar, LLC',
        1705 => 'Network Information Center Mexico, S.C.',
        1708 => 'Nominet Registrar Services Limited',
        1710 => 'Nhan Hoa Software Company Ltd',
        1712 => 'Number One Web Hosting Limited',
        1714 => 'Only Domains Limited',
        1715 => 'DevilDogDomains.com, LLC',
        1716 => 'EU Technology (HK) Limited',
        1717 => 'Netzadresse.at Domain Service GmbH',
        1718 => 'Dynadot6 LLC',
        1719 => 'Dynadot7 LLC',
        1720 => 'Dynadot8 LLC',
        1721 => 'JPRS Registrar Co., Ltd',
        1722 => 'Tianjin Zhuiri Science and Technology Development Co. Ltd',
        1723 => 'Internet Domain Name System Beijing Engineering Research Center LLC (ZDNS)',
        1724 => 'Stork Registry Inc.',
        1725 => 'Global Village GmbH',
        1726 => 'Taka Enterprise Ltd',
        1727 => 'Papaki Ltd.',
        1728 => 'IP Twins SAS',
        1729 => 'Beijing ZhongWan Network Technology Co Ltd',
        1730 => 'Aetrion LLC dba DNSimple',
        1731 => 'TLD Registrar Pty Ltd',
        1732 => 'Hostnet bv',
        1733 => 'Beijing Zihai Technology Co., Ltd',
        1734 => 'Shenzhen Hu Lian Xian Feng Technology CO., Ltd.',
        1735 => 'Emerald Registrar Limited',
        1736 => 'Emerald Global Registrar Services Limited',
        1737 => 'JarheadDomains.com LLC',
        1738 => 'Emirates Telecommunications Corporation - Etisalat',
        1739 => 'Hangzhou Dianshang Internet Technology Co., Ltd',
        1740 => 'Henan Weichuang Network Technology Co. Ltd',
        1741 => 'Shinjiru MSC Sdn Bhd',
        1742 => 'Zhengzhou Zitian Network Technology Co., Ltd',
        1743 => 'Aahwed, Inc.',
        1744 => 'Domain Vault Limited',
        1745 => 'LogicBoxes Naming Services Ltd.',
        1746 => 'REG.BG OOD',
        1747 => 'PANASIA INFORMATION LIMITED',
        1748 => 'Registrar Services, LLC',
        1749 => 'Upperlink Limited',
        1750 => 'Authentic Web Inc.',
        1751 => 'SQUIDSAILERDOMAINS.COM, LLC',
        1752 => 'Salenames Ltd',
        1753 => 'Domain Shield Pty Ltd',
        1754 => 'Shenzhen Esin Technology Co., Ltd',
        1755 => 'Netistrar Limited',
        1756 => 'DropCatch.com 345 LLC',
        1757 => 'DropCatch.com 346 LLC',
        1758 => 'DropCatch.com 347 LLC',
        1759 => 'DropCatch.com 348 LLC',
        1760 => 'DropCatch.com 349 LLC',
        1761 => 'DropCatch.com 350 LLC',
        1762 => 'DropCatch.com 351 LLC',
        1763 => 'DropCatch.com 352 LLC',
        1764 => 'DropCatch.com 353 LLC',
        1765 => 'DropCatch.com 354 LLC',
        1766 => 'DropCatch.com 355 LLC',
        1767 => 'DropCatch.com 356 LLC',
        1768 => 'DropCatch.com 357 LLC',
        1769 => 'DropCatch.com 358 LLC',
        1770 => 'DropCatch.com 359 LLC',
        1771 => 'DropCatch.com 360 LLC',
        1772 => 'DropCatch.com 361 LLC',
        1773 => 'DropCatch.com 362 LLC',
        1774 => 'DropCatch.com 363 LLC',
        1775 => 'DropCatch.com 364 LLC',
        1776 => 'DropCatch.com 365 LLC',
        1777 => 'DropCatch.com 366 LLC',
        1778 => 'DropCatch.com 367 LLC',
        1779 => 'DropCatch.com 368 LLC',
        1780 => 'DropCatch.com 369 LLC',
        1781 => 'DropCatch.com 370 LLC',
        1782 => 'DropCatch.com 371 LLC',
        1783 => 'DropCatch.com 372 LLC',
        1784 => 'DropCatch.com 373 LLC',
        1785 => 'DropCatch.com 374 LLC',
        1786 => 'DropCatch.com 375 LLC',
        1787 => 'DropCatch.com 376 LLC',
        1788 => 'DropCatch.com 377 LLC',
        1789 => 'DropCatch.com 378 LLC',
        1790 => 'DropCatch.com 379 LLC',
        1791 => 'DropCatch.com 380 LLC',
        1792 => 'DropCatch.com 381 LLC',
        1793 => 'DropCatch.com 382 LLC',
        1794 => 'DropCatch.com 383 LLC',
        1795 => 'DropCatch.com 384 LLC',
        1796 => 'DropCatch.com 385 LLC',
        1797 => 'DropCatch.com 386 LLC',
        1798 => 'DropCatch.com 387 LLC',
        1799 => 'DropCatch.com 388 LLC',
        1800 => 'DropCatch.com 389 LLC',
        1801 => 'DropCatch.com 390 LLC',
        1802 => 'DropCatch.com 391 LLC',
        1803 => 'DropCatch.com 392 LLC',
        1804 => 'DropCatch.com 393 LLC',
        1805 => 'DropCatch.com 394 LLC',
        1806 => 'DropCatch.com 395 LLC',
        1807 => 'DropCatch.com 396 LLC',
        1808 => 'DropCatch.com 397 LLC',
        1809 => 'DropCatch.com 398 LLC',
        1810 => 'DropCatch.com 399 LLC',
        1811 => 'DropCatch.com 400 LLC',
        1812 => 'DropCatch.com 401 LLC',
        1813 => 'DropCatch.com 402 LLC',
        1814 => 'DropCatch.com 403 LLC',
        1815 => 'DropCatch.com 404 LLC',
        1816 => 'DropCatch.com 405 LLC',
        1817 => 'DropCatch.com 406 LLC',
        1818 => 'DropCatch.com 407 LLC',
        1819 => 'DropCatch.com 408 LLC',
        1820 => 'DropCatch.com 409 LLC',
        1821 => 'DropCatch.com 410 LLC',
        1822 => 'DropCatch.com 411 LLC',
        1823 => 'DropCatch.com 412 LLC',
        1824 => 'DropCatch.com 413 LLC',
        1825 => 'DropCatch.com 414 LLC',
        1826 => 'DropCatch.com 415 LLC',
        1827 => 'DropCatch.com 416 LLC',
        1828 => 'DropCatch.com 417 LLC',
        1829 => 'DropCatch.com 418 LLC',
        1830 => 'DropCatch.com 419 LLC',
        1831 => 'DropCatch.com 420 LLC',
        1832 => 'DropCatch.com 421 LLC',
        1833 => 'DropCatch.com 422 LLC',
        1834 => 'DropCatch.com 423 LLC',
        1835 => 'DropCatch.com 424 LLC',
        1836 => 'DropCatch.com 425 LLC',
        1837 => 'DropCatch.com 426 LLC',
        1838 => 'DropCatch.com 427 LLC',
        1839 => 'DropCatch.com 428 LLC',
        1840 => 'DropCatch.com 429 LLC',
        1841 => 'DropCatch.com 430 LLC',
        1842 => 'DropCatch.com 431 LLC',
        1843 => 'DropCatch.com 432 LLC',
        1844 => 'DropCatch.com 433 LLC',
        1845 => 'DropCatch.com 434 LLC',
        1846 => 'DropCatch.com 435 LLC',
        1847 => 'DropCatch.com 436 LLC',
        1848 => 'DropCatch.com 437 LLC',
        1849 => 'DropCatch.com 438 LLC',
        1850 => 'DropCatch.com 439 LLC',
        1851 => 'DropCatch.com 440 LLC',
        1852 => 'DropCatch.com 441 LLC',
        1853 => 'DropCatch.com 442 LLC',
        1854 => 'DropCatch.com 443 LLC',
        1855 => 'DropCatch.com 444 LLC',
        1856 => 'DropCatch.com 445 LLC',
        1857 => 'Alpnames Limited',
        1858 => 'NameCentral, Inc.',
        1859 => 'Namemaster RC GmbH',
        1860 => 'Paragon Internet Group Ltd t/a Paragon Names',
        1861 => 'Porkbun, LLC',
        1862 => 'Onlide Inc.',
        1863 => 'Dotmedia Limited',
        1864 => 'Dynadot9 LLC',
        1865 => 'Dynadot10 LLC',
        1866 => 'Dynadot11 LLC',
        1867 => 'Dynadot12 LLC',
        1868 => 'Eranet International Limited',
        1870 => 'Domainname Blvd, Inc',
        1871 => 'Domainname Fwy, Inc',
        1872 => 'Flappy Domain, Inc',
        1873 => 'MAFF Avenue, Inc',
        1874 => 'Versio BV',
        1875 => 'Intracom Middle East FZE',
        1876 => 'NCC Group Secure Registrar, Inc.',
        1877 => 'Attila the Hun, LLC',
        1878 => 'Charlemagne 888, LLC',
        1879 => 'Douglas MacArthur, LLC',
        1880 => 'Dwight D. Eisenhower, LLC',
        1881 => 'Genghis Khan, LLC',
        1882 => 'George S. Patton, LLC',
        1883 => 'George Washington 888, LLC',
        1884 => 'Hannibal Barca, LLC',
        1885 => 'Isoroku Yamamoto, LLC',
        1886 => 'Karl Von Clausewitz, LLC',
        1887 => 'Napoleon Bonaparte, LLC',
        1888 => 'Robert E. Lee 888, LLC',
        1889 => 'Scipio Africanus, LLC',
        1890 => 'Sun Tzu 888, LLC',
        1891 => 'Ulysses S. Grant, LLC',
        1892 => 'Vo Nguyen Giap, LLC',
        1893 => 'William the Conqueror, LLC',
        1895 => 'Namespro Solutions Inc.',
        1896 => 'ATI',
        1897 => 'Taiwan Network Information Center',
        1898 => 'BR domain Inc. dba namegear.co',
        1899 => 'CyanDomains, Inc.',
        1900 => 'DomainName Bridge, Inc.',
        1901 => 'DomainName Route, Inc.',
        1902 => 'HazelDomains, Inc.',
        1903 => 'KQW, Inc.',
        1904 => 'Xiamen Dianmei Network Technology Co., Ltd.',
        1905 => 'Xiamen Domains, Inc.',
        1907 => 'DomainName Path, Inc.',
        1908 => 'BRS, LLC',
        1909 => 'Webnames Limited',
        1910 => 'CloudFlare, Inc.',
        1911 => 'NUXIT',
        1912 => 'Vodien Internet Solutions Pte Ltd',
        1913 => 'DOTSERVE INC.',
        1914 => 'Beijing Zhuoyue Shengming Technologies Company Ltd.',
        1915 => 'West263 International Limited',
        1916 => 'Shenzhen Internet Works Online Co., Ltd.',
        1917 => 'MainReg Inc.',
        1919 => 'DomainName Driveway, Inc.',
        1920 => 'DomainName Parkway, Inc.',
        1921 => 'Fujian Domains, Inc.',
        1922 => 'Guangzhou Domains, Inc.',
        1923 => 'Beijing Lanhai Jiye Technology Co., Ltd',
        1924 => 'Hello Internet Corp.',
        1925 => 'Guangdong HUYI Internet & IP Services Co., Ltd.',
        1926 => 'DropCatch.com 446 LLC',
        1927 => 'DropCatch.com 447 LLC',
        1928 => 'DropCatch.com 448 LLC',
        1929 => 'DropCatch.com 449 LLC',
        1930 => 'DropCatch.com 450 LLC',
        1931 => 'DropCatch.com 451 LLC',
        1932 => 'DropCatch.com 452 LLC',
        1933 => 'DropCatch.com 453 LLC',
        1934 => 'DropCatch.com 454 LLC',
        1935 => 'DropCatch.com 455 LLC',
        1936 => 'DropCatch.com 456 LLC',
        1937 => 'DropCatch.com 457 LLC',
        1938 => 'DropCatch.com 458 LLC',
        1939 => 'DropCatch.com 459 LLC',
        1940 => 'DropCatch.com 460 LLC',
        1941 => 'DropCatch.com 461 LLC',
        1942 => 'DropCatch.com 462 LLC',
        1943 => 'DropCatch.com 463 LLC',
        1944 => 'DropCatch.com 464 LLC',
        1945 => 'DropCatch.com 465 LLC',
        1946 => 'DropCatch.com 466 LLC',
        1947 => 'DropCatch.com 467 LLC',
        1948 => 'DropCatch.com 468 LLC',
        1949 => 'DropCatch.com 469 LLC',
        1950 => 'DropCatch.com 470 LLC',
        1951 => 'DropCatch.com 471 LLC',
        1952 => 'DropCatch.com 472 LLC',
        1953 => 'DropCatch.com 473 LLC',
        1954 => 'DropCatch.com 474 LLC',
        1955 => 'DropCatch.com 475 LLC',
        1956 => 'DropCatch.com 476 LLC',
        1957 => 'DropCatch.com 477 LLC',
        1958 => 'DropCatch.com 478 LLC',
        1959 => 'DropCatch.com 479 LLC',
        1960 => 'DropCatch.com 480 LLC',
        1961 => 'DropCatch.com 481 LLC',
        1962 => 'DropCatch.com 482 LLC',
        1963 => 'DropCatch.com 483 LLC',
        1964 => 'DropCatch.com 484 LLC',
        1965 => 'DropCatch.com 485 LLC',
        1966 => 'DropCatch.com 486 LLC',
        1967 => 'DropCatch.com 487 LLC',
        1968 => 'DropCatch.com 488 LLC',
        1969 => 'DropCatch.com 489 LLC',
        1970 => 'DropCatch.com 490 LLC',
        1971 => 'DropCatch.com 491 LLC',
        1972 => 'DropCatch.com 492 LLC',
        1973 => 'DropCatch.com 493 LLC',
        1974 => 'DropCatch.com 494 LLC',
        1975 => 'DropCatch.com 495 LLC',
        1976 => 'DropCatch.com 496 LLC',
        1977 => 'DropCatch.com 497 LLC',
        1978 => 'DropCatch.com 498 LLC',
        1979 => 'DropCatch.com 499 LLC',
        1980 => 'DropCatch.com 500 LLC',
        1981 => 'DropCatch.com 501 LLC',
        1982 => 'DropCatch.com 502 LLC',
        1983 => 'DropCatch.com 503 LLC',
        1984 => 'DropCatch.com 504 LLC',
        1985 => 'DropCatch.com 505 LLC',
        1986 => 'DropCatch.com 506 LLC',
        1987 => 'DropCatch.com 507 LLC',
        1988 => 'DropCatch.com 508 LLC',
        1989 => 'DropCatch.com 509 LLC',
        1990 => 'DropCatch.com 510 LLC',
        1991 => 'DropCatch.com 511 LLC',
        1992 => 'DropCatch.com 512 LLC',
        1993 => 'DropCatch.com 513 LLC',
        1994 => 'DropCatch.com 514 LLC',
        1995 => 'DropCatch.com 515 LLC',
        1996 => 'DropCatch.com 516 LLC',
        1997 => 'DropCatch.com 517 LLC',
        1998 => 'DropCatch.com 518 LLC',
        1999 => 'DropCatch.com 519 LLC',
        2000 => 'DropCatch.com 520 LLC',
        2001 => 'DropCatch.com 521 LLC',
        2002 => 'DropCatch.com 522 LLC',
        2003 => 'DropCatch.com 523 LLC',
        2004 => 'DropCatch.com 524 LLC',
        2005 => 'DropCatch.com 525 LLC',
        2006 => 'DropCatch.com 526 LLC',
        2007 => 'DropCatch.com 527 LLC',
        2008 => 'DropCatch.com 528 LLC',
        2009 => 'DropCatch.com 529 LLC',
        2010 => 'DropCatch.com 530 LLC',
        2011 => 'DropCatch.com 531 LLC',
        2012 => 'DropCatch.com 532 LLC',
        2013 => 'DropCatch.com 533 LLC',
        2014 => 'DropCatch.com 534 LLC',
        2015 => 'DropCatch.com 535 LLC',
        2016 => 'DropCatch.com 536 LLC',
        2017 => 'DropCatch.com 537 LLC',
        2018 => 'DropCatch.com 538 LLC',
        2019 => 'DropCatch.com 539 LLC',
        2020 => 'DropCatch.com 540 LLC',
        2021 => 'DropCatch.com 541 LLC',
        2022 => 'DropCatch.com 542 LLC',
        2023 => 'DropCatch.com 543 LLC',
        2024 => 'DropCatch.com 544 LLC',
        2025 => 'DropCatch.com 545 LLC',
        2026 => 'DropCatch.com 546 LLC',
        2027 => 'DropCatch.com 547 LLC',
        2028 => 'DropCatch.com 548 LLC',
        2029 => 'DropCatch.com 549 LLC',
        2030 => 'DropCatch.com 550 LLC',
        2031 => 'DropCatch.com 551 LLC',
        2032 => 'DropCatch.com 552 LLC',
        2033 => 'DropCatch.com 553 LLC',
        2034 => 'DropCatch.com 554 LLC',
        2035 => 'DropCatch.com 555 LLC',
        2036 => 'DropCatch.com 556 LLC',
        2037 => 'DropCatch.com 557 LLC',
        2038 => 'DropCatch.com 558 LLC',
        2039 => 'DropCatch.com 559 LLC',
        2040 => 'DropCatch.com 560 LLC',
        2041 => 'DropCatch.com 561 LLC',
        2042 => 'DropCatch.com 562 LLC',
        2043 => 'DropCatch.com 563 LLC',
        2044 => 'DropCatch.com 564 LLC',
        2045 => 'DropCatch.com 565 LLC',
        2046 => 'DropCatch.com 566 LLC',
        2047 => 'DropCatch.com 567 LLC',
        2048 => 'DropCatch.com 568 LLC',
        2049 => 'DropCatch.com 569 LLC',
        2050 => 'DropCatch.com 570 LLC',
        2051 => 'DropCatch.com 571 LLC',
        2052 => 'DropCatch.com 572 LLC',
        2053 => 'DropCatch.com 573 LLC',
        2054 => 'DropCatch.com 574 LLC',
        2055 => 'DropCatch.com 575 LLC',
        2056 => 'DropCatch.com 576 LLC',
        2057 => 'DropCatch.com 577 LLC',
        2058 => 'DropCatch.com 578 LLC',
        2059 => 'DropCatch.com 579 LLC',
        2060 => 'DropCatch.com 580 LLC',
        2061 => 'DropCatch.com 581 LLC',
        2062 => 'DropCatch.com 582 LLC',
        2063 => 'DropCatch.com 583 LLC',
        2064 => 'DropCatch.com 584 LLC',
        2065 => 'DropCatch.com 585 LLC',
        2066 => 'DropCatch.com 586 LLC',
        2067 => 'DropCatch.com 587 LLC',
        2068 => 'DropCatch.com 588 LLC',
        2069 => 'DropCatch.com 589 LLC',
        2070 => 'DropCatch.com 590 LLC',
        2071 => 'DropCatch.com 591 LLC',
        2072 => 'DropCatch.com 592 LLC',
        2073 => 'DropCatch.com 593 LLC',
        2074 => 'DropCatch.com 594 LLC',
        2075 => 'DropCatch.com 595 LLC',
        2076 => 'DropCatch.com 596 LLC',
        2077 => 'DropCatch.com 597 LLC',
        2078 => 'DropCatch.com 598 LLC',
        2079 => 'DropCatch.com 599 LLC',
        2080 => 'DropCatch.com 600 LLC',
        2081 => 'DropCatch.com 601 LLC',
        2082 => 'DropCatch.com 602 LLC',
        2083 => 'DropCatch.com 603 LLC',
        2084 => 'DropCatch.com 604 LLC',
        2085 => 'DropCatch.com 605 LLC',
        2086 => 'DropCatch.com 606 LLC',
        2087 => 'DropCatch.com 607 LLC',
        2088 => 'DropCatch.com 608 LLC',
        2089 => 'DropCatch.com 609 LLC',
        2090 => 'DropCatch.com 610 LLC',
        2091 => 'DropCatch.com 611 LLC',
        2092 => 'DropCatch.com 612 LLC',
        2093 => 'DropCatch.com 613 LLC',
        2094 => 'DropCatch.com 614 LLC',
        2095 => 'DropCatch.com 615 LLC',
        2096 => 'DropCatch.com 616 LLC',
        2097 => 'DropCatch.com 617 LLC',
        2098 => 'DropCatch.com 618 LLC',
        2099 => 'DropCatch.com 619 LLC',
        2100 => 'DropCatch.com 620 LLC',
        2101 => 'DropCatch.com 621 LLC',
        2102 => 'DropCatch.com 622 LLC',
        2103 => 'DropCatch.com 623 LLC',
        2104 => 'DropCatch.com 624 LLC',
        2105 => 'DropCatch.com 625 LLC',
        2106 => 'DropCatch.com 626 LLC',
        2107 => 'DropCatch.com 627 LLC',
        2108 => 'DropCatch.com 628 LLC',
        2109 => 'DropCatch.com 629 LLC',
        2110 => 'DropCatch.com 630 LLC',
        2111 => 'DropCatch.com 631 LLC',
        2112 => 'DropCatch.com 632 LLC',
        2113 => 'DropCatch.com 633 LLC',
        2114 => 'DropCatch.com 634 LLC',
        2115 => 'DropCatch.com 635 LLC',
        2116 => 'DropCatch.com 636 LLC',
        2117 => 'DropCatch.com 637 LLC',
        2118 => 'DropCatch.com 638 LLC',
        2119 => 'DropCatch.com 639 LLC',
        2120 => 'DropCatch.com 640 LLC',
        2121 => 'DropCatch.com 641 LLC',
        2122 => 'DropCatch.com 642 LLC',
        2123 => 'DropCatch.com 643 LLC',
        2124 => 'DropCatch.com 644 LLC',
        2125 => 'DropCatch.com 645 LLC',
        2126 => 'DropCatch.com 646 LLC',
        2127 => 'DropCatch.com 647 LLC',
        2128 => 'DropCatch.com 648 LLC',
        2129 => 'DropCatch.com 649 LLC',
        2130 => 'DropCatch.com 650 LLC',
        2131 => 'DropCatch.com 651 LLC',
        2132 => 'DropCatch.com 652 LLC',
        2133 => 'DropCatch.com 653 LLC',
        2134 => 'DropCatch.com 654 LLC',
        2135 => 'DropCatch.com 655 LLC',
        2136 => 'DropCatch.com 656 LLC',
        2137 => 'DropCatch.com 657 LLC',
        2138 => 'DropCatch.com 658 LLC',
        2139 => 'DropCatch.com 659 LLC',
        2140 => 'DropCatch.com 660 LLC',
        2141 => 'DropCatch.com 661 LLC',
        2142 => 'DropCatch.com 662 LLC',
        2143 => 'DropCatch.com 663 LLC',
        2144 => 'DropCatch.com 664 LLC',
        2145 => 'DropCatch.com 665 LLC',
        2146 => 'DropCatch.com 666 LLC',
        2147 => 'DropCatch.com 667 LLC',
        2148 => 'DropCatch.com 668 LLC',
        2149 => 'DropCatch.com 669 LLC',
        2150 => 'DropCatch.com 670 LLC',
        2151 => 'DropCatch.com 671 LLC',
        2152 => 'DropCatch.com 672 LLC',
        2153 => 'DropCatch.com 673 LLC',
        2154 => 'DropCatch.com 674 LLC',
        2155 => 'DropCatch.com 675 LLC',
        2156 => 'DropCatch.com 676 LLC',
        2157 => 'DropCatch.com 677 LLC',
        2158 => 'DropCatch.com 678 LLC',
        2159 => 'DropCatch.com 679 LLC',
        2160 => 'DropCatch.com 680 LLC',
        2161 => 'DropCatch.com 681 LLC',
        2162 => 'DropCatch.com 682 LLC',
        2163 => 'DropCatch.com 683 LLC',
        2164 => 'DropCatch.com 684 LLC',
        2165 => 'DropCatch.com 685 LLC',
        2166 => 'DropCatch.com 686 LLC',
        2167 => 'DropCatch.com 687 LLC',
        2168 => 'DropCatch.com 688 LLC',
        2169 => 'DropCatch.com 689 LLC',
        2170 => 'DropCatch.com 690 LLC',
        2171 => 'DropCatch.com 691 LLC',
        2172 => 'DropCatch.com 692 LLC',
        2173 => 'DropCatch.com 693 LLC',
        2174 => 'DropCatch.com 694 LLC',
        2175 => 'DropCatch.com 695 LLC',
        2176 => 'DropCatch.com 696 LLC',
        2177 => 'DropCatch.com 697 LLC',
        2178 => 'DropCatch.com 698 LLC',
        2179 => 'DropCatch.com 699 LLC',
        2180 => 'DropCatch.com 700 LLC',
        2181 => 'DropCatch.com 701 LLC',
        2182 => 'DropCatch.com 702 LLC',
        2183 => 'DropCatch.com 703 LLC',
        2184 => 'DropCatch.com 704 LLC',
        2185 => 'DropCatch.com 705 LLC',
        2186 => 'DropCatch.com 706 LLC',
        2187 => 'DropCatch.com 707 LLC',
        2188 => 'DropCatch.com 708 LLC',
        2189 => 'DropCatch.com 709 LLC',
        2190 => 'DropCatch.com 710 LLC',
        2191 => 'DropCatch.com 711 LLC',
        2192 => 'DropCatch.com 712 LLC',
        2193 => 'DropCatch.com 713 LLC',
        2194 => 'DropCatch.com 714 LLC',
        2195 => 'DropCatch.com 715 LLC',
        2196 => 'DropCatch.com 716 LLC',
        2197 => 'DropCatch.com 717 LLC',
        2198 => 'DropCatch.com 718 LLC',
        2199 => 'DropCatch.com 719 LLC',
        2200 => 'DropCatch.com 720 LLC',
        2201 => 'DropCatch.com 721 LLC',
        2202 => 'DropCatch.com 722 LLC',
        2203 => 'DropCatch.com 723 LLC',
        2204 => 'DropCatch.com 724 LLC',
        2205 => 'DropCatch.com 725 LLC',
        2206 => 'DropCatch.com 726 LLC',
        2207 => 'DropCatch.com 727 LLC',
        2208 => 'DropCatch.com 728 LLC',
        2209 => 'DropCatch.com 729 LLC',
        2210 => 'DropCatch.com 730 LLC',
        2211 => 'DropCatch.com 731 LLC',
        2212 => 'DropCatch.com 732 LLC',
        2213 => 'DropCatch.com 733 LLC',
        2214 => 'DropCatch.com 734 LLC',
        2215 => 'DropCatch.com 735 LLC',
        2216 => 'DropCatch.com 736 LLC',
        2217 => 'DropCatch.com 737 LLC',
        2218 => 'DropCatch.com 738 LLC',
        2219 => 'DropCatch.com 739 LLC',
        2220 => 'DropCatch.com 740 LLC',
        2221 => 'DropCatch.com 741 LLC',
        2222 => 'DropCatch.com 742 LLC',
        2223 => 'DropCatch.com 743 LLC',
        2224 => 'DropCatch.com 744 LLC',
        2225 => 'DropCatch.com 745 LLC',
        2226 => 'Aquarius Domains, LLC',
        2227 => 'Big Dipper Domains, LLC',
        2228 => 'Bonzai Domains, LLC',
        2229 => 'ChocolateChipDomains, LLC',
        2230 => 'ClouBreakDomains, LLC',
        2231 => 'CloudNineDomains, LLC',
        2232 => 'Cool River Names, LLC',
        2233 => 'Desert Sand Domains, LLC',
        2234 => 'DomainToOrder, LLC',
        2235 => 'EndeavourDomains, LLC',
        2236 => 'Fetch Registrar, LLC',
        2237 => 'Lionshare Domains, LLC',
        2238 => 'Lucky Elephant Domains, LLC',
        2239 => 'Magnate Domains, LLC',
        2240 => 'NamesElite, LLC',
        2241 => 'NameSourceDomains, LLC',
        2242 => 'New Order Domains, LLC',
        2243 => 'Noteworthy Domains, LLC',
        2244 => 'Painted Pony Names, LLC',
        2245 => 'Pipeline Domains, LLC',
        2246 => 'Shining Star Domains, LLC',
        2247 => 'SliceofHeaven Domains, LLC',
        2248 => 'Tradewinds Names, LLC',
        2249 => 'White Alligator Domains, LLC',
        2250 => 'WildZebraDomains, LLC',
        2251 => 'Hongkong Domain Name Information Management Co., Ltd.',
        2252 => 'Cool Breeze Domains, LLC',
        2253 => 'Domain Name Origin, LLC',
        2254 => 'Domain Name Root LLC',
        2255 => 'Easy Street Domains, LLC',
        2256 => 'Entrust Domains, LLC',
        2257 => 'Fair Trade Domains, LLC',
        2258 => 'Fine Grain Domains, LLC',
        2259 => 'Free Spirit Domains, LLC',
        2260 => 'Hangten Domains, LLC',
        2261 => 'Leatherneckdomains.com, LLC',
        2262 => 'Line Drive Domains, LLC',
        2263 => 'Magnolia Domains, LLC',
        2264 => 'Major Leaque Domains, LLC',
        2265 => 'Pararescuedomains.com, LLC',
        2266 => 'Pink Elephant Domains, LLC',
        2267 => 'Ripcord Domains, LLC',
        2268 => 'Ripcurl Domains, LLC',
        2269 => 'Riptide Domains, LLC',
        2270 => 'Soaring Eagle Domains, LLC',
        2271 => 'Soldierofonedomains.com',
        2272 => 'Sourced Domains, LLC',
        2273 => 'Steamline Domains, LLC',
        2274 => 'Sugar Cube Domains, LLC',
        2275 => 'Tiger Shark Domains, LLC',
        2276 => 'Veritas Domains, LLC',
        2277 => 'White Rhino Domains, LLC',
        2278 => 'Wild Bunch Domains, LLC',
        2279 => 'Your Domain Casa, LLC',
        2280 => 'Fan Domains., LTD',
        2281 => 'VentraIP Australia Pty Ltd',
        2282 => 'Dynadot13 LLC',
        2283 => 'Dynadot14 LLC',
        2284 => 'Dynadot15 LLC',
        2285 => 'Dynadot16 LLC',
        2286 => 'Dynadot17 LLC',
        2287 => 'Domain Name Services (Pty) Ltd',
        2289 => 'Abraham Lincoln, LLC',
        2290 => 'Achilles 888, LLC',
        2291 => 'Annam, LLC',
        2292 => 'Apollo 888, LLC',
        2293 => 'Ares 888, LLC',
        2294 => 'Aristotle 888, LLC',
        2295 => 'Arthur Pendragon, LLC',
        2296 => 'Benjamin Franklin 888, LLC',
        2297 => 'Billy the Kid, LLC',
        2298 => 'Buddha, LLC',
        2299 => 'Charles Darwin, LLC',
        2300 => 'Confucius, LLC',
        2301 => 'Constantine the Great, LLC',
        2302 => 'Dainam, LLC',
        2303 => 'Dalai Lama, LLC',
        2304 => 'Eric the Red, LLC',
        2305 => 'Erwin Rommel, LLC',
        2306 => 'Galileo Galilei, LLC',
        2307 => 'Hercules 888, LLC',
        2308 => 'Isaac Newton, LLC',
        2309 => 'James Madison, LLC',
        2310 => 'Joan of Arc, LLC',
        2311 => 'Leif Ericson, LLC',
        2312 => 'Leonardo da Vinci, LLC',
        2313 => 'Leonidas, LLC',
        2314 => 'Mahatma Gandhi, LLC',
        2315 => 'Mailinh, LLC',
        2316 => 'Odysseus 888, LLC',
        2317 => 'Omni 888, LLC',
        2318 => 'Perseus 888, LLC',
        2319 => 'Peter the Great, LLC',
        2320 => 'Plato 888, LLC',
        2321 => 'Poseidon 888, LLC',
        2322 => 'Radu Damian, LLC',
        2323 => 'Ramses II, LLC',
        2324 => 'Richard the Lionheart 888, LLC',
        2325 => 'Maximus, LLC',
        2326 => 'Sir Lancelot du Lac, LLC',
        2327 => 'Socrates 888, LLC',
        2328 => 'Spartacus, LLC',
        2329 => 'Ad Valorem Domains, LLC',
        2330 => 'Alethia Domains, LLC',
        2331 => 'Barracuda Domains, LLC',
        2332 => 'Bonam Fortunam Domains, LLC',
        2333 => 'Deep Dive Domains, LLC',
        2334 => 'Domain ala Carte, LLC',
        2335 => 'Domain Collage, LLC',
        2336 => 'Domain Esta Aqui, LLC',
        2337 => 'Domain Lifestyle, LLC',
        2338 => 'Domain Locale, LLC',
        2339 => 'Domain Original, LLC',
        2340 => 'Domaining Oro, LLC',
        2341 => 'Domains of Origin, LLC',
        2342 => 'Eagle Eye Domains, LLC',
        2343 => 'Ethos Domains, LLC',
        2344 => 'EZ Times Domains, LLC',
        2345 => 'Free Dive Domains, LLC',
        2346 => 'Glide Slope Domains, LLC',
        2347 => 'House of Domains, LLC',
        2348 => 'Lemon Shark Domains, LLC',
        2349 => 'Moon Shot Domains, LLC',
        2350 => 'Old Tyme Domains, LLC',
        2351 => 'Rally Cry Domains, LLC',
        2352 => 'Straight 8 Domains, LLC',
        2353 => 'V 12 Domains, LLC',
        2354 => 'Tan Tran, LLC',
        2355 => 'Theseus 888, LLC',
        2356 => 'Thomas Edison, LLC',
        2357 => 'Thomas Jefferson, LLC',
        2358 => 'Titus 888, LLC',
        2359 => 'Vlad the Impaler, LLC',
        2360 => 'Wild Bill Hickok, LLC',
        2361 => 'William Wallace, LLC',
        2362 => 'Winston Churchill, LLC',
        2363 => 'Zeus 888, LLC',
        2364 => 'Excalibur, LLC',
        2365 => 'Green Destiny, LLC',
        2366 => 'Heavens Will, LLC',
        2367 => 'Honjo Masamune, LLC',
        2368 => 'Hrunting, LLC',
        2369 => 'Joyeuse, LLC',
        2370 => 'La Tizone, LLC',
        2371 => 'Stormbringer, LLC',
        2372 => 'Ulfberht, LLC',
        2373 => 'Zulfigar, LLC',
        2374 => 'Hosting Ukraine LLC',
        2375 => 'Pheenix 1, LLC',
        2376 => 'Pheenix 2, LLC',
        2377 => 'Pheenix 3, LLC',
        2378 => 'Pheenix 4, LLC',
        2379 => 'Pheenix 5, LLC',
        2380 => 'Pheenix 6, LLC',
        2381 => 'Pheenix 7, LLC',
        2382 => 'Pheenix 8, LLC',
        2383 => 'Pheenix 9, LLC',
        2384 => 'Pheenix 10, LLC',
        2385 => 'Pheenix 11, LLC',
        2386 => 'Pheenix 12, LLC',
        2387 => 'Pheenix 13, LLC',
        2388 => 'Pheenix 14, LLC',
        2389 => 'Pheenix 15, LLC',
        2390 => 'Pheenix 16, LLC',
        2391 => 'Pheenix 17, LLC',
        2392 => 'Pheenix 18, LLC',
        2393 => 'Pheenix 19, LLC',
        2394 => 'Pheenix 20, LLC',
        2395 => 'Pheenix 21, LLC',
        2396 => 'Pheenix 22, LLC',
        2397 => 'Pheenix 23, LLC',
        2398 => 'Pheenix 24, LLC',
        2399 => 'Pheenix 25, LLC',
        2400 => 'Pheenix 26, LLC',
        2401 => 'Pheenix 27, LLC',
        2402 => 'Pheenix 28, LLC',
        2403 => 'Pheenix 29, LLC',
        2404 => 'Pheenix 30, LLC',
        2405 => 'Pheenix 31, LLC',
        2406 => 'Pheenix 32, LLC',
        2407 => 'Pheenix 33, LLC',
        2408 => 'Pheenix 34, LLC',
        2409 => 'Pheenix 35, LLC',
        2410 => 'Pheenix 36, LLC',
        2411 => 'Pheenix 37, LLC',
        2412 => 'Pheenix 38, LLC',
        2413 => 'Pheenix 39, LLC',
        2414 => 'Pheenix 40, LLC',
        2415 => 'Pheenix 41, LLC',
        2416 => 'Pheenix 42, LLC',
        2417 => 'Pheenix 43, LLC',
        2418 => 'Pheenix 44, LLC',
        2419 => 'Pheenix 45, LLC',
        2420 => 'Pheenix 46, LLC',
        2421 => 'Pheenix 47, LLC',
        2422 => 'Pheenix 48, LLC',
        2423 => 'Pheenix 49, LLC',
        2424 => 'Pheenix 50, LLC',
        2425 => 'Pheenix 51, LLC',
        2426 => 'Pheenix 52, LLC',
        2427 => 'Pheenix 53, LLC',
        2428 => 'Pheenix 54, LLC',
        2429 => 'Pheenix 55, LLC',
        2430 => 'Pheenix 56, LLC',
        2431 => 'Pheenix 57, LLC',
        2432 => 'Pheenix 58, LLC',
        2433 => 'Pheenix 59, LLC',
        2434 => 'Pheenix 60, LLC',
        2435 => 'Pheenix 61, LLC',
        2436 => 'Pheenix 62, LLC',
        2437 => 'Pheenix 63, LLC',
        2438 => 'Pheenix 64, LLC',
        2439 => 'Pheenix 65, LLC',
        2440 => 'Pheenix 66, LLC',
        2441 => 'Pheenix 67, LLC',
        2442 => 'Pheenix 68, LLC',
        2443 => 'Pheenix 69, LLC',
        2444 => 'Pheenix 70, LLC',
        2445 => 'Pheenix 71, LLC',
        2446 => 'Pheenix 72, LLC',
        2447 => 'Pheenix 73, LLC',
        2448 => 'Pheenix 74, LLC',
        2449 => 'Pheenix 75, LLC',
        2450 => 'Pheenix 76, LLC',
        2451 => 'Pheenix 77, LLC',
        2452 => 'Pheenix 78, LLC',
        2453 => 'Pheenix 79, LLC',
        2454 => 'Pheenix 80, LLC',
        2455 => 'Pheenix 81, LLC',
        2456 => 'Pheenix 82, LLC',
        2457 => 'Pheenix 83, LLC',
        2458 => 'Pheenix 84, LLC',
        2459 => 'Pheenix 85, LLC',
        2460 => 'Pheenix 86, LLC',
        2461 => 'Pheenix 87, LLC',
        2462 => 'Pheenix 88, LLC',
        2463 => 'Pheenix 89, LLC',
        2464 => 'Pheenix 90, LLC',
        2465 => 'Pheenix 91, LLC',
        2466 => 'Pheenix 92, LLC',
        2467 => 'Pheenix 93, LLC',
        2468 => 'Pheenix 94, LLC',
        2469 => 'Pheenix 95, LLC',
        2470 => 'Pheenix 96, LLC',
        2471 => 'Pheenix 97, LLC',
        2472 => 'Pheenix 98, LLC',
        2473 => 'Pheenix 99, LLC',
        2474 => 'Pheenix 100, LLC',
        2475 => 'Focus IP, Inc. dba AppDetex',
        2476 => 'PlanetHoster Inc.',
        2477 => 'Brandma.co Limited',
        2478 => 'Hezhong Lianchen Beijing Technology Co., Ltd',
        9995 => 'Reserved for Pre-Delegation Testing transactions #1 reporting',
        9996 => 'Reserved for Pre-Delegation Testing transactions #2 reporting',
        9997 => 'Reserved for ICANN\'s Registry SLA Monitoring System transactions reporting',
        9998 => 'Reserved for billable transactions where Registry Operator acts as Registrar',
        9999 => 'Reserved for non-billable transactions where Registry Operator acts as Registrar',
        10007 => 'Domain The Net Technologies Ltd.',
        8888888 => 'Reserved for historic use by Registry Operator acting as Registrar',
    ];

    /**
     * Constructor function
     */
    public function __construct()
    {
        // Load DATA array
        $servers = require('whois.servers.php');

        $this->DATA               = $servers['DATA'];
        $this->NON_UTF8           = $servers['NON_UTF8'];
        $this->WHOIS_PARAM        = $servers['WHOIS_PARAM'];
        $this->WHOIS_SPECIAL      = $servers['WHOIS_SPECIAL'];
        $this->WHOIS_GTLD_HANDLER = $servers['WHOIS_GTLD_HANDLER'];

        $this->codeVersion = file_get_contents(__DIR__ . '/../VERSION');
        // Set version
        $this->version = sprintf("phpWhois v%s", $this->codeVersion);
    }

    /**
     * Perform lookup
     *
     * @return array Raw response as array separated by "\n"
     */
    public function getRawData($query)
    {
        $this->query['query'] = $query;

        // clear error description
        if (isset($this->query['errstr'])) {
            $this->query['errstr'] = [];
        }

        if (!isset($this->query['server'])) {
            $this->query['status'] = 'error';
            $this->query['errstr'][] = 'No server specified';
            return [];
        }

        // Check if protocol is http
        if (
            strpos($this->query['server'], 'http://') === 0 ||
            strpos($this->query['server'], 'https://') === 0
        ) {
            $output = $this->httpQuery();

            if (!$output) {
                $this->query['status'] = 'error';
                $this->query['errstr'][] = 'Connect failed to: ' . $this->query['server'];
                return (array());
            }

            $this->query['args'] = substr(strstr($this->query['server'], '?'), 1);
            $this->query['server'] = strtok($this->query['server'], '?');

            if (strpos($this->query['server'], 'http://') === 0) {
                $this->query['server_port'] = 80;
            } else {
                $this->query['server_port'] = 443;
            }
        } else {
            // Get args
            if (strpos($this->query['server'], '?')) {
                $parts = explode('?', $this->query['server']);
                $this->query['server'] = trim($parts[0]);
                $query_args = trim($parts[1]);

                // replace substitution parameters
                $query_args = str_replace(['{query}', '{version}'], [$query, 'phpWhois' . $this->codeVersion], $query_args);

                $iptools = new IpTools();
                if (strpos($query_args, '{ip}') !== false) {
                    $query_args = str_replace('{ip}', $iptools->getClientIp(), $query_args);
                }

                if (strpos($query_args, '{hname}') !== false) {
                    $query_args = str_replace('{hname}', gethostbyaddr($iptools->getClientIp()), $query_args);
                }
            } else {
                if (empty($this->query['args'])) {
                    $query_args = $query;
                } else {
                    $query_args = $this->query['args'];
                }
            }

            $this->query['args'] = $query_args;

            if (strpos($this->query['server'], 'rwhois://') === 0) {
                $this->query['server'] = substr($this->query['server'], 9);
            }

            if (strpos($this->query['server'], 'whois://') === 0) {
                $this->query['server'] = substr($this->query['server'], 8);
            }

            // Get port
            if (strpos($this->query['server'], ':')) {
                $parts = explode(':', $this->query['server']);
                $this->query['server'] = trim($parts[0]);
                $this->query['server_port'] = trim($parts[1]);
            } else {
                $this->query['server_port'] = $this->port;
            }

            // Connect to whois server, or return if failed
            $ptr = $this->connect();

            if ($ptr === false) {
                $this->query['status'] = 'error';
                $this->query['errstr'][] = 'Connect failed to: ' . $this->query['server'];
                return array();
            }

            stream_set_timeout($ptr, $this->stimeout);
            stream_set_blocking($ptr, 0);

            // Send query
            fwrite($ptr, trim($query_args) . "\r\n");

            // Prepare to receive result
            $raw = '';
            $start = time();
            $null = null;
            $r = [
                $ptr
            ];

            while (!feof($ptr)) {
                if (!empty($r) && stream_select($r, $null, $null, $this->stimeout)) {
                    $raw .= fgets($ptr, $this->buffer);
                }

                if (time() - $start > $this->stimeout) {
                    $this->query['status'] = 'error';
                    $this->query['errstr'][] = 'Timeout reading from ' . $this->query['server'];
                    return array();
                }
            }

            if (array_key_exists($this->query['server'], $this->NON_UTF8)) {
                $raw = utf8_encode($raw);
            }

            $output = explode("\n", $raw);

            // Drop empty last line (if it's empty! - saleck)
            if (empty($output[count($output) - 1])) {
                unset($output[count($output) - 1]);
            }
        }

        return $output;
    }

    /**
     * Perform lookup
     *
     * @return array The *rawdata* element contains an
     * array of lines gathered from the whois query. If a top level domain
     * handler class was found for the domain, other elements will have been
     * populated too.
     */
    public function getData( $query='', $deep_whois=true ): array
    {
        // If domain to query passed in, use it, otherwise use domain from initialization
        $query = !empty($query) ? $query : $this->query['query'];

        $who_is_raw = $this->getRawData($query);
        $legacy_who_is_result = $this->legacyParseRawWhoIs($who_is_raw,$query);


        $who_is_data = new WhoIsData();
        // proprietario - persona fisica o azienda che ha comprato il dominio
        $propriety_info = $legacy_who_is_result['regrinfo'] ?? [];
        // registrar - con chi è stato registrato (Aruba, TopHost, ecc...)
        $registrar_info = $legacy_who_is_result['regyinfo'] ?? [];
        $domain_info = $propriety_info['domain'] ?? [];
        $registrant_info = $propriety_info['owner'] ?? [];
        $admin_info = $propriety_info['admin'] ?? [];
        $technical_info = $propriety_info['tech'] ?? [];

        $who_is_info = static::handleWhoIsText( $who_is_raw, $this->query['tld'] );

        $domain_data = static::handleDomainInfo($domain_info,$who_is_info,$propriety_info);

        $who_is_data = new WhoIsData();
        $who_is_data->setRawData($who_is_raw);
        $who_is_data->setRegistrarInfo(static::handleRegistrarInfo($registrar_info,$who_is_info));
        $who_is_data->setDomainInfo($domain_data);
        $who_is_data->setRegistrantInfo(static::handleRegistrantInfo($registrant_info,$who_is_info));
        $who_is_data->setAdminInfo(static::handleAdminInfo($admin_info,$who_is_info));
        $who_is_data->setTechnicalInfo(static::handleTechnicalInfo($technical_info,$who_is_info,$domain_data));

        // Legacy information
        $who_is_data->regrinfo = $propriety_info;
        $who_is_data->regyinfo = $registrar_info;

        // TODO: Add this?
//        'last_update' => (new DateTime('now',new DateTimeZone('UTC')))->format('c'), // 2022-09-21T09:44:43+00:00

        print_r($who_is_info);
        print_r($who_is_data);
        exit;
    }

    protected function legacyParseRawWhoIs( array $who_is_raw, string $query='' ): array
    {
        // Create result and set 'rawdata'
        $result = $this->setWhoisInfo(['rawdata' => $who_is_raw]);

        // Return now on error
        if (empty($who_is_raw)) {
            return $result;
        }

        // If we have a handler, post-process it with it
        if (isset($this->query['handler'])) {
            // Keep server list
            $servers = $result['regyinfo']['servers'];
            unset($result['regyinfo']['servers']);

            // Process data
            $result = $this->process($result);

            // Add new servers to the server list
            if (isset($result['regyinfo']['servers'])) {
                $result['regyinfo']['servers'] = array_merge($servers, $result['regyinfo']['servers']);
            } else {
                $result['regyinfo']['servers'] = $servers;
            }

            // Handler may forget to set rawdata
            if (!isset($result['rawdata'])) {
                $result['rawdata'] = $who_is_raw;
            }
        }

        // Type defaults to domain
        if (!isset($result['regyinfo']['type'])) {
            $result['regyinfo']['type'] = 'domain';
        }

        // Add error information if any
        if (isset($this->query['errstr'])) {
            $result['errstr'] = $this->query['errstr'];
        }

        // Fix/add nameserver information
        if (method_exists($this, 'fixResult') && $this->query['tld'] !== 'ip') {
            $this->fixResult($result, $query);
        }

        return $result;
    }

    /**
     * Adds whois server query information to result
     * @param $result array Result array
     * @return array Original result array with server query information
     * @deprecated
     */
    public function setWhoisInfo( array $result ): array
    {
        $info = [
            'server' => $this->query['server'],
        ];

        if (!empty($this->query['args'])) {
            $info['args'] = $this->query['args'];
        } else {
            $info['args'] = $this->query['query'];
        }

        if (!empty($this->query['server_port'])) {
            $info['port'] = $this->query['server_port'];
        } else {
            $info['port'] = 43;
        }

        unset(
            $result['regyinfo']['whois'],
            $result['regyinfo']['rwhois']
        );

        $result['regyinfo']['servers'][] = $info;

        return $result;
    }

    /**
     * Convert html output to plain text
     *
     * @return array Rawdata
     */
    public function httpQuery()
    {
        $lines = @file($this->query['server']);

        if (!$lines) {
            return false;
        }

        $output = '';
        $pre = '';

        foreach ($lines as $val) {
            $val = trim($val);

            $pos = stripos($val, '<PRE>');
            if ($pos !== false) {
                $pre = "\n";
                $output .= substr($val, 0, $pos) . "\n";
                $val = substr($val, $pos + 5);
            }
            $pos = stripos($val, '</PRE>');
            if ($pos !== false) {
                $pre = '';
                $output .= substr($val, 0, $pos) . "\n";
                $val = substr($val, $pos + 6);
            }
            $output .= $val . $pre;
        }

        $search = array(
            '<BR>', '<P>', '</TITLE>',
            '</H1>', '</H2>', '</H3>',
            '<br>', '<p>', '</title>',
            '</h1>', '</h2>', '</h3>');

        $output = str_replace($search, "\n", $output);
        $output = str_replace(['<TD','<td','<tr','<TR','&nbsp;'], [' <td',' <td', "\n<tr", "\n<tr", ' '], $output);
        $output = strip_tags($output);
        $output = explode("\n", $output);

        $rawdata = array();
        $null = 0;

        foreach ($output as $val) {
            $val = trim($val);
            if ($val == '') {
                if (++$null > 2) {
                    continue;
                }
            } else {
                $null = 0;
            }
            $rawdata[] = $val;
        }

        return $rawdata;
    }

    /**
     * Open a socket to the whois server.
     *
     * @param string|null $server Server address to connect. If null, $this->query['server'] will be used
     *
     * @return resource|false Returns a socket connection pointer on success, or -1 on failure
     */
    public function connect($server = null)
    {

        if (empty($server)) {
            $server = $this->query['server'];
        }

        /** @TODO Throw an exception here */
        if (empty($server)) {
            return false;
        }

        $port = $this->query['server_port'];

        $parsed = $this->parseServer($server);
        $server = $parsed['host'];

        if (array_key_exists('port', $parsed)) {
            $port = $parsed['port'];
        }

        // Enter connection attempt loop
        $retry = 0;

        while ($retry <= $this->retry) {
            // Set query status
            $this->query['status'] = 'ready';

            // Connect to whois port
            $ptr = @fsockopen($server, $port, $errno, $errstr, $this->stimeout);

            if ($ptr > 0) {
                $this->query['status'] = 'ok';
                return $ptr;
            }

            // Failed this attempt
            $this->query['status'] = 'error';
            $this->query['error'][] = "[$errno] $errstr";
            $retry++;

            // Sleep before retrying
            sleep($this->sleep);
        }

        // If we get this far, it hasn't worked
        return false;
    }

    /**
     * Post-process result with handler class.
     *
     * @return array On success, returns the result from the handler.
     * On failure, returns passed result unaltered.
     */
    public function process(&$result, $deep_whois = true)
    {
        $handlerName = $this->loadHandler($this->query['handler']);

        if ($handlerName === false) {
            $handlerName = $this->loadLegacyHandler($this->query['handler'], $this->query['file']);
        }

        if ($handlerName === false) {
            $this->query['errstr'][] = "Can't find {$this->query['handler']} handler: " . $this->query['file'];

            return $result;
        }

        if (!$this->gtldRecurse && $this->query['file'] === 'whois.gtld.php') {
            return $result;
        }

        // Pass result to handler
        $handler = new $handlerName('');

        // If handler returned an error, append it to the query errors list
        if (isset($handler->query['errstr'])) {
            $this->query['errstr'][] = $handler->query['errstr'];
        }

        $handler->deepWhois = $deep_whois;

        // Process and return the result
        return $handler->parse($result, $this->query['query']);
    }

    /**
     * Does more (deeper) whois
     *
     * @return array Resulting array
     */
    public function deepWhois($query, $result)
    {

        if (!isset($result['regyinfo']['whois'])) {
            return $result;
        }

        $this->query['server'] = $wserver = $result['regyinfo']['whois'];
        unset($result['regyinfo']['whois']);
        $subresult = $this->getRawData($query);

        if (!empty($subresult)) {
            $result = $this->setWhoisInfo($result);
            $result['rawdata'] = $subresult;

            if (isset($this->WHOIS_GTLD_HANDLER[$wserver])) {
                $this->query['handler'] = $this->WHOIS_GTLD_HANDLER[$wserver];
            } else {
                $parts = explode('.', $wserver);
                $hname = strtolower($parts[1]);

                if (($fp = @fopen('whois.gtld.' . $hname . '.php', 'rb', 1)) and fclose($fp)) {
                    $this->query['handler'] = $hname;
                }
            }

            if (!empty($this->query['handler'])) {
                $this->query['file'] = sprintf('whois.gtld.%s.php', $this->query['handler']);
                $regrinfo = $this->process($subresult); //$result['rawdata']);
                $result['regrinfo'] = $this->mergeResults($result['regrinfo'], $regrinfo);
            }
        }

        return $result;
    }

    /**
     * Merge results
     *
     * @param array $a1
     * @param array $a2
     * @return array
     * @deprecated
     */
    public function mergeResults($a1, $a2)
    {

        reset($a2);

        foreach ($a2 as $key => $val) {
            if (isset($a1[$key])) {
                if (is_array($val)) {
                    if ($key !== 'nserver') {
                        $a1[$key] = $this->mergeResults($a1[$key], $val);
                    }
                } else {
                    $val = trim($val);
                    if ($val !== '') {
                        $a1[$key] = $val;
                    }
                }
            } else {
                $a1[$key] = $val;
            }
        }

        return $a1;
    }

    /**
     * Remove unnecessary symbols from nameserver received from whois server
     * @param string[] $nserver List of received nameservers
     * @return string[]
     * @deprecated
     */
    public function fixNameServer($nserver)
    {
        $dns = [];

        foreach ($nserver as $val) {
            $val = str_replace( ['[', ']', '(', ')', "\t"], ['', '', '', '', ' '], trim($val));
            $parts = explode(' ', $val);
            $host = '';
            $ip = '';

            foreach ($parts as $p) {
                if (substr($p, -1) === '.') {
                    $p = substr($p, 0, -1);
                }

                if ((ip2long($p) === -1) or (ip2long($p) === false)) {
                    // Hostname ?
                    if ($host === '' && preg_match('/^[\w\-]+(\.[\w\-]+)+$/', $p)) {
                        $host = $p;
                    }
                } else {
                    // IP Address
                    $ip = $p;
                }
            }

            // Valid host name ?
            if ($host == '') {
                continue;
            }

            // Get ip address
            if ($ip == '') {
                $ip = gethostbyname($host);
                if ($ip == $host) {
                    $ip = '(DOES NOT EXIST)';
                }
            }

            if (substr($host, -1, 1) === '.') {
                $host = substr($host, 0, -1);
            }

            $dns[strtolower($host)] = $ip;
        }

        return $dns;
    }

    /**
     * Parse server string into array with host and port keys
     *
     * @param  string    $server   server string in various formattes
     * @return array    Array containing 'host' key with server host and 'port' if defined in original $server string
     */
    public function parseServer($server)
    {
        $server = trim($server);

        $server = preg_replace('/\/$/', '', $server);
        $ipTools = new IpTools();
        if ($ipTools->validIpv6($server)) {
            $result = array('host' => "[$server]");
        } else {
            $parsed = parse_url($server);
            if (array_key_exists('path', $parsed) && !array_key_exists('host', $parsed)) {
                $host = preg_replace('/\//', '', $parsed['path']);

                // if host is ipv6 with port. Example: [1a80:1f45::ebb:12]:8080
                if (preg_match('/^(\[[a-f0-9:]+\]):(\d{1,5})$/i', $host, $matches)) {
                    $result = array('host' => $matches[1], 'port' => $matches[2]);
                } else {
                    $result = array('host' => $host);
                }
            } else {
                $result = $parsed;
            }
        }
        return $result;
    }

    /**
     * @return string|bool
     */
    protected function loadHandler(string $tld)
    {
        // In this case we already have the handler class name
        if( class_exists($tld) ){
            return $tld;
        }

        $tld = ucfirst($tld);
        $handlerName = "phpWhois\\Handlers\\{$tld}Handler";

        if( class_exists($handlerName) ){
            return $handlerName;
        }

        return false;
    }

    /**
     * @return string|bool
     * @deprecated
     */
    protected function loadLegacyHandler(string $queryHandler, string $queryFile)
    {
        $handler_name = str_replace('.', '_', $queryHandler);

        // If the handler has not already been included somehow, include it now
        $HANDLER_FLAG = sprintf("__%s_HANDLER__", strtoupper($handler_name));

        if (!defined($HANDLER_FLAG)) {
            include($queryFile);
        }

        // If the handler has still not been included, append to query errors list and return
        if (!defined($HANDLER_FLAG)) {
            return false;
        }

        return $handler_name . '_handler';
    }


    ////////////////////////////////////////////
    ////////////////////////////////////////////
    ////////////////////////////////////////////
    // Newer logic :-)

    /**
     * Using who_is response split into an array, extract all info available
     * @param array  $raw_data_text
     * @param string $tld
     * @param string $whois_domain
     * @return array
     */
    protected static function handleWhoIsText( array $raw_data_text, string $tld, string $whois_domain='' ): array
    {
        $isLineToSkip = static function( $line ){
            return empty($line) || str_starts_with($line,'*') || str_starts_with($line,'>>>') || str_starts_with($line,'%%') || str_starts_with($line,'NOTICE: ') || str_starts_with($line,'TERMS OF USE: ');
        };
        $getKeyValueByLine = static function( $line, &$previous_key ) use ($tld){

            if(
                // TODO: use a "Handler" to check "when there a new line of the WhoIS"
                /* For other TLD */  (($tld !== 'pl') && str_contains($line,':')) ||
                /* Check only for PL domains */(($tld === 'pl') && (substr_count($line,':')===1 || str_starts_with($line,'created:') || str_starts_with($line,'last modified:') || (str_contains($line,'nameservers:') && str_contains($line,'dns.pl.'))))
            ){
                $arr = explode(':', $line, 2);
                // Reset the $previous_key (section)
                $previous_key = null;

            }else if( $previous_key !== null ){
                $arr = [$previous_key,$line];
            }else{
                $arr = [$line,''];
            }

            return [
                strtolower(trim($arr[0])), // key
                trim($arr[1]) // value
            ];
        };

        $section = '';
        $who_is_info = [];
        $previous_key = null;
        $is_nic_section = false;    // Used for FR domains :-(

        $whois_section_names = [
            // Example in WhoIS text:
            // holder-c: CCDS71-FRNIC
            // admin-c: CCED209-FRNIC
            // tech-c: OVH5-FRNIC

            // This will be in the "admin" section
//            nic-hdl: CCED209-FRNIC
//            type: ORGANIZATION
//            ...

            // This will be in the "holder" section
//            nic-hdl: CCDS71-FRNIC
//            type: ORGANIZATION
//            ...

            //  'holder' => 'CCDS71-FRNIC',
            //  'admin' => 'CCED209-FRNIC',
            //  'tech' => 'OVH5-FRNIC',
            //  other...? Maybe... :-)
        ];

        // Retrieve "$whois_section_names" by "NIC Handle" ("nic-hdl" key), used by ".fr" domains
        foreach( $raw_data_text as $line ){

            if( $isLineToSkip($line) ){
                continue;
            }

            [$key,$value] = $getKeyValueByLine($line,$previous_key);

            if( str_ends_with($key,'-c') ){
                // holder-c | admin-c | tech-c | zone-c
                $key_name = substr($key,0,-2);
                if( empty($whois_section_names[$key_name]) ){
                    $whois_section_names[$key_name] = $value;
                }
            }
        }

        // Retrive all info parsing all rows in $raw_data_text
        foreach( $raw_data_text as $line ){
            $line = trim(str_replace(['&gt;','&lt;'],'',$line));

            if( $line === "" ){
                // New section info
                $section = '';
                $is_nic_section = false;
            }

            if( $isLineToSkip($line) ){
                continue;
            }

            $lower_line = strtolower($line);

            if( $section === 'technical ' && str_starts_with($lower_line,'nserver:') ){
                // Case for WhoIS "servizi.garr.it"
                $section = '';
                $previous_key = $lower_line;
            }else if( !$is_nic_section && (($start_with_contact = str_starts_with($lower_line,'contact:')) || in_array($lower_line,['registrant','admin contact','technical contacts','registrar','nameservers'])) ){
                $section = ($start_with_contact ? trim(str_replace('contact:','',$lower_line)) : $lower_line) .' ';
                $previous_key = $lower_line === 'nameservers' ? $lower_line : null; // Caso particolare
                continue;
            }

            [$key,$value] = $getKeyValueByLine($line,$previous_key);

            if(
                str_starts_with($value,'Please query') || str_starts_with($value,'Whois protection') ||
                in_array(strtolower($value),['redacted for privacy','data protected','expired expired','redacted'],true)
            ){
                continue;
            }

            if( str_starts_with($value,'<img src') ){
                preg_match('/<img src="(?<image_path>\/eimg\/[\w\/]+\/(?<image_hash>\w+)\.png)"[ \w="]+>(?<email>@[\w.-]+)/',$value,$matches);
//                $value = static::parseImageContent($whois_domain.trim($matches['image_path'],'/')) . $matches['email'];
                $value = $matches['email'];
            }

            // Restore the correct section when in the WhoIS response used the "nic-hdl" header section
            // ITA: a volte nella risposta non vengono divise le sezioni con delle parole, ma viene usata la chiave "nic-hdl"
            // per determinare che cosa indica quella sezione di testo. Usata spesso dai (maledetti) registri francesi.
            if( $key === 'nic-hdl' ){
                $is_nic_section = true;
                $section = (array_search($value,$whois_section_names,true) ?: $value) .'_';
                $key = 'code';
            }

            if( $previous_key === null && str_contains($line, ':') ){
                $previous_key = $key;
            }

            $info_key = str_replace(' ', '_', (($previous_key === 'nameservers') ? $previous_key : $section . $key) );

            if( isset($who_is_info[$info_key]) && ($who_is_info[$info_key] !== $value) ){
                if( !is_array($who_is_info[$info_key]) ){
                    $who_is_info[$info_key] = [$who_is_info[$info_key]];
                }
                if( !in_array($value,$who_is_info[$info_key],true) ){
                    $who_is_info[$info_key][] = $value;
                }
            }else{
                $who_is_info[$info_key] = $value;
            }
        }

        unset(
            $who_is_info['url_of_the_icann_whois_inaccuracy_complaint_form'],
            $who_is_info['for_more_information_on_whois_status_codes,_please_visit_https'],
            $who_is_info['notice'],
            $who_is_info['terms_of_use'],
            $who_is_info['by_the_following_terms_of_use'],
            $who_is_info['to'],
            $who_is_info['https'],
        );

        return $who_is_info;
    }

    protected static function retrieveInfoFromRawWhoIs( array $info, array $who_is_info, array $map_info_keys ): array
    {
        foreach( $map_info_keys as $map_key => $raw_who_is_keys ){

            if( !empty($info[$map_key]) ){
                // Already set :-)
                continue;
            }

            $info[$map_key] = null;
            foreach( $raw_who_is_keys as $key ){
                if( !empty($who_is_info[$key]) ){
                    $info[$map_key] = trim(is_array($who_is_info[$key]) ? implode(', ',array_unique($who_is_info[$key])) : $who_is_info[$key]);
                    break;
                }
            }
        }

        return $info;
    }

    /** @noinspection SuspiciousAssignmentsInspection */
    protected static function handleRegistrarInfo( array $registrar_info, array $who_is_info ): array {

        $registrar_info = static::retrieveInfoFromRawWhoIs(
            $registrar_info,
            $who_is_info,
            [
                'code' => ['registrar_iana_id','sponsoring_registrar_iana_id'], // $reg_iana_id
                'name' => ['registrar_name','sponsoring_registrar','registrar'], // $reg_name
                'url' => ['registrar_url','registrar-url','referral_url'],    // $reg_web
                'phone' => ['registrar_phone','registrar_abuse_contact_phone'], // $reg_phone
//                'fax' => ['registrar_fax'], // $reg_fax
                'email' => ['registrar_email','registrar_abuse_contact_email'], // $reg_email
                'address' => [], // $reg_address
                'country' => ['registrar_country'], // $reg_country
                'whois_server' => ['registrar_whois_server'],
                'dns_security' => ['dnssec','registrar_dnssec'],
            ]
        );

        if( empty($registrar_info['name']) && !empty($domain['sponsor']) ){
            $registrar_info['name'] = $domain['sponsor'];
        }

        if( !empty($registrar_info['code']) && ($registrar_info['name'] !== 'not applicable') ){
            // Lo recupero dalla tabella IANA
            $registrar_info['name'] = static::getRegistrarNameByIANACode($registrar_info['code']) ?? $registrar_info['name'] ?? null;
        }

        // Fix the name of Registrar including the "Organization name"
        $registrar_info['name'] = static::handleOrganizationInfo(
            $registrar_info,
            $registrar_info['organization'] ?? $who_is_info['registrar_organization'] ?? null
        );

        if( empty($registrar_info['whois_server']) && !empty($registrar_info['servers'][0]['server']) ){
            $registrar_info['whois_server'] = $registrar_info['servers'][0]['server'];
        }

        if( !empty($registrar_info['dns_security'])  ){

            switch( $registrar_info['dns_security'] ){
                case 'yes': $registrar_info['dns_security'] = true; break;
                case 'no': $registrar_info['dns_security'] = false; break;
                default: $registrar_info['dns_security'] = null; break;
            }

//            // TODO: PHP8
//            $registrar_info['dns_security'] = match($registrar_info['dns_security']){
//                'yes' => true,
//                'no' => false,
//                default => null // example: unsigned
//            };
        }

        if( !empty($registrar_info['country']) ){
            $registrar_info['country'] = Countries::countryToISO3($registrar_info['country']);
        }

        unset(
            $registrar_info['servers'],
            $registrar_info['registrar'],
            $registrar_info['sponsor'],
        );

        return $registrar_info;
    }

    protected static function handleDomainInfo( array $domain_info, array $who_is_info, array $propriety_info=[] ): array
    {
        if( !empty($domain_info['handle']) ){
            $domain_info['code'] = $domain_info['handle'];
        }

        $domain_info = static::retrieveInfoFromRawWhoIs(
            $domain_info,
            $who_is_info,
            [
                'code' => [],
                'ip' => [],
                'name' => ['domain'],
                'is_registered' => [],
                'dns' => [],
                'created_at' => ['creation_date','domain_name_commencement_date','created','registered_on','created_on'],
                'updated_at' => ['updated_date','last_update','last_updated','last-update'],
                'expiration_date' => ['registrar_registration_expiration_date','expires','expire','expires_on','expiry_date','paid-till','free-date','registry_expiry_date']
            ]
        );

        if( !empty($domain_info['created']) && empty($domain_info['created_at']) ){
            $domain_info['created_at'] = $domain_info['created'];
        }
        if( !empty($domain_info['changed']) && empty($domain_info['updated_at']) ){
            $domain_info['updated_at'] = $domain_info['changed'];
        }
        if( !empty($domain_info['expires']) && empty($domain_info['expiration_date']) ){
            $domain_info['expiration_date'] = $domain_info['expires'];
        }

        if( !empty($domain_info['name']) ){
            $domain_info['ip'] = static::retrieveIPDomain($domain_info['name']);
        }

        if( empty($who_is_info['nameservers']) ){
            $who_is_info['nameservers'] = [];
        }

        $domain_info['dns'] = [];
        $dns_list = $who_is_info['nserver'] ?? array_combine($who_is_info['nameservers'],$who_is_info['nameservers']);
        if( is_string($dns_list) ){
            $dns_list = [$dns_list => $dns_list];
        }
        foreach( $dns_list as $dns_name => $dns_ip ){
            if( is_numeric($dns_name) ){
                // In case the list is [0 => "dns_1_name", 1 => "dns_2_name", ... ]
                $dns_name = $dns_ip;
                $dns_ip = gethostbyname($dns_name);
            }
            $domain_info['dns'][] = (static::retrieveIPLookup($dns_ip) ?? []) + ['url' => $dns_name];
        }

        // We need it?
        $domain_info['status'] = static::getDomainStatus([
            isset($domain_info['status']) ? implode(' ', (array) $domain_info['status']) : '',
            $propriety_info['status'] ?? '',
            is_array($who_is_info['domain_status'] ?? '') ? implode(' ',$who_is_info['domain_status']) : '',
            is_string($who_is_info['domain_status'] ?? []) ? $who_is_info['domain_status'] : '',
        ]);

        $domain_info['is_registered'] = (!empty($propriety_info['registered']) && $propriety_info['registered'] === 'yes') || !empty($domain_info['status']) || (!empty($domain_info['eppstatus']) && $domain_info['eppstatus']==='active');

        // TODO: check if dates must be formatted?

        return static::cleaningDataStructure($domain_info);
    }

    protected static function handleRegistrantInfo( array $registrant_info, array $who_is_info ): array
    {
        $registrant_info['code'] = $registrant_info['handle'] ?? $who_is_info['registrant_id'] ?? null;

        $registrant_info = static::retrieveInfoFromRawWhoIs(
            $registrant_info,
            $who_is_info,
            [
                'name' => ['registrant_name','registrant','holder_code'], // $rgnt_name
                'address' => ['registrant_street','registrant_address','holder_address'], // $rgnt_street
                'city' => ['registrant_city'],  // $rgnt_city
                'state' => ['registrant_state/province','registrant_state'], // $rgnt_state
                'postal_code' => ['registrant_postal_code'], // $rgnt_postcode
                'country' => ['registrant_country_code','registrant_country','holder_country'], // $rgnt_country
                'phone' => ['registrant_phone','registrant_phone_ext','holder_phone'],
//                'fax' => ['registrant_fax','registrant_fax_ext'],
                'email' => ['registrant_email','holder_e-mail'],
                'site_web' => ['registrant_site'],
                'created_at' => ['registrant_created'],
                'updated_at' => ['registrant_last_update','holder_changed'],
            ]
        );

        $registrant_info['address'] = static::handleAddressInfo($registrant_info);
        $registrant_info['name'] = static::handleOrganizationInfo(
            $registrant_info,
            $registrant_info['organization'] ?? $who_is_info['registrant_organization'] ?? null
        );

        if( !empty($registrant_info['address']) && empty($registrant_info['country']) ){
            $registrant_info['country'] = Countries::retrieveCountryByAddress($registrant_info);
        }

        if( !empty($registrant_info['country']) ){
            $registrant_info['country'] = Countries::countryToISO3($registrant_info['country']);
        }

        return static::cleaningDataStructure($registrant_info);
    }

    protected static function handleAdminInfo( array $admin_info, array $who_is_info ): array
    {
        // Collapse address info
        $admin_info = static::retrieveInfoFromRawWhoIs(
            $admin_info,
            $who_is_info,
            [
                'code' => ['registry_admin_id','admin_id','admin_handle','administrative_contact_id','admin_code'],
                'name' => ['admin_name','admin_contact_name','administrative_contact_name','administrative_name'],
                'organization' => ['admin_organization','admin_contact_organization','administrative_contact_organization','administrative_organisation'],
                'phone' => ['admin_phone','admin_phone_number','admin_contact_phone_number','admin_phone_ext','administrative_contact_phone','administrative_contact_phone_number','administrative_phone'],
//                'fax' => ['admin_fax','admin_fax_number','admin_fax_ext','administrative_contact_fax','administrative_contact_facsimile_number','administrative_fax-no'],
                'email' => ['admin_e-mail','admin_email','admin_mail','admin_contact_email','administrative_contact_email','administrative_e-mail'],

                'created_at' => ['admin_created','admin_contact_created'],
                'updated_at' => ['admin_changed','admin_contact_changed'],

                'address' => ['admin_address','admin_contact_address','administrative_contact_address','administrative_contact_address1','administrative_contact_address2','administrative_address'],
                'street' => ['admin_street','admin_contact_street','administrative_contact_street'],
                'city' => ['admin_city','admin_contact_city','administrative_contact_city'],
                'state' => ['admin_state','admin_contact_state','administrative_contact_state','admin_state/province','administrative_contact_state/province'],
                'country' => ['admin_country','admin_country_code','admin_contact_country','admin_contact_country_code','administrative_contact_country','administrative_contact_country_code'],
                'postal_code' => ['admin_postal_code','admin_contact_postal_code','admin_postcode','administrative_contact_postal_code'],
            ]
        );

        $admin_info['code'] = $admin_info['code'] ?? $admin_info['handle'] ?? null;
        $admin_info['name'] = static::handleOrganizationInfo($admin_info);
        $admin_info['address'] = static::handleAddressInfo($admin_info);

        if( !empty($admin_info['address']) && empty($admin_info['country']) ){
            $admin_info['country'] = Countries::retrieveCountryByAddress($admin_info);
        }

        if( !empty($admin_info['country']) ){
            $admin_info['country'] = Countries::countryToISO3($admin_info['country']);
        }

        return static::cleaningDataStructure($admin_info);
    }

    protected static function handleTechnicalInfo( array $technical_info, array $who_is_info, array $domain_data ): array
    {
        // Collapse address info
        $technical_info = static::retrieveInfoFromRawWhoIs(
            $technical_info,
            $who_is_info,
            [
                'code' => ['tech_code'],
                'name' => ['tech_name','technical_contacts_name','technical_name','tech_contact'],
                'organization' => ['technical_contacts_organization','technical_organisation'],
                'handle' => ['tech_id','technical_contacts_id'],
                'phone' => ['tech_phone','technical_contacts_phone','technical_contact_phone_number','technical_phone'],
//                'fax' => ['tech_fax','technical_contacts_fax','technical_contact_fax','technical_fax-no'],
                'email' => ['tech_email','technical_contacts_email','technical_contact_email','technical_e-mail','tech_e-mail'],

                'created_at' => ['technical_contacts_created'],
                'updated_at' => ['technical_contacts_last_update'],

                'address' => ['technical_contacts_address','technical_address','tech_address'],
                'street' => ['tech_street'],
                'city' => ['tech_city'],
                'state' => ['tech_state/province','tech_state'],
                'country' => ['tech_country','technical_contact_country_code'],
                'postal_code' => ['tech_postal_code','technical_contact_postal_code'],
            ]
        );

        $technical_info['code'] = $technical_info['handle'] ?? null;
        $technical_info['address'] = static::handleAddressInfo($technical_info);
        $technical_info['name'] = static::handleOrganizationInfo($technical_info);

        if( empty($technical_info['country']) && !empty($domain_data['ip']) ){
            foreach( $domain_data['ip'] as $ip_address ){
                $technical_info['country'] = Countries::retriveCountryByAddressIP($ip_address);
                if( !empty($technical_info['country']) ){
                    break;
                }
            }
        }

        if( !empty($technical_info['address']) && empty($technical_info['country']) ){
            $technical_info['country'] = Countries::retrieveCountryByAddress($technical_info);
        }

        if( !empty($technical_info['country']) ){
            $technical_info['country'] = Countries::countryToISO3($technical_info['country']);
        }

        return static::cleaningDataStructure($technical_info);
    }

    /**
     * From a map of info (retrieved by who is response), returns the address formatted
     * @param array $info
     * @return string|null
     */
    protected static function handleAddressInfo( array $info ): ?string
    {
        if( !empty($info['address']) && is_string($info['address']) ){
            return $info['address'];
        }

        // Sometimes, rows are single-element arrays  :-|
        if( is_array($info['address']) ){
            foreach( $info['address'] as &$row ){
                if( is_array($row) ){
                    $row = implode(' ',$row);
                }
            }
            unset($row);
        }

        $address = implode(', ',array_filter([
            $info['address']['street'] ?? $info['street'] ?? null,
            $info['address']['postcode'] ?? $info['addres']['pcode'] ?? $info['postcode'] ?? $info['postal_code'] ?? null,
            $info['address']['city'] ?? $info['city'] ?? null,
            $info['state'] ?? null,
            $info['address']['country'] ?? $info['country'] ?? null,
        ]));

        return ($address !== '') ? $address : null;
    }

    protected static function handleOrganizationInfo( array $info, ?string $organization=null ): ?string
    {
        if( $organization === null ){
            $organization = $info['organization'] ?? null;
        }

        if( is_array($info['name']) ){
            $info['name'] = implode(', ',$info['name']);
        }

        if( empty($organization) ){
            return $info['name'] ?? null;
        }

        return !empty($info['name']) ? "{$info['name']} ($organization)": $organization;
    }

    protected static function retrieveIPDomain( string $domain ): ?array
    {
        $dns = @dns_get_record($domain,DNS_A);

        if( empty($dns) ){
            return null;
        }

        return array_column($dns,'ip');
    }

    /**
     * Returns statuses of the domain
     */
    protected static function getDomainStatus( array $raw_status ): array
    {
        $domain_status = array_unique(array_filter($raw_status));
        sort($domain_status);
        return array_filter(explode(' ',
            trim(str_replace('  ',' ', preg_replace('/https?:\/\/(www\.)?icann\.org\/epp#[a-zA-Z]+/','',implode(' ',$domain_status))))
        ));
    }

    /**
     * Remove redundant keys/values
     */
    protected static function cleaningDataStructure( array $info ): array
    {
        unset(
            $info['created'],
            $info['changed'],
            $info['expires'],
            $info['nserver'],
            $info['hold'],
            $info['sponsor'],
            $info['handle'],
            $info['registrant_id'],
            $info['organization'],
            $info['street'],
            $info['city'],
            $info['state'],
            $info['postal_code'],
            $info['anonymous'],
            $info['obsoleted'],
            $info['eligstatus'],
            $info['reachmedia'],
            $info['reachsource'],
            $info['reachstatus'],
            $info['reachdate'],
            $info['type'],
            $info['source'],
            $info['admin-c'],
            $info['tech-c'],
        );

        return $info;
    }

    protected static function retrieveIPLookup( string $ip_address ): ?array
    {
        if( empty($ip_address) || !filter_var($ip_address,FILTER_VALIDATE_IP) ){
            return null;
        }

        // First IP block to find the "iana whois"
        $IANA_ADDRESS_BLOCKS = [
            0 => '',
            1 => 'whois.apnic.net',
            2 => 'whois.ripe.net',
            3 => 'whois.arin.net',
            4 => 'whois.arin.net',
            5 => 'whois.ripe.net',
            6 => 'whois.arin.net',
            7 => 'whois.arin.net',
            8 => 'whois.arin.net',
            9 => 'whois.arin.net',
            10 => '',
            11 => 'whois.arin.net',
            12 => 'whois.arin.net',
            13 => 'whois.arin.net',
            14 => 'whois.apnic.net',
            15 => 'whois.arin.net',
            16 => 'whois.arin.net',
            17 => 'whois.arin.net',
            18 => 'whois.arin.net',
            19 => 'whois.arin.net',
            20 => 'whois.arin.net',
            21 => 'whois.arin.net',
            22 => 'whois.arin.net',
            23 => 'whois.arin.net',
            24 => 'whois.arin.net',
            25 => 'whois.ripe.net',
            26 => 'whois.arin.net',
            27 => 'whois.apnic.net',
            28 => 'whois.arin.net',
            29 => 'whois.arin.net',
            30 => 'whois.arin.net',
            31 => 'whois.ripe.net',
            32 => 'whois.arin.net',
            33 => 'whois.arin.net',
            34 => 'whois.arin.net',
            35 => 'whois.arin.net',
            36 => 'whois.apnic.net',
            37 => 'whois.ripe.net',
            38 => 'whois.arin.net',
            39 => 'whois.apnic.net',
            40 => 'whois.arin.net',
            41 => 'whois.afrinic.net',
            42 => 'whois.apnic.net',
            43 => 'whois.apnic.net',
            44 => 'whois.arin.net',
            45 => 'whois.arin.net',
            46 => 'whois.ripe.net',
            47 => 'whois.arin.net',
            48 => 'whois.arin.net',
            49 => 'whois.apnic.net',
            50 => 'whois.arin.net',
            51 => 'whois.ripe.net',
            52 => 'whois.arin.net',
            53 => 'whois.ripe.net',
            54 => 'whois.arin.net',
            55 => 'whois.arin.net',
            56 => 'whois.arin.net',
            57 => 'whois.ripe.net',
            58 => 'whois.apnic.net',
            59 => 'whois.apnic.net',
            60 => 'whois.apnic.net',
            61 => 'whois.apnic.net',
            62 => 'whois.ripe.net',
            63 => 'whois.arin.net',
            64 => 'whois.arin.net',
            65 => 'whois.arin.net',
            66 => 'whois.arin.net',
            67 => 'whois.arin.net',
            68 => 'whois.arin.net',
            69 => 'whois.arin.net',
            70 => 'whois.arin.net',
            71 => 'whois.arin.net',
            72 => 'whois.arin.net',
            73 => 'whois.arin.net',
            74 => 'whois.arin.net',
            75 => 'whois.arin.net',
            76 => 'whois.arin.net',
            77 => 'whois.ripe.net',
            78 => 'whois.ripe.net',
            79 => 'whois.ripe.net',
            80 => 'whois.ripe.net',
            81 => 'whois.ripe.net',
            82 => 'whois.ripe.net',
            83 => 'whois.ripe.net',
            84 => 'whois.ripe.net',
            85 => 'whois.ripe.net',
            86 => 'whois.ripe.net',
            87 => 'whois.ripe.net',
            88 => 'whois.ripe.net',
            89 => 'whois.ripe.net',
            90 => 'whois.ripe.net',
            91 => 'whois.ripe.net',
            92 => 'whois.ripe.net',
            93 => 'whois.ripe.net',
            94 => 'whois.ripe.net',
            95 => 'whois.ripe.net',
            96 => 'whois.arin.net',
            97 => 'whois.arin.net',
            98 => 'whois.arin.net',
            99 => 'whois.arin.net',
            100 => 'whois.arin.net',
            101 => 'whois.apnic.net',
            102 => 'whois.afrinic.net',
            103 => 'whois.apnic.net',
            104 => 'whois.arin.net',
            105 => 'whois.afrinic.net',
            106 => 'whois.apnic.net',
            107 => 'whois.arin.net',
            108 => 'whois.arin.net',
            109 => 'whois.ripe.net',
            110 => 'whois.apnic.net',
            111 => 'whois.apnic.net',
            112 => 'whois.apnic.net',
            113 => 'whois.apnic.net',
            114 => 'whois.apnic.net',
            115 => 'whois.apnic.net',
            116 => 'whois.apnic.net',
            117 => 'whois.apnic.net',
            118 => 'whois.apnic.net',
            119 => 'whois.apnic.net',
            120 => 'whois.apnic.net',
            121 => 'whois.apnic.net',
            122 => 'whois.apnic.net',
            123 => 'whois.apnic.net',
            124 => 'whois.apnic.net',
            125 => 'whois.apnic.net',
            126 => 'whois.apnic.net',
            127 => '',
            128 => 'whois.arin.net',
            129 => 'whois.arin.net',
            130 => 'whois.arin.net',
            131 => 'whois.arin.net',
            132 => 'whois.arin.net',
            133 => 'whois.apnic.net',
            134 => 'whois.arin.net',
            135 => 'whois.arin.net',
            136 => 'whois.arin.net',
            137 => 'whois.arin.net',
            138 => 'whois.arin.net',
            139 => 'whois.arin.net',
            140 => 'whois.arin.net',
            141 => 'whois.ripe.net',
            142 => 'whois.arin.net',
            143 => 'whois.arin.net',
            144 => 'whois.arin.net',
            145 => 'whois.ripe.net',
            146 => 'whois.arin.net',
            147 => 'whois.arin.net',
            148 => 'whois.arin.net',
            149 => 'whois.arin.net',
            150 => 'whois.apnic.net',
            151 => 'whois.ripe.net',
            152 => 'whois.arin.net',
            153 => 'whois.apnic.net',
            154 => 'whois.afrinic.net',
            155 => 'whois.arin.net',
            156 => 'whois.arin.net',
            157 => 'whois.arin.net',
            158 => 'whois.arin.net',
            159 => 'whois.arin.net',
            160 => 'whois.arin.net',
            161 => 'whois.arin.net',
            162 => 'whois.arin.net',
            163 => 'whois.apnic.net',
            164 => 'whois.arin.net',
            165 => 'whois.arin.net',
            166 => 'whois.arin.net',
            167 => 'whois.arin.net',
            168 => 'whois.arin.net',
            169 => 'whois.arin.net',
            170 => 'whois.arin.net',
            171 => 'whois.apnic.net',
            172 => 'whois.arin.net',
            173 => 'whois.arin.net',
            174 => 'whois.arin.net',
            175 => 'whois.apnic.net',
            176 => 'whois.ripe.net',
            177 => 'whois.lacnic.net',
            178 => 'whois.ripe.net',
            179 => 'whois.lacnic.net',
            180 => 'whois.apnic.net',
            181 => 'whois.lacnic.net',
            182 => 'whois.apnic.net',
            183 => 'whois.apnic.net',
            184 => 'whois.arin.net',
            185 => 'whois.ripe.net',
            186 => 'whois.lacnic.net',
            187 => 'whois.lacnic.net',
            188 => 'whois.ripe.net',
            189 => 'whois.lacnic.net',
            190 => 'whois.lacnic.net',
            191 => 'whois.lacnic.net',
            192 => 'whois.arin.net',
            193 => 'whois.ripe.net',
            194 => 'whois.ripe.net',
            195 => 'whois.ripe.net',
            196 => 'whois.afrinic.net',
            197 => 'whois.afrinic.net',
            198 => 'whois.arin.net',
            199 => 'whois.arin.net',
            200 => 'whois.lacnic.net',
            201 => 'whois.lacnic.net',
            202 => 'whois.apnic.net',
            203 => 'whois.apnic.net',
            204 => 'whois.arin.net',
            205 => 'whois.arin.net',
            206 => 'whois.arin.net',
            207 => 'whois.arin.net',
            208 => 'whois.arin.net',
            209 => 'whois.arin.net',
            210 => 'whois.apnic.net',
            211 => 'whois.apnic.net',
            212 => 'whois.ripe.net',
            213 => 'whois.ripe.net',
            214 => 'whois.arin.net',
            215 => 'whois.arin.net',
            216 => 'whois.arin.net',
            217 => 'whois.ripe.net',
            218 => 'whois.apnic.net',
            219 => 'whois.apnic.net',
            220 => 'whois.apnic.net',
            221 => 'whois.apnic.net',
            222 => 'whois.apnic.net',
            223 => 'whois.apnic.net',
            224 => '',
            225 => '',
            226 => '',
            227 => '',
            228 => '',
            229 => '',
            230 => '',
            231 => '',
            232 => '',
            233 => '',
            234 => '',
            235 => '',
            236 => '',
            237 => '',
            238 => '',
            239 => '',
            240 => '',
            241 => '',
            242 => '',
            243 => '',
            244 => '',
            245 => '',
            246 => '',
            247 => '',
            248 => '',
            249 => '',
            250 => '',
            251 => '',
            252 => '',
            253 => '',
            254 => '',
            255 => '',
        ];

        $split = explode('.',$ip_address);

        $whois_server = $IANA_ADDRESS_BLOCKS[$split[0]];

        $response = static::queryWhoisServer('whois.lacnic.net',$ip_address);

        if( !empty($response['data_remarks']) && empty($response['admin_abuse-mailbox']) ){

            if( is_array($response['data_remarks']) ){
                $response['data_remarks'] = implode(' ',$response['data_remarks']);
            }

            preg_match('/(?<abuse_email>[\w.-]+@([\w-]+\.)+[\w-]{2,4})/', $response['data_remarks'], $matches );
            if( !empty($matches['abuse_email']) ){
                $response['admin_abuse-mailbox'] = $matches['abuse_email'];
            }
        }

        $data = static::retrieveInfoFromRawWhoIs( $response, [], [
            'code' => ['admin_orgid','abuse_orgabusehandle','data_admin-c','data_ownerid'],
            'name' => ['data_netname','data_owner'],
            'address' => ['admin_address','person_address'],
            'country' => ['data_country'],
//            'link' => [''],
//            'contact' => [''],
            'phone' => ['admin_phone','abuse_orgabusephone','tech_orgtechphone','noc_orgnocphone','person_phone'],
//            'fax' => ['admin_fax-no','person_fax-no'],
            'email' => ['abuse_orgabuseemail','admin_abuse-mailbox'],
            'abuse_email' => ['abuse_orgabuseemail','tech_orgtechemail','noc_orgnocemail','admin_abuse-mailbox','person_e-mail'],
            'created_at' => ['data_regdate','data_created','person_created'],
            'updated_at' => ['data_updated','data_last-modified','person_last-modified'],
        ]);

        if( empty(array_filter($data)) ){
            // ARIN - The response is:
//            Alibaba.com LLC AL-3 (NET-47-88-0-0-1) 47.88.0.0 - 47.91.255.255
//            ALICLOUD-US ALICLOUD-US (NET-47-88-0-0-2) 47.88.0.0 - 47.88.127.255
            $data['raw'] = $response;
        }

        if( empty($data['country']) ){
            $data['country'] = Countries::retriveCountryByAddressIP($ip_address);
        }

        return ['ip' => $ip_address, 'whois_server' => $whois_server] + $data;
    }

    /**
     *
     */
    protected static function queryWhoisServer($whois_server, $domain): array
    {
        $fp = @fsockopen($whois_server, 43, $errno, $err_str, 10);

        if( empty($fp) ){
            // or die('Socket Error '. $errno .' - '. $err_str);
            return [];
        }

        //if($whoisserver == "whois.verisign-grs.com") $domain = "=".$domain; // whois.verisign-grs.com requires the equals sign ("=") or it returns any result containing the searched string.

        fwrite($fp, $domain . "\r\n");
        $out = "";
        while(!feof($fp)){
            $out .= @fgets($fp);
        }
        fclose($fp);

        $result = [];
        if( !str_contains(strtolower($out),'error') && !str_contains(strtolower($out), 'not allocated') ) {

            $section = 'data';
            $rows = explode("\n", $out);
            foreach( $rows as $row ){
                $row = trim($row);

                if( empty($row) || str_starts_with($row,'#') || str_starts_with($row,'%') ){
                    continue;
                }

                if( str_contains($row,':') ){
                    [$key,$value] = @explode(':', $row, 2);
                    $key = strtolower(trim($key));
                    $value = trim($value);

                    if( str_starts_with($value,'*') ){
                        continue;
                    }

                    if( in_array($key,['role','orgname','orgnochandle','orgabusehandle','orgtechhandle']) ){
                        // This is the master info to attribute to the ADMIN person

                        switch( $key ){
                            case 'orgnochandle': $section = 'noc'; break;
                            case 'orgabusehandle': $section = 'abuse'; break;
                            case 'orgtechhandle': $section = 'tech'; break;
                            case 'role': case 'orgname': $section = 'admin'; break;
                        }

                        // TODO: PHP8
//                        $section = match($key){
//                            'orgnochandle' => 'noc',
//                            'orgabusehandle' => 'abuse',
//                            'orgtechhandle' => 'tech',
//                            'role','orgname' => 'admin'
//                        };
                    }elseif( in_array($key,['person','irt','route']) ){
                        $section = $key;
                    }

                    $info_key = strtolower(str_replace(' ','_',$section .'_'. $key ));

                    if( isset($result[$info_key]) ){
                        if( !is_array($result[$info_key]) ){
                            $result[$info_key] = [$result[$info_key]];
                        }
                        $result[$info_key][] = $value;
                    }else{
                        $result[$info_key] = $value;
                    }

                }else{
                    $result[] = $row;
                }

            }
        }

        return $result;
    }

    /**
     * Returns the name of Registrars
    */
    protected static function getRegistrarNameByIANACode( string $iana_id ): ?string
    {
        if( $iana_id === 'not applicable' ){
            return null;
        }

        if( !is_numeric($iana_id) ){
            return null;
        }

        return static::IANA_REGISTRAR_IDS[$iana_id] ?? null;
    }
}
