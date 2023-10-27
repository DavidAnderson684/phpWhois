<?php

namespace phpWhois\Utils;


class Countries
{
    /**
     * @var array Countries map data
    */
    protected const MAP = [
        'ABW' => ['name'=>'Aruba', 'iso2'=>'AW', 'ip_from'=>962322432, 'ip_to'=>962324479],
        'AFG' => ['name'=>'Afghanistan', 'iso2'=>'AF', 'ip_from'=>391692288, 'ip_to'=>391700479],
        'AGO' => ['name'=>'Angola', 'iso2'=>'AO', 'ip_from'=>692035584, 'ip_to'=>692043775],
        'AIA' => ['name'=>'Anguilla', 'iso2'=>'AI', 'ip_from'=>1080988672, 'ip_to'=>1080989183],
        'ALA' => ['name'=>'Åland Islands', 'iso2'=>'AX', 'ip_from'=>1334116352, 'ip_to'=>1334124543],
        'ALB' => ['name'=>'Albania', 'iso2'=>'AL', 'ip_from'=>97445888, 'ip_to'=>97447935],
        'AND' => ['name'=>'Andorra', 'iso2'=>'AD', 'ip_from'=>576948224, 'ip_to'=>576948735],
        'ARE' => ['name'=>'United Arab Emirates', 'iso2'=>'AE', 'ip_from'=>34643456, 'ip_to'=>34643711],
        'ARG' => ['name'=>'Argentina', 'iso2'=>'AR', 'ip_from'=>28454912, 'ip_to'=>28459007],
        'ARM' => ['name'=>'Armenia', 'iso2'=>'AM', 'ip_from'=>34732288, 'ip_to'=>34732543],
        'ASM' => ['name'=>'American Samoa', 'iso2'=>'AS', 'ip_from'=>695039232, 'ip_to'=>695039487],
        'ATA' => ['name'=>'Antarctica', 'iso2'=>'AQ', 'ip_from'=>null, 'ip_to'=>null],
        'ATF' => ['name'=>'French Southern Territories', 'iso2'=>'TF', 'ip_from'=>null, 'ip_to'=>null],
        'ATG' => ['name'=>'Antigua and Barbuda', 'iso2'=>'AG', 'ip_from'=>394563584, 'ip_to'=>394563839],
        'AUS' => ['name'=>'Australia', 'iso2'=>'AU', 'ip_from'=>16778240, 'ip_to'=>16779263],
        'AUT' => ['name'=>'Austria', 'iso2'=>'AT', 'ip_from'=>34605568, 'ip_to'=>34605823],
        'AZE' => ['name'=>'Azerbaijan', 'iso2'=>'AZ', 'ip_from'=>86777856, 'ip_to'=>86779903],
        'BDI' => ['name'=>'Burundi', 'iso2'=>'BI', 'ip_from'=>34736896, 'ip_to'=>34737151],
        'BEL' => ['name'=>'Belgium', 'iso2'=>'BE', 'ip_from'=>34637824, 'ip_to'=>34638079],
        'BEN' => ['name'=>'Benin', 'iso2'=>'BJ', 'ip_from'=>692715520, 'ip_to'=>692719615],
        'BES' => ['name'=>'Bonaire, Sint Eustatius and Saba', 'iso2'=>'BQ', 'ip_from'=>2399150080, 'ip_to'=>2399151103],
        'BFA' => ['name'=>'Burkina Faso', 'iso2'=>'BF', 'ip_from'=>692989952, 'ip_to'=>692991999],
        'BGD' => ['name'=>'Bangladesh', 'iso2'=>'BD', 'ip_from'=>37434112, 'ip_to'=>37434367],
        'BGR' => ['name'=>'Bulgaria', 'iso2'=>'BG', 'ip_from'=>34876672, 'ip_to'=>34876927],
        'BHR' => ['name'=>'Bahrain', 'iso2'=>'BH', 'ip_from'=>50671616, 'ip_to'=>50672639],
        'BHS' => ['name'=>'Bahamas', 'iso2'=>'BS', 'ip_from'=>398012416, 'ip_to'=>398012671],
        'BIH' => ['name'=>'Bosnia and Herzegovina', 'iso2'=>'BA', 'ip_from'=>86720512, 'ip_to'=>86736895],
        'BLM' => ['name'=>'Saint Barthélemy', 'iso2'=>'BL', 'ip_from'=>394782720, 'ip_to'=>394782975],
        'BLR' => ['name'=>'Belarus', 'iso2'=>'BY', 'ip_from'=>90488832, 'ip_to'=>90497023],
        'BLZ' => ['name'=>'Belize', 'iso2'=>'BZ', 'ip_from'=>624025856, 'ip_to'=>624026111],
        'BMU' => ['name'=>'Bermuda', 'iso2'=>'BM', 'ip_from'=>1101750784, 'ip_to'=>1101751295],
        'BOL' => ['name'=>'Bolivia', 'iso2'=>'BO', 'ip_from'=>576979968, 'ip_to'=>576980991],
        'BRA' => ['name'=>'Brazil', 'iso2'=>'BR', 'ip_from'=>28450816, 'ip_to'=>28454911],
        'BRB' => ['name'=>'Barbados', 'iso2'=>'BB', 'ip_from'=>401342464, 'ip_to'=>401346559],
        'BRN' => ['name'=>'Brunei Darussalam', 'iso2'=>'BN', 'ip_from'=>95864064, 'ip_to'=>95864319],
        'BTN' => ['name'=>'Bhutan', 'iso2'=>'BT', 'ip_from'=>95863808, 'ip_to'=>95864063],
        'BVT' => ['name'=>'Bouvet Island', 'iso2'=>'BV', 'ip_from'=>3116465152, 'ip_to'=>3116466175],
        'BWA' => ['name'=>'Botswana', 'iso2'=>'BW', 'ip_from'=>640937984, 'ip_to'=>640938495],
        'CAF' => ['name'=>'Central African Republic', 'iso2'=>'CF', 'ip_from'=>693008384, 'ip_to'=>693009407],
        'CAN' => ['name'=>'Canada', 'iso2'=>'CA', 'ip_from'=>35014656, 'ip_to'=>35015679],
        'CCK' => ['name'=>'Cocos (Keeling] Islands', 'iso2'=>'CC', 'ip_from'=>null, 'ip_to'=>null],
        'CHE' => ['name'=>'Switzerland', 'iso2'=>'CH', 'ip_from'=>34606080, 'ip_to'=>34606591],
        'CHL' => ['name'=>'Chile', 'iso2'=>'CL', 'ip_from'=>34794496, 'ip_to'=>34795519],
        'CHN' => ['name'=>'China', 'iso2'=>'CN', 'ip_from'=>16777472, 'ip_to'=>16778239],
        'CIV' => ['name'=>'Ivory Coast', 'iso2'=>'CI', 'ip_from'=>692191232, 'ip_to'=>692207615],
        'CMR' => ['name'=>'Cameroon', 'iso2'=>'CM', 'ip_from'=>34637312, 'ip_to'=>34637567],
        'COD' => ['name'=>'Democratic Republic of the Congo', 'iso2'=>'CD', 'ip_from'=>95374592, 'ip_to'=>95374847],
        'COG' => ['name'=>'Congo', 'iso2'=>'CG', 'ip_from'=>692797440, 'ip_to'=>692801535],
        'COK' => ['name'=>'Cook Islands', 'iso2'=>'CK', 'ip_from'=>243869696, 'ip_to'=>243870207],
        'COL' => ['name'=>'Colombia', 'iso2'=>'CO', 'ip_from'=>69330944, 'ip_to'=>69331455],
        'COM' => ['name'=>'Comoros', 'iso2'=>'KM', 'ip_from'=>700588032, 'ip_to'=>700588543],
        'CPV' => ['name'=>'Cabo Verde', 'iso2'=>'CV', 'ip_from'=>692748288, 'ip_to'=>692752383],
        'CRI' => ['name'=>'Costa Rica', 'iso2'=>'CR', 'ip_from'=>150204416, 'ip_to'=>150206463],
        'CUB' => ['name'=>'Cuba', 'iso2'=>'CU', 'ip_from'=>961179136, 'ip_to'=>961179647],
        'CUW' => ['name'=>'Curaçao', 'iso2'=>'CW', 'ip_from'=>759667712, 'ip_to'=>759668735],
        'CXR' => ['name'=>'Christmas Island', 'iso2'=>'CX', 'ip_from'=>null, 'ip_to'=>null],
        'CYM' => ['name'=>'Cayman Islands', 'iso2'=>'KY', 'ip_from'=>398196736, 'ip_to'=>398196991],
        'CYP' => ['name'=>'Cyprus', 'iso2'=>'CY', 'ip_from'=>40716288, 'ip_to'=>40717055],
        'CZE' => ['name'=>'Czechia', 'iso2'=>'CZ', 'ip_from'=>34603520, 'ip_to'=>34603775],
        'DEU' => ['name'=>'Germany', 'iso2'=>'DE', 'ip_from'=>34603776, 'ip_to'=>34604031],
        'DJI' => ['name'=>'Djibouti', 'iso2'=>'DJ', 'ip_from'=>700309504, 'ip_to'=>700310527],
        'DMA' => ['name'=>'Dominica', 'iso2'=>'DM', 'ip_from'=>398127104, 'ip_to'=>398127359],
        'DNK' => ['name'=>'Denmark', 'iso2'=>'DK', 'ip_from'=>34619136, 'ip_to'=>34619391],
        'DOM' => ['name'=>'Dominican Republic', 'iso2'=>'DO', 'ip_from'=>134874624, 'ip_to'=>134875135],
        'DZA' => ['name'=>'Algeria', 'iso2'=>'DZ', 'ip_from'=>694157312, 'ip_to'=>695039231],
        'ECU' => ['name'=>'Ecuador', 'iso2'=>'EC', 'ip_from'=>137562624, 'ip_to'=>137562879],
        'EGY' => ['name'=>'Egypt', 'iso2'=>'EG', 'ip_from'=>34963456, 'ip_to'=>34964479],
        'ERI' => ['name'=>'Eritrea', 'iso2'=>'ER', 'ip_from'=>3301466112, 'ip_to'=>3301470207],
        'ESH' => ['name'=>'Western Sahara', 'iso2'=>'EH', 'ip_from'=>null, 'ip_to'=>null],
        'ESP' => ['name'=>'Spain', 'iso2'=>'ES', 'ip_from'=>28499968, 'ip_to'=>28508159],
        'EST' => ['name'=>'Estonia', 'iso2'=>'EE', 'ip_from'=>37346304, 'ip_to'=>37347327],
        'ETH' => ['name'=>'Ethiopia', 'iso2'=>'ET', 'ip_from'=>1425971968, 'ip_to'=>1425972223],
        'FIN' => ['name'=>'Finland', 'iso2'=>'FI', 'ip_from'=>34639872, 'ip_to'=>34640383],
        'FJI' => ['name'=>'Fiji', 'iso2'=>'FJ', 'ip_from'=>243869184, 'ip_to'=>243869439],
        'FLK' => ['name'=>'Falkland Islands', 'iso2'=>'FK', 'ip_from'=>1053837824, 'ip_to'=>1053838335],
        'FRA' => ['name'=>'France', 'iso2'=>'FR', 'ip_from'=>28536832, 'ip_to'=>28540927],
        'FRO' => ['name'=>'Faroe Islands', 'iso2'=>'FO', 'ip_from'=>628685824, 'ip_to'=>628686335],
        'FSM' => ['name'=>'Federated States of Micronesia', 'iso2'=>'FM', 'ip_from'=>1730673664, 'ip_to'=>1730674687],
        'GAB' => ['name'=>'Gabon', 'iso2'=>'GA', 'ip_from'=>693039104, 'ip_to'=>693040127],
        'GBR' => ['name'=>'United Kingdom', 'iso2'=>'GB', 'ip_from'=>34606592, 'ip_to'=>34606847],
        'GEO' => ['name'=>'Georgia', 'iso2'=>'GE', 'ip_from'=>37345280, 'ip_to'=>37346303],
        'GGY' => ['name'=>'Guernsey', 'iso2'=>'GG', 'ip_from'=>87970816, 'ip_to'=>87971071],
        'GHA' => ['name'=>'Ghana', 'iso2'=>'GH', 'ip_from'=>34622720, 'ip_to'=>34622975],
        'GIB' => ['name'=>'Gibraltar', 'iso2'=>'GI', 'ip_from'=>87972864, 'ip_to'=>87973375],
        'GIN' => ['name'=>'Guinea', 'iso2'=>'GN', 'ip_from'=>692959232, 'ip_to'=>692961279],
        'GLP' => ['name'=>'Guadeloupe', 'iso2'=>'GP', 'ip_from'=>90590208, 'ip_to'=>90590463],
        'GMB' => ['name'=>'Gambia', 'iso2'=>'GM', 'ip_from'=>692848640, 'ip_to'=>692850687],
        'GNB' => ['name'=>'Guinea-Bissau', 'iso2'=>'GW', 'ip_from'=>961716736, 'ip_to'=>961717247],
        'GNQ' => ['name'=>'Equatorial Guinea', 'iso2'=>'GQ', 'ip_from'=>693055488, 'ip_to'=>693056511],
        'GRC' => ['name'=>'Greece', 'iso2'=>'GR', 'ip_from'=>34607872, 'ip_to'=>34608127],
        'GRD' => ['name'=>'Grenada', 'iso2'=>'GD', 'ip_from'=>394438656, 'ip_to'=>394438911],
        'GRL' => ['name'=>'Greenland', 'iso2'=>'GL', 'ip_from'=>621947904, 'ip_to'=>621948927],
        'GTM' => ['name'=>'Guatemala', 'iso2'=>'GT', 'ip_from'=>412627968, 'ip_to'=>412628991],
        'GUF' => ['name'=>'French Guiana', 'iso2'=>'GF', 'ip_from'=>90590976, 'ip_to'=>90591231],
        'GUM' => ['name'=>'Guam', 'iso2'=>'GU', 'ip_from'=>134443008, 'ip_to'=>134446847],
        'GUY' => ['name'=>'Guyana', 'iso2'=>'GY', 'ip_from'=>961213952, 'ip_to'=>961214463],
        'HKG' => ['name'=>'Hong Kong', 'iso2'=>'HK', 'ip_from'=>18923520, 'ip_to'=>18925567],
        'HMD' => ['name'=>'Heard Island and McDonald Islands', 'iso2'=>'HM', 'ip_from'=>null, 'ip_to'=>null],
        'HND' => ['name'=>'Honduras', 'iso2'=>'HN', 'ip_from'=>755258368, 'ip_to'=>755259391],
        'HRV' => ['name'=>'Croatia', 'iso2'=>'HR', 'ip_from'=>37367808, 'ip_to'=>37368831],
        'HTI' => ['name'=>'Haiti', 'iso2'=>'HT', 'ip_from'=>961179648, 'ip_to'=>961180159],
        'HUN' => ['name'=>'Hungary', 'iso2'=>'HU', 'ip_from'=>37398528, 'ip_to'=>37399551],
        'IDN' => ['name'=>'Indonesia', 'iso2'=>'ID', 'ip_from'=>50668544, 'ip_to'=>50669567],
        'IMN' => ['name'=>'Isle of Man', 'iso2'=>'IM', 'ip_from'=>87970304, 'ip_to'=>87970815],
        'IND' => ['name'=>'India', 'iso2'=>'IN', 'ip_from'=>17170432, 'ip_to'=>17301503],
        'IOT' => ['name'=>'British Indian Ocean Territory', 'iso2'=>'IO', 'ip_from'=>700588544, 'ip_to'=>700588799],
        'IRL' => ['name'=>'Ireland', 'iso2'=>'IE', 'ip_from'=>34615552, 'ip_to'=>34615807],
        'IRN' => ['name'=>'Iran', 'iso2'=>'IR', 'ip_from'=>42991616, 'ip_to'=>43253759],
        'IRQ' => ['name'=>'Iraq', 'iso2'=>'IQ', 'ip_from'=>37233664, 'ip_to'=>37234687],
        'ISL' => ['name'=>'Iceland', 'iso2'=>'IS', 'ip_from'=>37286656, 'ip_to'=>37286911],
        'ISR' => ['name'=>'Israel', 'iso2'=>'IL', 'ip_from'=>35055872, 'ip_to'=>35056127],
        'ITA' => ['name'=>'Italy', 'iso2'=>'IT', 'ip_from'=>34607360, 'ip_to'=>34607615],
        'JAM' => ['name'=>'Jamaica', 'iso2'=>'JM', 'ip_from'=>292973568, 'ip_to'=>292974591],
        'JEY' => ['name'=>'Jersey', 'iso2'=>'JE', 'ip_from'=>86220800, 'ip_to'=>86222847],
        'JOR' => ['name'=>'Jordan', 'iso2'=>'JO', 'ip_from'=>34674688, 'ip_to'=>34675711],
        'JPN' => ['name'=>'Japan', 'iso2'=>'JP', 'ip_from'=>16781312, 'ip_to'=>16785407],
        'KAZ' => ['name'=>'Kazakhstan', 'iso2'=>'KZ', 'ip_from'=>37314560, 'ip_to'=>37315583],
        'KEN' => ['name'=>'Kenya', 'iso2'=>'KE', 'ip_from'=>34709760, 'ip_to'=>34710015],
        'KGZ' => ['name'=>'Kyrgyzstan', 'iso2'=>'KG', 'ip_from'=>87623680, 'ip_to'=>87625727],
        'KHM' => ['name'=>'Cambodia', 'iso2'=>'KH', 'ip_from'=>18938880, 'ip_to'=>18939135],
        'KIR' => ['name'=>'Kiribati', 'iso2'=>'KI', 'ip_from'=>960935936, 'ip_to'=>960936447],
        'KNA' => ['name'=>'Saint Kitts and Nevis', 'iso2'=>'KN', 'ip_from'=>394514432, 'ip_to'=>394514687],
        'KOR' => ['name'=>'South Korea', 'iso2'=>'KR', 'ip_from'=>17498112, 'ip_to'=>17563647],
        'KWT' => ['name'=>'Kuwait', 'iso2'=>'KW', 'ip_from'=>90718720, 'ip_to'=>90719231],
        'LAO' => ['name'=>'Laos', 'iso2'=>'LA', 'ip_from'=>100513792, 'ip_to'=>100514303],
        'LBN' => ['name'=>'Lebanon', 'iso2'=>'LB', 'ip_from'=>84443136, 'ip_to'=>84451327],
        'LBR' => ['name'=>'Liberia', 'iso2'=>'LR', 'ip_from'=>691621888, 'ip_to'=>691625983],
        'LBY' => ['name'=>'Libya', 'iso2'=>'LY', 'ip_from'=>88014848, 'ip_to'=>88016895],
        'LCA' => ['name'=>'Saint Lucia', 'iso2'=>'LC', 'ip_from'=>398311424, 'ip_to'=>398311935],
        'LIE' => ['name'=>'Liechtenstein', 'iso2'=>'LI', 'ip_from'=>86177792, 'ip_to'=>86179839],
        'LKA' => ['name'=>'Sri Lanka', 'iso2'=>'LK', 'ip_from'=>94197760, 'ip_to'=>94198015],
        'LSO' => ['name'=>'Lesotho', 'iso2'=>'LS', 'ip_from'=>692850688, 'ip_to'=>692852735],
        'LTU' => ['name'=>'Lithuania', 'iso2'=>'LT', 'ip_from'=>37414912, 'ip_to'=>37415935],
        'LUX' => ['name'=>'Luxembourg', 'iso2'=>'LU', 'ip_from'=>34798080, 'ip_to'=>34798335],
        'LVA' => ['name'=>'Latvia', 'iso2'=>'LV', 'ip_from'=>37260800, 'ip_to'=>37261311],
        'MAC' => ['name'=>'Macau', 'iso2'=>'MO', 'ip_from'=>291211264, 'ip_to'=>291213311],
        'MAF' => ['name'=>'Saint Martin', 'iso2'=>'MF', 'ip_from'=>90590464, 'ip_to'=>90590719],
        'MAR' => ['name'=>'Morocco', 'iso2'=>'MA', 'ip_from'=>392165120, 'ip_to'=>392165375],
        'MCO' => ['name'=>'Monaco', 'iso2'=>'MC', 'ip_from'=>576957440, 'ip_to'=>576957951],
        'MDA' => ['name'=>'Moldova', 'iso2'=>'MD', 'ip_from'=>37224448, 'ip_to'=>37225471],
        'MDG' => ['name'=>'Madagascar', 'iso2'=>'MG', 'ip_from'=>692027392, 'ip_to'=>692035583],
        'MDV' => ['name'=>'Maldives', 'iso2'=>'MV', 'ip_from'=>460488704, 'ip_to'=>460505087],
        'MEX' => ['name'=>'Mexico', 'iso2'=>'MX', 'ip_from'=>37374976, 'ip_to'=>37375999],
        'MHL' => ['name'=>'Marshall Islands', 'iso2'=>'MH', 'ip_from'=>960934400, 'ip_to'=>960934911],
        'MKD' => ['name'=>'North Macedonia', 'iso2'=>'MK', 'ip_from'=>86028288, 'ip_to'=>86030335],
        'MLI' => ['name'=>'Mali', 'iso2'=>'ML', 'ip_from'=>692674560, 'ip_to'=>692682751],
        'MLT' => ['name'=>'Malta', 'iso2'=>'MT', 'ip_from'=>37453824, 'ip_to'=>37454847],
        'MMR' => ['name'=>'Myanmar', 'iso2'=>'MM', 'ip_from'=>398936064, 'ip_to'=>398936319],
        'MNE' => ['name'=>'Montenegro', 'iso2'=>'ME', 'ip_from'=>533512192, 'ip_to'=>533528575],
        'MNG' => ['name'=>'Mongolia', 'iso2'=>'MN', 'ip_from'=>234978304, 'ip_to'=>234979327],
        'MNP' => ['name'=>'Northern Mariana Islands', 'iso2'=>'MP', 'ip_from'=>134446848, 'ip_to'=>134447103],
        'MOZ' => ['name'=>'Mozambique', 'iso2'=>'MZ', 'ip_from'=>691853312, 'ip_to'=>691853567],
        'MRT' => ['name'=>'Mauritania', 'iso2'=>'MR', 'ip_from'=>696942592, 'ip_to'=>696950783],
        'MSR' => ['name'=>'Montserrat', 'iso2'=>'MS', 'ip_from'=>1761587200, 'ip_to'=>1761587711],
        'MTQ' => ['name'=>'Martinique', 'iso2'=>'MQ', 'ip_from'=>90590720, 'ip_to'=>90590975],
        'MUS' => ['name'=>'Mauritius', 'iso2'=>'MU', 'ip_from'=>691631104, 'ip_to'=>691632127],
        'MWI' => ['name'=>'Malawi', 'iso2'=>'MW', 'ip_from'=>692453376, 'ip_to'=>692486143],
        'MYS' => ['name'=>'Malaysia', 'iso2'=>'MY', 'ip_from'=>17367040, 'ip_to'=>17432575],
        'MYT' => ['name'=>'Mayotte', 'iso2'=>'YT', 'ip_from'=>90589184, 'ip_to'=>90589439],
        'NAM' => ['name'=>'Namibia', 'iso2'=>'NA', 'ip_from'=>692043776, 'ip_to'=>692060159],
        'NCL' => ['name'=>'New Caledonia', 'iso2'=>'NC', 'ip_from'=>460980224, 'ip_to'=>460981247],
        'NER' => ['name'=>'Niger', 'iso2'=>'NE', 'ip_from'=>693007360, 'ip_to'=>693008383],
        'NFK' => ['name'=>'Norfolk Island', 'iso2'=>'NF', 'ip_from'=>1730923520, 'ip_to'=>1730924031],
        'NGA' => ['name'=>'Nigeria', 'iso2'=>'NG', 'ip_from'=>136526080, 'ip_to'=>136526335],
        'NIC' => ['name'=>'Nicaragua', 'iso2'=>'NI', 'ip_from'=>292959232, 'ip_to'=>292960255],
        'NIU' => ['name'=>'Niue', 'iso2'=>'NU', 'ip_from'=>832319488, 'ip_to'=>832320511],
        'NLD' => ['name'=>'Netherlands', 'iso2'=>'NL', 'ip_from'=>34607616, 'ip_to'=>34607871],
        'NOR' => ['name'=>'Norway', 'iso2'=>'NO', 'ip_from'=>28233472, 'ip_to'=>28233727],
        'NPL' => ['name'=>'Nepal', 'iso2'=>'NP', 'ip_from'=>243873024, 'ip_to'=>243873279],
        'NRU' => ['name'=>'Nauru', 'iso2'=>'NR', 'ip_from'=>736495104, 'ip_to'=>736495359],
        'NZL' => ['name'=>'New Zealand', 'iso2'=>'NZ', 'ip_from'=>90769920, 'ip_to'=>90770175],
        'OMN' => ['name'=>'Oman', 'iso2'=>'OM', 'ip_from'=>85262336, 'ip_to'=>85327871],
        'PAK' => ['name'=>'Pakistan', 'iso2'=>'PK', 'ip_from'=>234973184, 'ip_to'=>234974207],
        'PAN' => ['name'=>'Panama', 'iso2'=>'PA', 'ip_from'=>100440064, 'ip_to'=>100440319],
        'PCN' => ['name'=>'Pitcairn Islands', 'iso2'=>'PN', 'ip_from'=>2617296896, 'ip_to'=>2617297151],
        'PER' => ['name'=>'Peru', 'iso2'=>'PE', 'ip_from'=>87359488, 'ip_to'=>87359743],
        'PHL' => ['name'=>'Philippines', 'iso2'=>'PH', 'ip_from'=>19202048, 'ip_to'=>19267583],
        'PLW' => ['name'=>'Palau', 'iso2'=>'PW', 'ip_from'=>960933888, 'ip_to'=>960934399],
        'PNG' => ['name'=>'Papua New Guinea', 'iso2'=>'PG', 'ip_from'=>243867648, 'ip_to'=>243867903],
        'POL' => ['name'=>'Poland', 'iso2'=>'PL', 'ip_from'=>34647040, 'ip_to'=>34647295],
        'PRI' => ['name'=>'Puerto Rico', 'iso2'=>'PR', 'ip_from'=>204046336, 'ip_to'=>204047103],
        'PRK' => ['name'=>'North Korea', 'iso2'=>'KP', 'ip_from'=>1743020544, 'ip_to'=>1743021055],
        'PRT' => ['name'=>'Portugal', 'iso2'=>'PT', 'ip_from'=>34619648, 'ip_to'=>34619903],
        'PRY' => ['name'=>'Paraguay', 'iso2'=>'PY', 'ip_from'=>412624896, 'ip_to'=>412625919],
        'PSE' => ['name'=>'Palestine', 'iso2'=>'PS', 'ip_from'=>28471296, 'ip_to'=>28479487],
        'PYF' => ['name'=>'French Polynesia', 'iso2'=>'PF', 'ip_from'=>737783808, 'ip_to'=>737784831],
        'QAT' => ['name'=>'Qatar', 'iso2'=>'QA', 'ip_from'=>35104768, 'ip_to'=>35105791],
        'REU' => ['name'=>'Réunion', 'iso2'=>'RE', 'ip_from'=>90589440, 'ip_to'=>90589951],
        'ROU' => ['name'=>'Romania', 'iso2'=>'RO', 'ip_from'=>34698240, 'ip_to'=>34699263],
        'RUS' => ['name'=>'Russia', 'iso2'=>'RU', 'ip_from'=>34608128, 'ip_to'=>34608639],
        'RWA' => ['name'=>'Rwanda', 'iso2'=>'RW', 'ip_from'=>692756480, 'ip_to'=>692760575],
        'SAU' => ['name'=>'Saudi Arabia', 'iso2'=>'SA', 'ip_from'=>37434368, 'ip_to'=>37435391],
        'SDN' => ['name'=>'Sudan', 'iso2'=>'SD', 'ip_from'=>692256768, 'ip_to'=>692273151],
        'SEN' => ['name'=>'Senegal', 'iso2'=>'SN', 'ip_from'=>693239808, 'ip_to'=>693370879],
        'SGP' => ['name'=>'Singapore', 'iso2'=>'SG', 'ip_from'=>18907136, 'ip_to'=>18923519],
        'SGS' => ['name'=>'South Georgia and the South Sandwich Islands', 'iso2'=>'GS', 'ip_from'=>3522354176, 'ip_to'=>3522354431],
        'SHN' => ['name'=>'Saint Helena, Ascension and Tristan da Cunha', 'iso2'=>'SH', 'ip_from'=>2617297408, 'ip_to'=>2617297663],
        'SJM' => ['name'=>'Svalbard and Jan Mayen', 'iso2'=>'SJ', 'ip_from'=>1482338816, 'ip_to'=>1482339071],
        'SLB' => ['name'=>'Solomon Islands', 'iso2'=>'SB', 'ip_from'=>243868160, 'ip_to'=>243868415],
        'SLE' => ['name'=>'Sierra Leone', 'iso2'=>'SL', 'ip_from'=>692999168, 'ip_to'=>693000191],
        'SLV' => ['name'=>'El Salvador', 'iso2'=>'SV', 'ip_from'=>540740608, 'ip_to'=>540740863],
        'SMR' => ['name'=>'San Marino', 'iso2'=>'SM', 'ip_from'=>522779136, 'ip_to'=>522779391],
        'SOM' => ['name'=>'Somalia', 'iso2'=>'SO', 'ip_from'=>692996096, 'ip_to'=>692997119],
        'SPM' => ['name'=>'Saint Pierre and Miquelon', 'iso2'=>'PM', 'ip_from'=>100429824, 'ip_to'=>100430847],
        'SRB' => ['name'=>'Serbia', 'iso2'=>'RS', 'ip_from'=>85368832, 'ip_to'=>85377023],
        'SSD' => ['name'=>'South Sudan', 'iso2'=>'SS', 'ip_from'=>640370688, 'ip_to'=>640371711],
        'STP' => ['name'=>'São Tomé and Príncipe', 'iso2'=>'ST', 'ip_from'=>3272083456, 'ip_to'=>3272083711],
        'SUR' => ['name'=>'Suriname', 'iso2'=>'SR', 'ip_from'=>759436288, 'ip_to'=>759437055],
        'SVK' => ['name'=>'Slovakia', 'iso2'=>'SK', 'ip_from'=>37306368, 'ip_to'=>37307391],
        'SVN' => ['name'=>'Slovenia', 'iso2'=>'SI', 'ip_from'=>86018048, 'ip_to'=>86020095],
        'SWE' => ['name'=>'Sweden', 'iso2'=>'SE', 'ip_from'=>34619904, 'ip_to'=>34620927],
        'SWZ' => ['name'=>'Eswatini', 'iso2'=>'SZ', 'ip_from'=>95374336, 'ip_to'=>95374591],
        'SXM' => ['name'=>'Sint Maarten', 'iso2'=>'SX', 'ip_from'=>2208388096, 'ip_to'=>2208389119],
        'SYC' => ['name'=>'Seychelles', 'iso2'=>'SC', 'ip_from'=>37227008, 'ip_to'=>37227263],
        'SYR' => ['name'=>'Syria', 'iso2'=>'SY', 'ip_from'=>83886080, 'ip_to'=>83951615],
        'TCA' => ['name'=>'Turks and Caicos Islands', 'iso2'=>'TC', 'ip_from'=>759086848, 'ip_to'=>759087103],
        'TCD' => ['name'=>'Chad', 'iso2'=>'TD', 'ip_from'=>702152960, 'ip_to'=>702154751],
        'TGO' => ['name'=>'Togo', 'iso2'=>'TG', 'ip_from'=>693012480, 'ip_to'=>693013503],
        'THA' => ['name'=>'Thailand', 'iso2'=>'TH', 'ip_from'=>16809984, 'ip_to'=>16842751],
        'TJK' => ['name'=>'Tajikistan', 'iso2'=>'TJ', 'ip_from'=>627218432, 'ip_to'=>627220479],
        'TKL' => ['name'=>'Tokelau', 'iso2'=>'TK', 'ip_from'=>459282432, 'ip_to'=>459284479],
        'TKM' => ['name'=>'Turkmenistan', 'iso2'=>'TM', 'ip_from'=>455258112, 'ip_to'=>455258367],
        'TLS' => ['name'=>'East Timor', 'iso2'=>'TL', 'ip_from'=>243867904, 'ip_to'=>243868159],
        'TON' => ['name'=>'Tonga', 'iso2'=>'TO', 'ip_from'=>243872256, 'ip_to'=>243872511],
        'TTO' => ['name'=>'Trinidad and Tobago', 'iso2'=>'TT', 'ip_from'=>386091008, 'ip_to'=>386091263],
        'TUN' => ['name'=>'Tunisia', 'iso2'=>'TN', 'ip_from'=>691929088, 'ip_to'=>691994623],
        'TUR' => ['name'=>'Türkiye', 'iso2'=>'TR', 'ip_from'=>34641408, 'ip_to'=>34641919],
        'TUV' => ['name'=>'Tuvalu', 'iso2'=>'TV', 'ip_from'=>960932352, 'ip_to'=>960932863],
        'TWN' => ['name'=>'Taiwan', 'iso2'=>'TW', 'ip_from'=>18927616, 'ip_to'=>18929663],
        'TZA' => ['name'=>'Tanzania', 'iso2'=>'TZ', 'ip_from'=>34732544, 'ip_to'=>34732799],
        'UGA' => ['name'=>'Uganda', 'iso2'=>'UG', 'ip_from'=>34732032, 'ip_to'=>34732287],
        'UKR' => ['name'=>'Ukraine', 'iso2'=>'UA', 'ip_from'=>34953472, 'ip_to'=>34953727],
        'UMI' => ['name'=>'United States Minor Outlying Islands', 'iso2'=>'UM', 'ip_from'=>412818432, 'ip_to'=>412818687],
        'URY' => ['name'=>'Uruguay', 'iso2'=>'UY', 'ip_from'=>34750464, 'ip_to'=>34750719],
        'USA' => ['name'=>'United States', 'iso2'=>'US', 'ip_from'=>16777216, 'ip_to'=>16777471],
        'UZB' => ['name'=>'Uzbekistan', 'iso2'=>'UZ', 'ip_from'=>37305344, 'ip_to'=>37306367],
        'VAT' => ['name'=>'Vatican City', 'iso2'=>'VA', 'ip_from'=>37253120, 'ip_to'=>37253375],
        'VCT' => ['name'=>'Saint Vincent and the Grenadines', 'iso2'=>'VC', 'ip_from'=>397037568, 'ip_to'=>397037823],
        'VEN' => ['name'=>'Venezuela', 'iso2'=>'VE', 'ip_from'=>137573376, 'ip_to'=>137573631],
        'VGB' => ['name'=>'Virgin Islands (British]', 'iso2'=>'VG', 'ip_from'=>394452992, 'ip_to'=>394453247],
        'VIR' => ['name'=>'Virgin Islands (U.S.]', 'iso2'=>'VI', 'ip_from'=>212792064, 'ip_to'=>212792831],
        'VNM' => ['name'=>'Viet Nam', 'iso2'=>'VN', 'ip_from'=>20185088, 'ip_to'=>20447231],
        'VUT' => ['name'=>'Vanuatu', 'iso2'=>'VU', 'ip_from'=>243868928, 'ip_to'=>243869183],
        'WLF' => ['name'=>'Wallis and Futuna', 'iso2'=>'WF', 'ip_from'=>461225984, 'ip_to'=>461227007],
        'WSM' => ['name'=>'Samoa', 'iso2'=>'WS', 'ip_from'=>737256448, 'ip_to'=>737257471],
        'YEM' => ['name'=>'Yemen', 'iso2'=>'YE', 'ip_from'=>90480640, 'ip_to'=>90482687],
        'ZAF' => ['name'=>'South Africa', 'iso2'=>'ZA', 'ip_from'=>34638848, 'ip_to'=>34639359],
        'ZMB' => ['name'=>'Zambia', 'iso2'=>'ZM', 'ip_from'=>691798016, 'ip_to'=>691804159],
        'ZWE' => ['name'=>'Zimbabwe', 'iso2'=>'ZW', 'ip_from'=>84610304, 'ip_to'=>84610559]
    ];

    public static function get( $iso3 ): array
    {
        return static::MAP[$iso3] ?? [];
    }

    public static function retrieveCountryByAddress( array $info ): ?string
    {
        preg_match('/, (?<country_code>[a-zA-Z]{2,3})$/',$info['address'],$matches);

        if( empty($matches['country_code']) ){

            // Last change, search by name
            preg_match('/, (?<country_name>[a-zA-Z]+)$/',$info['address'],$matches);

            if( empty($matches['country_name']) ){

                // Last try check if is "United States of America"
                if( str_contains(strtolower($info['address']),'united states of america') ){
                    return 'USA';
                }

                if( str_contains(strtolower($info['name']),'ALIBABA.COM SINGAPORE') ){
                    // Singapore
                    return 'SGP';
                }

                return null;
            }

            return static::countryToISO3($matches['country_name']);
        }

        return static::countryToISO3($matches['country_code']);
    }

    public static function countryToISO3( string $country_code ): ?string
    {
        $country_code = strtoupper(trim($country_code));

        if( strlen($country_code) === 3 ){
            return $country_code;
        }

        if( strlen($country_code) === 2 ){
            // Old iso2 code style
            return static::MAP[$country_code]['iso3'] ?? null;
        }

        foreach( static::MAP AS $country ){
            if( $country['name'] === $country_code ){
                return $country['iso3'];
            }
        }

        return null;
    }

    /**
     * Returns ISO3 code of the country
     * @param string $ip_address
     * @return string|null
     */
    public static function retriveCountryByAddressIP( string $ip_address ): ?string
    {
        $ip_long_int = ip2long($ip_address);

        foreach( static::MAP AS $country ){
            if( ($country['ip_from'] >= $ip_long_int) && ($country['ip_to'] <= $ip_long_int) ){
                return $country['iso3'];
            }
        }

        return null;
    }
}