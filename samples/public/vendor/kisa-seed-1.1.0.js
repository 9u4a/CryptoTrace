Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
//#region src/common.ts
var Common = class Common {
	static {
		this.BIG_ENDIAN = 0;
	}
	static {
		this.LITTLE_ENDIAN = 1;
	}
	static {
		this.ENDIAN = Common.BIG_ENDIAN;
	}
	static arraycopy(dst, src, length) {
		for (let i = 0; i < length; i++) dst[i] = src[i];
	}
	static arraycopy_offset(dst, dst_offset, src, src_offset, length) {
		for (let i = 0; i < length; i++) dst[dst_offset + i] = src[src_offset + i];
	}
	static arrayinit(dst, value, length) {
		for (let i = 0; i < length; i++) dst[i] = value;
	}
	static arrayinit_offset(dst, dst_offset, value, length) {
		for (let i = 0; i < length; i++) dst[dst_offset + i] = value;
	}
	static memcpy(dst, src, length, ENDIAN_or_src_offset) {
		if (src instanceof Uint8Array && typeof ENDIAN_or_src_offset === "number") {
			let iLen = Math.floor(length / 4);
			for (let i = 0; i < iLen; i++) this.byte_to_int(dst, i, src, i * 4, ENDIAN_or_src_offset);
		} else if (Array.isArray(src) && typeof ENDIAN_or_src_offset === "number") {
			let iLen = Math.floor(length / 4) + (length % 4 !== 0 ? 1 : 0);
			for (let i = 0; i < iLen; i++) dst[i] = src[ENDIAN_or_src_offset + i];
		} else throw new Error("Invalid arguments");
	}
	static set_byte_for_int(dst, b_offset, value, endian) {
		let shift_value;
		let mask_value;
		let mask_value2;
		let value2;
		if (Common.ENDIAN == Common.BIG_ENDIAN) {
			shift_value = (3 - b_offset % 4) * 8;
			mask_value = 255 << shift_value;
			mask_value2 = ~mask_value;
			value2 = (value & 255) << shift_value;
			dst[Math.floor(b_offset / 4)] = dst[Math.floor(b_offset / 4)] & mask_value2 | value2 & mask_value;
		} else {
			shift_value = b_offset % 4 * 8;
			mask_value = 255 << shift_value;
			mask_value2 = ~mask_value;
			value2 = (value & 255) << shift_value;
			dst[Math.floor(b_offset / 4)] = dst[Math.floor(b_offset / 4)] & mask_value2 | value2 & mask_value;
		}
	}
	static get_byte_for_int(src, b_offset, ENDIAN) {
		let shift_value;
		let mask_value;
		let value;
		if (ENDIAN == Common.BIG_ENDIAN) {
			shift_value = (3 - b_offset % 4) * 8;
			mask_value = 255 << shift_value;
			value = (src[Math.floor(b_offset / 4)] & mask_value) >> shift_value;
			return value & 255;
		} else {
			shift_value = b_offset % 4 * 8;
			mask_value = 255 << shift_value;
			value = (src[Math.floor(b_offset / 4)] & mask_value) >> shift_value;
			return value & 255;
		}
	}
	static get_bytes_for_ints(src, offset, endian) {
		let iLen = src.length - offset;
		let result = new Uint8Array(iLen * 4);
		for (let i = 0; i < iLen; i++) this.int_to_byte(result, i * 4, src, offset + i, endian);
		return result;
	}
	static byte_to_int(...args) {
		if (args.length === 5) {
			const [dst, dst_offset, src, src_offset, ENDIAN] = args;
			if (ENDIAN === Common.BIG_ENDIAN) dst[dst_offset] = src[src_offset] << 24 | src[src_offset + 1] << 16 | src[src_offset + 2] << 8 | src[src_offset + 3];
			else dst[dst_offset] = src[src_offset] | src[src_offset + 1] << 8 | src[src_offset + 2] << 16 | src[src_offset + 3] << 24;
		} else if (args.length === 3) {
			const [src, src_offset, ENDIAN] = args;
			if (ENDIAN === Common.BIG_ENDIAN) return src[src_offset] << 24 | src[src_offset + 1] << 16 | src[src_offset + 2] << 8 | src[src_offset + 3];
			else return src[src_offset] | src[src_offset + 1] << 8 | src[src_offset + 2] << 16 | src[src_offset + 3] << 24;
		} else throw new Error("Invalid arguments");
	}
	static byte_to_int_big_endian(src, src_offset) {
		return src[src_offset] << 24 | src[src_offset + 1] << 16 | src[src_offset + 2] << 8 | src[src_offset + 3];
	}
	static int_to_byte(dst, dst_offset, src, src_offset, ENDIAN) {
		this.int_to_byte_unit(dst, dst_offset, src[src_offset], ENDIAN);
	}
	static int_to_byte_unit(dst, dst_offset, src, ENDIAN) {
		if (ENDIAN === this.BIG_ENDIAN) {
			dst[dst_offset] = src >> 24 & 255;
			dst[dst_offset + 1] = src >> 16 & 255;
			dst[dst_offset + 2] = src >> 8 & 255;
			dst[dst_offset + 3] = src & 255;
		} else {
			dst[dst_offset] = src & 255;
			dst[dst_offset + 1] = src >> 8 & 255;
			dst[dst_offset + 2] = src >> 16 & 255;
			dst[dst_offset + 3] = src >> 24 & 255;
		}
	}
	static int_to_byte_unit_big_endian(dst, dst_offset, src) {
		dst[dst_offset] = src >> 24 & 255;
		dst[dst_offset + 1] = src >> 16 & 255;
		dst[dst_offset + 2] = src >> 8 & 255;
		dst[dst_offset + 3] = src & 255;
	}
	static URShift(x, n) {
		if (n === 0) return x;
		if (n >= 32) return 0;
		return x >> n & ~(2147483648 >> n - 1);
	}
	static {
		this.INT_RANGE_MAX = Math.pow(2, 32);
	}
	static intToUnsigned(x) {
		if (x >= 0) return x;
		return x + this.INT_RANGE_MAX;
	}
	static Padding(pbData, padData, length) {
		let padvalue = 16 - length % 16;
		for (let i = 0; i < length; i++) padData[i] = pbData[i];
		let i = length;
		do {
			padData[i] = padvalue;
			i++;
		} while (i % 16 !== 0);
		return i;
	}
	static BLOCK_XOR_PROPOSAL(OUT_VALUE, out_value_offset, IN_VALUE1, in_value1_offset, IN_VALUE2, in_value2_offset) {
		for (let i = 0; i < 4; i++) OUT_VALUE[out_value_offset + i] = (in_value1_offset + i < IN_VALUE1.length ? IN_VALUE1[in_value1_offset + i] : 0) ^ (in_value2_offset + i < IN_VALUE2.length ? IN_VALUE2[in_value2_offset + i] : 0);
	}
};
//#endregion
//#region src/defaults.ts
const defaults = {
	SS0: [
		696885672,
		92635524,
		382128852,
		331600848,
		340021332,
		487395612,
		747413676,
		621093156,
		491606364,
		54739776,
		403181592,
		504238620,
		289493328,
		1020063996,
		181060296,
		591618912,
		671621160,
		71581764,
		536879136,
		495817116,
		549511392,
		583197408,
		147374280,
		386339604,
		629514660,
		261063564,
		50529024,
		994800504,
		999011256,
		318968592,
		314757840,
		785310444,
		809529456,
		210534540,
		1057960764,
		680042664,
		839004720,
		500027868,
		919007988,
		876900468,
		751624428,
		361075092,
		185271048,
		390550356,
		474763356,
		457921368,
		1032696252,
		16843008,
		604250148,
		470552604,
		860058480,
		411603096,
		268439568,
		214745292,
		851636976,
		432656856,
		738992172,
		667411428,
		843215472,
		58950528,
		462132120,
		297914832,
		109478532,
		164217288,
		541089888,
		272650320,
		595829664,
		734782440,
		218956044,
		914797236,
		512660124,
		256852812,
		931640244,
		441078360,
		113689284,
		944271480,
		646357668,
		302125584,
		797942700,
		365285844,
		557932896,
		63161280,
		881111220,
		21053760,
		306336336,
		1028485500,
		227377548,
		134742024,
		521081628,
		428446104,
		0,
		420024600,
		67371012,
		323179344,
		935850996,
		566354400,
		1036907004,
		910586484,
		789521196,
		654779172,
		813740208,
		193692552,
		235799052,
		730571688,
		578986656,
		776888940,
		327390096,
		223166796,
		692674920,
		1011642492,
		151585032,
		168428040,
		1066382268,
		802153452,
		868479984,
		96846276,
		126321540,
		335810580,
		1053750012,
		608460900,
		516870876,
		772678188,
		189481800,
		436867608,
		101057028,
		553722144,
		726360936,
		642146916,
		33686016,
		902164980,
		310547088,
		176849544,
		202113036,
		864269232,
		1045328508,
		281071824,
		977957496,
		122110788,
		377918100,
		633725412,
		637936164,
		8421504,
		764256684,
		533713884,
		562143648,
		805318704,
		923218740,
		781099692,
		906375732,
		352653588,
		570565152,
		940060728,
		885321972,
		663200676,
		88424772,
		206323788,
		25264512,
		701096424,
		75792516,
		394761108,
		889532724,
		197903304,
		248431308,
		1007431740,
		826372464,
		285282576,
		130532292,
		160006536,
		893743476,
		1003222008,
		449499864,
		952692984,
		344232084,
		424235352,
		42107520,
		80003268,
		1070593020,
		155795784,
		956903736,
		658989924,
		12632256,
		265274316,
		398971860,
		948482232,
		252642060,
		244220556,
		37896768,
		587408160,
		293704080,
		743202924,
		466342872,
		612671652,
		872689716,
		834793968,
		138952776,
		46318272,
		793731948,
		1024274748,
		755835180,
		4210752,
		1049539260,
		1041117756,
		1015853244,
		29475264,
		713728680,
		982168248,
		240009804,
		356864340,
		990589752,
		483184860,
		675831912,
		1062171516,
		478974108,
		415813848,
		172638792,
		373707348,
		927429492,
		545300640,
		768467436,
		105267780,
		897954228,
		722150184,
		625303908,
		986379e3,
		600040416,
		965325240,
		830583216,
		529503132,
		508449372,
		969535992,
		650568420,
		847426224,
		822161712,
		717939432,
		760045932,
		525292380,
		616882404,
		817950960,
		231588300,
		143163528,
		369496596,
		973746744,
		407392344,
		348442836,
		574775904,
		688464168,
		117900036,
		855847728,
		684253416,
		453710616,
		84214020,
		961114488,
		276861072,
		709517928,
		705307176,
		445289112
	],
	SS1: [
		943196208,
		3894986976,
		741149985,
		2753988258,
		3423588291,
		3693006546,
		2956166067,
		3090712752,
		2888798115,
		1612726368,
		1410680145,
		3288844227,
		1141130304,
		1815039843,
		1747667811,
		1478183763,
		3221472195,
		1612857954,
		808649523,
		3023406513,
		673777953,
		2686484640,
		3760374498,
		2754054051,
		3490956243,
		2417066385,
		269549841,
		67503618,
		471600144,
		3158084784,
		875955762,
		1208699715,
		3962556387,
		2282260608,
		1814842464,
		2821228704,
		337053459,
		3288646848,
		336987666,
		4097098992,
		3221406402,
		1141196097,
		3760308705,
		3558262482,
		1010765619,
		1010634033,
		2349764226,
		2551744656,
		673712160,
		1276005954,
		4097230578,
		1010699826,
		2753922465,
		4164536817,
		202181889,
		3693072339,
		3625502928,
		673909539,
		1680229986,
		2017086066,
		606537507,
		741281571,
		4029792753,
		1882342002,
		1073889858,
		3558130896,
		1073824065,
		3221274816,
		1882407795,
		1680295779,
		2888600736,
		2282457987,
		4097296371,
		2888666529,
		2147516544,
		471797523,
		3356150466,
		741084192,
		2821360290,
		875824176,
		3490890450,
		134941443,
		3962490594,
		3895052769,
		1545424209,
		2484372624,
		404228112,
		4164471024,
		1410811731,
		2888732322,
		134744064,
		3288712641,
		269681427,
		3423456705,
		2215020162,
		3090778545,
		4232040435,
		2084392305,
		3221340609,
		808517937,
		4097164785,
		2282392194,
		1747602018,
		2956034481,
		3490824657,
		538968096,
		3558328275,
		131586,
		539099682,
		67372032,
		1747470432,
		1882276209,
		67569411,
		3625700307,
		2619182481,
		2551810449,
		1612792161,
		3158216370,
		3827746530,
		1478052177,
		3692940753,
		1343308113,
		2417000592,
		3692874960,
		2551876242,
		2686682019,
		2821426083,
		3490758864,
		2147582337,
		202313475,
		1141327683,
		404359698,
		3760440291,
		3962359008,
		2349698433,
		3158282163,
		2484504210,
		2017151859,
		1545358416,
		2686616226,
		2686550433,
		1612923747,
		539165475,
		1275940161,
		3356018880,
		2619248274,
		2619116688,
		943327794,
		202116096,
		741215778,
		3090844338,
		1814974050,
		2619314067,
		1478117970,
		4029858546,
		2417132178,
		4029924339,
		1208568129,
		2016954480,
		3423390912,
		336921873,
		4164668403,
		1882210416,
		1949648241,
		2084523891,
		875889969,
		269484048,
		197379,
		1680098400,
		1814908257,
		3288778434,
		1949582448,
		3558196689,
		3023340720,
		3895118562,
		134809857,
		1949714034,
		404293905,
		4231974642,
		1073758272,
		269615634,
		3760242912,
		3158150577,
		67437825,
		4164602610,
		65793,
		4029726960,
		673843746,
		1545490002,
		2821294497,
		1410745938,
		1073955651,
		2214954369,
		336856080,
		2282326401,
		2551942035,
		2955968688,
		3827680737,
		1208502336,
		2017020273,
		2484570003,
		4231843056,
		471731730,
		2147648130,
		539033889,
		2349632640,
		404425491,
		1545555795,
		1949779827,
		1410614352,
		2956100274,
		471665937,
		606405921,
		1276071747,
		0,
		1141261890,
		3962424801,
		1477986384,
		1343373906,
		3895184355,
		2084458098,
		3625634514,
		3356084673,
		4231908849,
		808452144,
		2484438417,
		1680164193,
		1010568240,
		3023472306,
		3827614944,
		3090910131,
		2084326512,
		202247682,
		1343242320,
		943262001,
		606471714,
		808583730,
		2214888576,
		1747536225,
		2417197971,
		876021555,
		3827812323,
		606340128,
		2753856672,
		3356216259,
		1343439699,
		134875650,
		2215085955,
		3625568721,
		1275874368,
		2147713923,
		2349830019,
		3423522498,
		943393587,
		1208633922,
		3023538099
	],
	SS2: [
		2712152457,
		2172913029,
		3537114822,
		3553629123,
		1347687492,
		287055117,
		2695638156,
		556016901,
		1364991309,
		1128268611,
		270014472,
		303832590,
		1364201793,
		4043062476,
		3267889866,
		1667244867,
		539502600,
		1078199364,
		538976256,
		2442927501,
		3772784832,
		3806339778,
		3234334920,
		320083719,
		2711889285,
		2206994319,
		50332419,
		1937259339,
		3015195531,
		319820547,
		3536851650,
		3807129294,
		1886400576,
		2156661900,
		859586319,
		2695374984,
		842019330,
		3520863693,
		4076091078,
		1886663748,
		3773574348,
		2442401157,
		50858763,
		1398019911,
		1348213836,
		1398283083,
		2981903757,
		16777473,
		539239428,
		270277644,
		1936732995,
		2425886856,
		269488128,
		3234598092,
		4075827906,
		3520600521,
		539765772,
		3823380423,
		1919955522,
		2206204803,
		2476219275,
		3520074177,
		2189690502,
		3251112393,
		1616912448,
		1347424320,
		2745181059,
		3823643595,
		17566989,
		2998154886,
		2459704974,
		1129058127,
		3014932359,
		1381505610,
		3267626694,
		1886926920,
		2728666758,
		303043074,
		2745970575,
		3520337349,
		1633689921,
		3284140995,
		2964599940,
		1094713665,
		1380979266,
		1903967565,
		2173439373,
		526344,
		320610063,
		2442664329,
		0,
		286791945,
		263172,
		1397756739,
		4092868551,
		3789562305,
		4059839949,
		1920218694,
		590098191,
		589571847,
		2964336768,
		2206731147,
		34344462,
		2745707403,
		2728403586,
		1651256910,
		2475692931,
		1095503181,
		1634216265,
		1887190092,
		17303817,
		34081290,
		3015458703,
		3823906767,
		4092605379,
		3250849221,
		2206467975,
		269751300,
		4076617422,
		1617175620,
		3537641166,
		573320718,
		1128794955,
		303569418,
		33818118,
		555753729,
		1667771211,
		1650730566,
		33554946,
		4059313605,
		2458915458,
		2189953674,
		789516,
		3014669187,
		1920745038,
		3503296704,
		1920481866,
		1128531783,
		2459178630,
		3789825477,
		572794374,
		2155872384,
		2712415629,
		3554418639,
		2711626113,
		808464384,
		859059975,
		2729193102,
		842282502,
		286528773,
		572531202,
		808990728,
		4042536132,
		2745444231,
		1094976837,
		1078725708,
		2172649857,
		3790088649,
		2156135556,
		2475956103,
		825505029,
		3284667339,
		3268153038,
		809253900,
		1903178049,
		286265601,
		3284404167,
		2173176201,
		1903441221,
		4093131723,
		3537377994,
		4042799304,
		2425623684,
		1364728137,
		2189427330,
		3234071748,
		4093394895,
		1095240009,
		825768201,
		1667508039,
		3233808576,
		3284930511,
		3553892295,
		2964863112,
		51121935,
		2190216846,
		1111491138,
		589308675,
		2442137985,
		1617701964,
		3554155467,
		2695111812,
		808727556,
		4059050433,
		1078462536,
		3267363522,
		1668034383,
		826031373,
		556543245,
		1077936192,
		2998681230,
		842808846,
		2965126284,
		3250586049,
		2728929930,
		2998418058,
		1112280654,
		1364464965,
		859323147,
		3504086220,
		1617438792,
		1937522511,
		2426150028,
		3503823048,
		1112017482,
		1381242438,
		1936996167,
		2694848640,
		3790351821,
		1111754310,
		2981377413,
		589835019,
		1633953093,
		4076354250,
		3823117251,
		2981640585,
		2981114241,
		2476482447,
		1381768782,
		4059576777,
		3806602950,
		2997891714,
		825241857,
		3806866122,
		1634479437,
		1398546255,
		3773048004,
		4042272960,
		3251375565,
		2156398728,
		303306246,
		842545674,
		1347950664,
		3503559876,
		1650467394,
		556280073,
		50595591,
		858796803,
		3773311176,
		320346891,
		17040645,
		1903704393,
		2425360512,
		1650993738,
		573057546,
		2459441802
	],
	SS3: [
		137377848,
		3370182696,
		220277805,
		2258805798,
		3485715471,
		3469925406,
		2209591347,
		2293282872,
		2409868335,
		1080057888,
		1162957845,
		3351495687,
		1145062404,
		1331915823,
		1264805931,
		1263753243,
		3284385795,
		1113743394,
		53686323,
		2243015733,
		153167913,
		2158010400,
		3269648418,
		2275648551,
		3285438483,
		2173800465,
		17895441,
		100795398,
		202382364,
		2360392764,
		103953462,
		1262700555,
		3487820847,
		2290124808,
		1281387564,
		2292230184,
		118690839,
		3300967428,
		101848086,
		3304125492,
		3267543042,
		1161905157,
		3252805665,
		3335705622,
		255015999,
		221330493,
		2390920206,
		2291177496,
		136325160,
		1312967694,
		3337810998,
		238173246,
		2241963045,
		3388078137,
		218172429,
		3486768159,
		3369130008,
		186853419,
		1180853286,
		1249015866,
		119743527,
		253963311,
		3253858353,
		1114796082,
		1111638018,
		3302020116,
		1094795265,
		3233857536,
		1131638835,
		1197696039,
		2359340076,
		2340653067,
		3354653751,
		2376182829,
		2155905024,
		252910623,
		3401762826,
		203435052,
		2325915690,
		70267956,
		3268595730,
		184748043,
		3470978094,
		3387025449,
		1297177629,
		2224067604,
		135272472,
		3371235384,
		1196643351,
		2393025582,
		134219784,
		3317810181,
		51580947,
		3452029965,
		2256700422,
		2310125625,
		3488873535,
		1299283005,
		3250700289,
		20000817,
		3320968245,
		2323810314,
		1247963178,
		2175905841,
		3251752977,
		2105376,
		3352548375,
		33685506,
		35790882,
		67109892,
		1214277672,
		1097953329,
		117638151,
		3419658267,
		2375130141,
		2308020249,
		1096900641,
		2394078270,
		3336758310,
		1230067737,
		3453082653,
		1095847953,
		2156957712,
		3436239900,
		2324863002,
		2208538659,
		2342758443,
		3234910224,
		2172747777,
		251857935,
		1195590663,
		168957978,
		3286491171,
		3437292588,
		2374077453,
		2410921023,
		2257753110,
		1265858619,
		1280334876,
		2191695906,
		2174853153,
		1130586147,
		52633635,
		1296124941,
		3368077320,
		2391972894,
		2358287388,
		171063354,
		201329676,
		237120558,
		2326968378,
		1315073070,
		2408815647,
		1246910490,
		3270701106,
		2190643218,
		3287543859,
		1229015049,
		1215330360,
		3435187212,
		85005333,
		3421763643,
		1081110576,
		1165063221,
		1332968511,
		87110709,
		1052688,
		50528259,
		1147167780,
		1298230317,
		3334652934,
		1148220468,
		3318862869,
		2226172980,
		3403868202,
		151062537,
		1181905974,
		152115225,
		3472030782,
		1077952512,
		34738194,
		3235962912,
		2377235517,
		83952645,
		3404920890,
		16842753,
		3237015600,
		170010666,
		1314020382,
		2309072937,
		1179800598,
		1128480771,
		2239857669,
		68162580,
		2306967561,
		2341705755,
		2159063088,
		3319915557,
		1212172296,
		1232173113,
		2274595863,
		3438345276,
		236067870,
		2189590530,
		18948129,
		2357234700,
		185800731,
		1330863135,
		1198748727,
		1146115092,
		2192748594,
		219225117,
		86058021,
		1329810447,
		0,
		1178747910,
		3454135341,
		1213224984,
		1112690706,
		3420710955,
		1316125758,
		3402815514,
		3384920073,
		3455188029,
		3158064,
		2240910357,
		1164010533,
		204487740,
		2259858486,
		3303072804,
		2343811131,
		1282440252,
		235015182,
		1079005200,
		154220601,
		102900774,
		36843570,
		2223014916,
		1231120425,
		2207485971,
		120796215,
		3353601063,
		69215268,
		2225120292,
		3418605579,
		1129533459,
		167905290,
		2273543175,
		3385972761,
		1279282188,
		2206433283,
		2407762959,
		3468872718,
		187906107,
		1245857802,
		2276701239
	],
	KC: [
		2654435769,
		1013904243,
		2027808486,
		4055616972,
		3816266649,
		3337566003,
		2380164711,
		465362127,
		930724254,
		1861448508,
		3722897016,
		3150826737,
		2006686179,
		4013372358,
		3731777421,
		3168587547
	]
};
//#endregion
//#region src/util.ts
var KISA_ENC_DEC = class KISA_ENC_DEC {
	static {
		this._KISA_ENCRYPT = 0;
	}
	static {
		this._KISA_DECRYPT = 1;
	}
	constructor(value) {
		this.value = value;
	}
	static {
		this.KISA_ENCRYPT = new KISA_ENC_DEC(KISA_ENC_DEC._KISA_ENCRYPT);
	}
	static {
		this.KISA_DECRYPT = new KISA_ENC_DEC(KISA_ENC_DEC._KISA_DECRYPT);
	}
};
var KISA_SEED_KEY = class {
	constructor() {
		this.key_data = new Array(32).fill(0);
	}
	init() {
		this.key_data.fill(0);
	}
};
var KISA_SEED_INFO = class {
	constructor() {
		this.ivec = new Array(4).fill(0);
		this.seed_key = new KISA_SEED_KEY();
		this.cbc_buffer = new Array(4).fill(0);
		this.buffer_length = 0;
		this.cbc_last_block = new Array(4).fill(0);
		this.last_block_flag = 0;
		this.encrypt = 0;
		this.ivec.fill(0);
		this.seed_key.init();
		this.cbc_buffer.fill(0);
		this.buffer_length = 0;
		this.cbc_last_block.fill(0);
		this.last_block_flag = 0;
	}
};
//#endregion
//#region src/index.ts
var KISA_SEED_CBC = class KISA_SEED_CBC {
	static {
		this.ENDIAN = Common.BIG_ENDIAN;
	}
	static {
		this.BLOCK_SIZE_SEED = 16;
	}
	static {
		this.BLOCK_SIZE_SEED_INT = 4;
	}
	static Subst(A) {
		return defaults.SS0[A & 255] ^ defaults.SS1[A >> 8 & 255] ^ defaults.SS2[A >> 16 & 255] ^ defaults.SS3[A >> 24 & 255];
	}
	static SeedRound(T, LR, L0, L1, R0, R1, K, K_offset) {
		T[0] = LR[R0] ^ K[K_offset + 0];
		T[1] = LR[R1] ^ K[K_offset + 1];
		T[1] ^= T[0];
		T[1] = KISA_SEED_CBC.Subst(T[1]);
		T[0] += T[1];
		T[0] = KISA_SEED_CBC.Subst(T[0]);
		T[1] += T[0];
		T[1] = KISA_SEED_CBC.Subst(T[1]);
		T[0] += T[1];
		LR[L0] ^= T[0];
		LR[L1] ^= T[1];
	}
	static EndianChange(dwS) {
		return (dwS << 8 | dwS >> 24 & 255) & 16711935 | (dwS << 24 | dwS >> 8 & 16777215) & 4278255360;
	}
	static RoundKeyUpdate0(T, K, K_offset, ABCD, KC) {
		T[0] = ABCD[0] + ABCD[2] - KC;
		T[1] = ABCD[1] + KC - ABCD[3];
		K[K_offset + 0] = KISA_SEED_CBC.Subst(T[0]);
		K[K_offset + 1] = KISA_SEED_CBC.Subst(T[1]);
		T[0] = ABCD[0];
		ABCD[0] = ABCD[0] >> 8 & 16777215 ^ ABCD[1] << 24;
		ABCD[1] = ABCD[1] >> 8 & 16777215 ^ T[0] << 24;
	}
	static RoundKeyUpdate1(T, K, K_offset, ABCD, KC) {
		T[0] = ABCD[0] + ABCD[2] - KC;
		T[1] = ABCD[1] + KC - ABCD[3];
		K[K_offset + 0] = KISA_SEED_CBC.Subst(T[0]);
		K[K_offset + 1] = KISA_SEED_CBC.Subst(T[1]);
		T[0] = ABCD[2];
		ABCD[2] = ABCD[2] << 8 ^ ABCD[3] >> 24 & 255;
		ABCD[3] = ABCD[3] << 8 ^ T[0] >> 24 & 255;
	}
	static BLOCK_XOR_CBC(OUT_VALUE, out_value_offset, IN_VALUE1, in_value1_offset, IN_VALUE2, in_value2_offset) {
		OUT_VALUE[out_value_offset + 0] = (in_value1_offset < IN_VALUE1.length ? IN_VALUE1[in_value1_offset + 0] : 0) ^ (in_value2_offset < IN_VALUE2.length ? IN_VALUE2[in_value2_offset + 0] : 0);
		OUT_VALUE[out_value_offset + 1] = (in_value1_offset + 1 < IN_VALUE1.length ? IN_VALUE1[in_value1_offset + 1] : 0) ^ (in_value2_offset + 1 < IN_VALUE2.length ? IN_VALUE2[in_value2_offset + 1] : 0);
		OUT_VALUE[out_value_offset + 2] = (in_value1_offset + 2 < IN_VALUE1.length ? IN_VALUE1[in_value1_offset + 2] : 0) ^ (in_value2_offset + 2 < IN_VALUE2.length ? IN_VALUE2[in_value2_offset + 2] : 0);
		OUT_VALUE[out_value_offset + 3] = (in_value1_offset + 3 < IN_VALUE1.length ? IN_VALUE1[in_value1_offset + 3] : 0) ^ (in_value2_offset + 3 < IN_VALUE2.length ? IN_VALUE2[in_value2_offset + 3] : 0);
	}
	static {
		this.LR_L0 = 0;
	}
	static {
		this.LR_L1 = 1;
	}
	static {
		this.LR_R0 = 2;
	}
	static {
		this.LR_R1 = 3;
	}
	static KISA_SEED_Encrypt_Block_forCBC(inData, in_offset, outData, out_offset, ks) {
		let LR = new Array(4);
		let T = new Array(2);
		let K = ks.key_data;
		LR[KISA_SEED_CBC.LR_L0] = inData[in_offset + 0];
		LR[KISA_SEED_CBC.LR_L1] = inData[in_offset + 1];
		LR[KISA_SEED_CBC.LR_R0] = inData[in_offset + 2];
		LR[KISA_SEED_CBC.LR_R1] = inData[in_offset + 3];
		if (Common.BIG_ENDIAN !== KISA_SEED_CBC.ENDIAN) {
			LR[KISA_SEED_CBC.LR_L0] = KISA_SEED_CBC.EndianChange(LR[KISA_SEED_CBC.LR_L0]);
			LR[KISA_SEED_CBC.LR_L1] = KISA_SEED_CBC.EndianChange(LR[KISA_SEED_CBC.LR_L1]);
			LR[KISA_SEED_CBC.LR_R0] = KISA_SEED_CBC.EndianChange(LR[KISA_SEED_CBC.LR_R0]);
			LR[KISA_SEED_CBC.LR_R1] = KISA_SEED_CBC.EndianChange(LR[KISA_SEED_CBC.LR_R1]);
		}
		for (let i = 0; i < 16; i++) KISA_SEED_CBC.SeedRound(T, LR, i % 2 === 0 ? KISA_SEED_CBC.LR_L0 : KISA_SEED_CBC.LR_R0, i % 2 === 0 ? KISA_SEED_CBC.LR_L1 : KISA_SEED_CBC.LR_R1, i % 2 === 0 ? KISA_SEED_CBC.LR_R0 : KISA_SEED_CBC.LR_L0, i % 2 === 0 ? KISA_SEED_CBC.LR_R1 : KISA_SEED_CBC.LR_L1, K, i * 2);
		if (Common.BIG_ENDIAN !== KISA_SEED_CBC.ENDIAN) {
			LR[KISA_SEED_CBC.LR_L0] = KISA_SEED_CBC.EndianChange(LR[KISA_SEED_CBC.LR_L0]);
			LR[KISA_SEED_CBC.LR_L1] = KISA_SEED_CBC.EndianChange(LR[KISA_SEED_CBC.LR_L1]);
			LR[KISA_SEED_CBC.LR_R0] = KISA_SEED_CBC.EndianChange(LR[KISA_SEED_CBC.LR_R0]);
			LR[KISA_SEED_CBC.LR_R1] = KISA_SEED_CBC.EndianChange(LR[KISA_SEED_CBC.LR_R1]);
		}
		outData[out_offset + 0] = LR[KISA_SEED_CBC.LR_R0];
		outData[out_offset + 1] = LR[KISA_SEED_CBC.LR_R1];
		outData[out_offset + 2] = LR[KISA_SEED_CBC.LR_L0];
		outData[out_offset + 3] = LR[KISA_SEED_CBC.LR_L1];
	}
	static KISA_SEED_Decrypt_Block_forCBC(input, in_offset, outData, out_offset, ks) {
		let LR = new Array(4);
		let T = new Array(2);
		let K = ks.key_data;
		LR[KISA_SEED_CBC.LR_L0] = input[in_offset + 0];
		LR[KISA_SEED_CBC.LR_L1] = input[in_offset + 1];
		LR[KISA_SEED_CBC.LR_R0] = input[in_offset + 2];
		LR[KISA_SEED_CBC.LR_R1] = input[in_offset + 3];
		if (Common.BIG_ENDIAN !== KISA_SEED_CBC.ENDIAN) {
			LR[KISA_SEED_CBC.LR_L0] = KISA_SEED_CBC.EndianChange(LR[KISA_SEED_CBC.LR_L0]);
			LR[KISA_SEED_CBC.LR_L1] = KISA_SEED_CBC.EndianChange(LR[KISA_SEED_CBC.LR_L1]);
			LR[KISA_SEED_CBC.LR_R0] = KISA_SEED_CBC.EndianChange(LR[KISA_SEED_CBC.LR_R0]);
			LR[KISA_SEED_CBC.LR_R1] = KISA_SEED_CBC.EndianChange(LR[KISA_SEED_CBC.LR_R1]);
		}
		for (let i = 15; i >= 0; i--) KISA_SEED_CBC.SeedRound(T, LR, i % 2 === 1 ? KISA_SEED_CBC.LR_L0 : KISA_SEED_CBC.LR_R0, i % 2 === 1 ? KISA_SEED_CBC.LR_L1 : KISA_SEED_CBC.LR_R1, i % 2 === 1 ? KISA_SEED_CBC.LR_R0 : KISA_SEED_CBC.LR_L0, i % 2 === 1 ? KISA_SEED_CBC.LR_R1 : KISA_SEED_CBC.LR_L1, K, i * 2);
		if (Common.BIG_ENDIAN !== KISA_SEED_CBC.ENDIAN) {
			LR[KISA_SEED_CBC.LR_L0] = KISA_SEED_CBC.EndianChange(LR[KISA_SEED_CBC.LR_L0]);
			LR[KISA_SEED_CBC.LR_L1] = KISA_SEED_CBC.EndianChange(LR[KISA_SEED_CBC.LR_L1]);
			LR[KISA_SEED_CBC.LR_R0] = KISA_SEED_CBC.EndianChange(LR[KISA_SEED_CBC.LR_R0]);
			LR[KISA_SEED_CBC.LR_R1] = KISA_SEED_CBC.EndianChange(LR[KISA_SEED_CBC.LR_R1]);
		}
		outData[out_offset + 0] = LR[KISA_SEED_CBC.LR_R0];
		outData[out_offset + 1] = LR[KISA_SEED_CBC.LR_R1];
		outData[out_offset + 2] = LR[KISA_SEED_CBC.LR_L0];
		outData[out_offset + 3] = LR[KISA_SEED_CBC.LR_L1];
	}
	static chartoint32_for_SEED_CBC(input, inLen) {
		let len;
		if (inLen % 4 > 0) len = Math.floor(inLen / 4) + 1;
		else len = inLen / 4;
		let data = new Array(len).fill(0);
		for (let i = 0; i < len; i++) Common.byte_to_int(data, i, input, i * 4, Common.ENDIAN);
		return data;
	}
	static int32tochar_for_SEED_CBC(input, inLen) {
		let data = new Uint8Array(inLen * 4);
		if (Common.ENDIAN !== Common.BIG_ENDIAN) for (let i = 0; i < data.length; i++) data[i] = input[Math.floor(i / 4)] >> i % 4 * 8 & 255;
		else for (let i = 0; i < data.length; i++) data[i] = input[Math.floor(i / 4)] >> (3 - i % 4) * 8 & 255;
		return data;
	}
	static SEED_CBC_init(pInfo, enc, pbszUserKey, pbszIV) {
		let ABCD = new Array(4);
		let T = new Array(2);
		let K;
		if (!pInfo || !pbszUserKey || !pbszIV) return 0;
		K = pInfo.seed_key.key_data;
		pInfo.encrypt = enc.value;
		Common.memcpy(pInfo.ivec, pbszIV, 16, KISA_SEED_CBC.ENDIAN);
		pInfo.last_block_flag = pInfo.buffer_length = 0;
		ABCD[0] = Common.byte_to_int(pbszUserKey, 0, KISA_SEED_CBC.ENDIAN);
		ABCD[1] = Common.byte_to_int(pbszUserKey, 4, KISA_SEED_CBC.ENDIAN);
		ABCD[2] = Common.byte_to_int(pbszUserKey, 8, KISA_SEED_CBC.ENDIAN);
		ABCD[3] = Common.byte_to_int(pbszUserKey, 12, KISA_SEED_CBC.ENDIAN);
		if (Common.BIG_ENDIAN != KISA_SEED_CBC.ENDIAN) {
			ABCD[0] = KISA_SEED_CBC.EndianChange(ABCD[0]);
			ABCD[1] = KISA_SEED_CBC.EndianChange(ABCD[1]);
			ABCD[2] = KISA_SEED_CBC.EndianChange(ABCD[2]);
			ABCD[3] = KISA_SEED_CBC.EndianChange(ABCD[3]);
		}
		for (let i = 0; i < 15; i++) if (i % 2 === 0) KISA_SEED_CBC.RoundKeyUpdate0(T, K, i * 2, ABCD, defaults.KC[i]);
		else KISA_SEED_CBC.RoundKeyUpdate1(T, K, i * 2, ABCD, defaults.KC[i]);
		T[0] = ABCD[0] + ABCD[2] - defaults.KC[15];
		T[1] = ABCD[1] - ABCD[3] + defaults.KC[15];
		K[30] = KISA_SEED_CBC.Subst(T[0]);
		K[31] = KISA_SEED_CBC.Subst(T[1]);
		return 1;
	}
	static SEED_CBC_Process(pInfo, input, inLen, output, outLen) {
		let nCurrentCount = KISA_SEED_CBC.BLOCK_SIZE_SEED;
		let pdwXOR;
		let in_offset = 0;
		let out_offset = 0;
		let pdwXOR_offset = 0;
		if (!pInfo || !input || !output || inLen < 0) return 0;
		if (KISA_ENC_DEC._KISA_ENCRYPT == pInfo.encrypt) {
			pdwXOR = pInfo.ivec;
			in_offset = 0;
			out_offset = 0;
			pdwXOR_offset = 0;
			while (nCurrentCount <= inLen) {
				KISA_SEED_CBC.BLOCK_XOR_CBC(output, out_offset, input, in_offset, pdwXOR, pdwXOR_offset);
				KISA_SEED_CBC.KISA_SEED_Encrypt_Block_forCBC(output, out_offset, output, out_offset, pInfo.seed_key);
				pdwXOR = output;
				pdwXOR_offset = out_offset;
				nCurrentCount += KISA_SEED_CBC.BLOCK_SIZE_SEED;
				in_offset += KISA_SEED_CBC.BLOCK_SIZE_SEED_INT;
				out_offset += KISA_SEED_CBC.BLOCK_SIZE_SEED_INT;
			}
			outLen[0] = nCurrentCount - KISA_SEED_CBC.BLOCK_SIZE_SEED;
			pInfo.buffer_length = inLen - outLen[0];
			Common.memcpy(pInfo.ivec, pdwXOR, KISA_SEED_CBC.BLOCK_SIZE_SEED, pdwXOR_offset);
			Common.memcpy(pInfo.cbc_buffer, input, pInfo.buffer_length, in_offset);
		} else {
			pdwXOR = pInfo.ivec;
			in_offset = 0;
			out_offset = 0;
			pdwXOR_offset = 0;
			while (nCurrentCount <= inLen) {
				KISA_SEED_CBC.KISA_SEED_Decrypt_Block_forCBC(input, in_offset, output, out_offset, pInfo.seed_key);
				KISA_SEED_CBC.BLOCK_XOR_CBC(output, out_offset, output, out_offset, pdwXOR, pdwXOR_offset);
				pdwXOR = input;
				pdwXOR_offset = in_offset;
				nCurrentCount += KISA_SEED_CBC.BLOCK_SIZE_SEED;
				in_offset += KISA_SEED_CBC.BLOCK_SIZE_SEED_INT;
				out_offset += KISA_SEED_CBC.BLOCK_SIZE_SEED_INT;
			}
			outLen[0] = nCurrentCount - KISA_SEED_CBC.BLOCK_SIZE_SEED;
			Common.memcpy(pInfo.ivec, pdwXOR, KISA_SEED_CBC.BLOCK_SIZE_SEED, pdwXOR_offset);
			Common.memcpy(pInfo.cbc_last_block, output, KISA_SEED_CBC.BLOCK_SIZE_SEED, out_offset - KISA_SEED_CBC.BLOCK_SIZE_SEED_INT);
		}
		return 1;
	}
	static SEED_CBC_Close(pInfo, output, out_offset, outLen) {
		let nPaddngLeng;
		let i;
		outLen[0] = 0;
		if (null == output) return 0;
		if (KISA_ENC_DEC._KISA_ENCRYPT == pInfo.encrypt) {
			nPaddngLeng = KISA_SEED_CBC.BLOCK_SIZE_SEED - pInfo.buffer_length;
			for (i = pInfo.buffer_length; i < KISA_SEED_CBC.BLOCK_SIZE_SEED; i++) Common.set_byte_for_int(pInfo.cbc_buffer, i, nPaddngLeng & 255, KISA_SEED_CBC.ENDIAN);
			KISA_SEED_CBC.BLOCK_XOR_CBC(pInfo.cbc_buffer, 0, pInfo.cbc_buffer, 0, pInfo.ivec, 0);
			KISA_SEED_CBC.KISA_SEED_Encrypt_Block_forCBC(pInfo.cbc_buffer, 0, output, out_offset, pInfo.seed_key);
			outLen[0] = KISA_SEED_CBC.BLOCK_SIZE_SEED;
			return 1;
		} else {
			nPaddngLeng = Common.get_byte_for_int(pInfo.cbc_last_block, KISA_SEED_CBC.BLOCK_SIZE_SEED - 1, KISA_SEED_CBC.ENDIAN);
			if (nPaddngLeng > 0 && nPaddngLeng <= KISA_SEED_CBC.BLOCK_SIZE_SEED) {
				for (i = nPaddngLeng; i > 0; i--) Common.set_byte_for_int(output, out_offset - i, 0, KISA_SEED_CBC.ENDIAN);
				outLen[0] = nPaddngLeng;
			} else return 0;
		}
		return 1;
	}
	static SEED_CBC_Encrypt(pbszUserKey, pbszIV, message, message_offset, message_length) {
		const info = new KISA_SEED_INFO();
		let outbuf;
		let data;
		let cdata;
		let outlen;
		let nRetOutLeng = [0];
		let nPaddingLeng = [0];
		const pbszPlainText = message.slice(message_offset, message_offset + message_length);
		const nPlainTextLen = pbszPlainText.length;
		const nPlainTextPadding = KISA_SEED_CBC.BLOCK_SIZE_SEED - nPlainTextLen % KISA_SEED_CBC.BLOCK_SIZE_SEED;
		const newpbszPlainText = new Uint8Array(nPlainTextLen + nPlainTextPadding);
		Common.arraycopy(newpbszPlainText, pbszPlainText, nPlainTextLen);
		const pbszCipherText = new Uint8Array(newpbszPlainText.length);
		KISA_SEED_CBC.SEED_CBC_init(info, KISA_ENC_DEC.KISA_ENCRYPT, pbszUserKey, pbszIV);
		outlen = newpbszPlainText.length / KISA_SEED_CBC.BLOCK_SIZE_SEED * KISA_SEED_CBC.BLOCK_SIZE_SEED_INT;
		outbuf = new Array(outlen);
		data = KISA_SEED_CBC.chartoint32_for_SEED_CBC(newpbszPlainText, nPlainTextLen);
		KISA_SEED_CBC.SEED_CBC_Process(info, data, nPlainTextLen, outbuf, nRetOutLeng);
		KISA_SEED_CBC.SEED_CBC_Close(info, outbuf, Math.floor(nRetOutLeng[0] / 4), nPaddingLeng);
		cdata = KISA_SEED_CBC.int32tochar_for_SEED_CBC(outbuf, nRetOutLeng[0] + nPaddingLeng[0]);
		Common.arraycopy(pbszCipherText, cdata, nRetOutLeng[0] + nPaddingLeng[0]);
		return pbszCipherText;
	}
	static SEED_CBC_Decrypt(pbszUserKey, pbszIV, message, message_offset, message_length) {
		let info = new KISA_SEED_INFO();
		let outbuf;
		let data;
		let cdata;
		let outlen;
		let nRetOutLeng = [0];
		let nPaddingLeng = [0];
		const pbszCipherText = message.slice(message_offset, message_offset + message_length);
		let nCipherTextLen = pbszCipherText.length;
		if (pbszCipherText.length % KISA_SEED_CBC.BLOCK_SIZE_SEED !== 0) return /* @__PURE__ */ new Uint8Array(0);
		let newpbszCipherText = new Uint8Array(nCipherTextLen);
		Common.arraycopy(newpbszCipherText, pbszCipherText, nCipherTextLen);
		nCipherTextLen = newpbszCipherText.length;
		KISA_SEED_CBC.SEED_CBC_init(info, KISA_ENC_DEC.KISA_DECRYPT, pbszUserKey, pbszIV);
		outlen = nCipherTextLen / 16 * 4;
		outbuf = new Array(outlen);
		data = KISA_SEED_CBC.chartoint32_for_SEED_CBC(newpbszCipherText, nCipherTextLen);
		KISA_SEED_CBC.SEED_CBC_Process(info, data, nCipherTextLen, outbuf, nRetOutLeng);
		if (KISA_SEED_CBC.SEED_CBC_Close(info, outbuf, nRetOutLeng[0], nPaddingLeng) == 1) {
			cdata = KISA_SEED_CBC.int32tochar_for_SEED_CBC(outbuf, nRetOutLeng[0] - nPaddingLeng[0]);
			let pbszPlainText = new Uint8Array(nRetOutLeng[0] - nPaddingLeng[0]);
			Common.arraycopy(pbszPlainText, cdata, nRetOutLeng[0] - nPaddingLeng[0]);
			let pdmessage_length = nRetOutLeng[0] - nPaddingLeng[0];
			let result = new Uint8Array(pdmessage_length);
			result = pbszPlainText.slice(0, pdmessage_length);
			return result;
		} else return /* @__PURE__ */ new Uint8Array(0);
	}
	static stringToUint8Array(str) {
		return new TextEncoder().encode(str);
	}
	static uint8ArrayToString(uint8Array) {
		return new TextDecoder("utf-8", { fatal: true }).decode(uint8Array);
	}
	static base64ToUint8Array(base64) {
		return new Uint8Array(Buffer.from(base64, "base64"));
	}
	static uint8ArrayToBase64(uint8Array) {
		return Buffer.from(uint8Array).toString("base64");
	}
	static encrypt(pbszUserKey, pbszIV, message_str) {
		const message = KISA_SEED_CBC.stringToUint8Array(message_str);
		return KISA_SEED_CBC.encryptBytes(pbszUserKey, pbszIV, message);
	}
	static encryptBytes(pbszUserKey, pbszIV, message) {
		const pbszUserKeyUint8Array = KISA_SEED_CBC.base64ToUint8Array(pbszUserKey);
		const pbszIVUint8Array = KISA_SEED_CBC.base64ToUint8Array(pbszIV);
		const result = KISA_SEED_CBC.SEED_CBC_Encrypt(pbszUserKeyUint8Array, pbszIVUint8Array, message, 0, message.length);
		return KISA_SEED_CBC.uint8ArrayToBase64(result);
	}
	static decryptBytes(pbszUserKey, pbszIV, base64_str) {
		const pbszUserKeyUint8Array = KISA_SEED_CBC.base64ToUint8Array(pbszUserKey);
		const pbszIVUint8Array = KISA_SEED_CBC.base64ToUint8Array(pbszIV);
		const message = KISA_SEED_CBC.base64ToUint8Array(base64_str);
		return KISA_SEED_CBC.SEED_CBC_Decrypt(pbszUserKeyUint8Array, pbszIVUint8Array, message, 0, message.length);
	}
	static decrypt(pbszUserKey, pbszIV, base64_str) {
		const result = KISA_SEED_CBC.decryptBytes(pbszUserKey, pbszIV, base64_str);
		return KISA_SEED_CBC.uint8ArrayToString(result);
	}
};
//#endregion
exports.KISA_SEED_CBC = KISA_SEED_CBC;

//# sourceMappingURL=index.js.map