use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::Path;

use hex::{decode, encode as hex_encode};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature, SecretKey};
use qpb_consensus::{
    OutPoint, Prevout, Transaction, TxIn, TxOut, build_p2qpkh, build_p2qtsh, qpb_sighash, qpkh32,
    qtap_leaf_hash, qtap_reconstruct_root,
};
use serde_json::json;

// Fixed ML-DSA keypair (Dilithium3) for deterministic vectors.
const MLDSA_PK_HEX: &str = "473570fd15836e8a522351e76dd57286e07c78d68ec5a64ccedaa729c6ec211ef73cff2a33e0c3d93916ba0dd73721c3ef39167b728f1f8f6fec77ac5a36793c2be31d0678b87c16d477351df5108e67221bd17e7e4eff7be3e227a4ed5244e5a893446217255b0ae65af323c7856f893bd706a73f3db6074a68f0b76e3f543eae422e92399a82b5b58d0d39d2c8079671c2a62d0b0b405e05f2ac48bee8fafab190ddce65c0e414ed67c245813ad4da281778a57bef628d625219cede649d9ac4f494aa6e836ebbbfd154a626b991f436d384aaa3c7a8289374ba21277a394984c3459f1ead432a5b24a5f51efd672e381b44a46021f6247a500e8c783ba6395f8c97476aff5fe795e5128b330e5783cd1a62fa36c7f54a620bd15f3f04e5c7104adcc02d47fe70771490062d55e79fe7a763ac4b4c7ea598c6cb9e8554bfcf21e9a176d02e4ad6e430c23333a41bc8c47149d97cbb3e02ef7ef5aaa4104fbc5497bb99f91942393753ec70793c72b26601a7c9fa881660d78520a60ffaa5b0f4fe5f0fac4714ce7635995242b8e2978969efd14e28dc779872f7f51d8cb783444322ba4f3c6af6093d680c10488ea377ee5e7cdcb1cb5c44f6424befbeaae8a1de892f13df10b667d85a57d942deeb3c698c8d12e33e6ea8eabd375be9e7937c0cc60f1b4e0c5751c3e5891e719b04f32c737db601c461e3642a0c59b0fdd5d03c66a7fbe7679d15d6155b1bccff9957c9158d285ed1c80efeefe7cfc7728a4c1a950689569cb7f0d79358232acccd1d67cca689d9f2192abaf8fb2efffad677247702291782972011a89380c5ebd157f01eb954fb8224283caa5b036b65a3ff8dafd84a64c597e73cc9cdbef737af5c425a94048e875c2461794e5e649aa985583d0f724b2818b7cae5e409fdbd2ea76ee8f77dd70123d7def9d483cf5bef80b0c542639259caf1ec8cc38ab085829b86d6cdbf07ebe72dfc3662df7b0ead5ac7a04dbfccff9d3f1b5382967cac53b33ef9bf8e064a960bbe5eb90d97f81978299c92d97f085d1d8e13a57c33b8326a36031b49dc564f7da41dc04dddf4c6d086ec1184978fe504383f9d1659f4c51a1da02353a1b4b1ef41709fea76d2cbabef8f4b05692164ab7032fe86cb64545b65d0b4b77600355d5319f99d6e854323c04c1ce0610516a07ffb5fe40a9ff7c078199eedf969eb18d6a7d18c1a3c2c06a77bbded6c9ede38720349174b6652c2fc1318d6bf7d122de92020cb2f1a48ba14d155bc888dd6a195dabe864596fb98a680f1d2db62e4454e918fd34237d58cd533f5650e12fb19167e8b6d65e7a82391073d8244032724215489f2132f45266cafb2a8eac6d2d67952ba29a52680e5b01e760d7b8d25334df3b0f01480ad6431e8c2b6163771b0cd6e5f19bc810967fe4e76c859210a9b74d18f9b7b733e318fb3c745242c1455ab0c86be493503bf0924a59c2beb32c47f4b24cae1de9f8bc7d3f5e75cab08c9191c503c7800156608bed880e06c91731f8a553c53e4d39faf8e1e73648317bb44bc207447e6562f1ce04d07d5659b1c4ca8cb64ac297a62be4b78ad084780cd63024607e0833a98430850295910a79c581316f5f4ce1b694754d10e70bda9ed69774005fd790b6ebb1ba974380e22a6259c7da54af949195c30fe793f5be492fcd50a6af7c54e8b87bf94c437d8189ae7961c61d43c4849b1d4a579a3e86da602876e4adc0c27e308442930e89c5cfe88c9712adeafeb1d67c7f0b13e90dfd190492b7d878424da26dae54f3665b5cb0c92dbb729ad6e8cf0e71608e120383a90ab6052085b8a22a9453a8f47829adfb5a6eeeb3aad50ca880fe0809c9c7404e0706c925e6f5d5bed2cf745782e333c79a0c72fd60d44f9e9e202a184eb11e993698bef64a8a2ae092070ff4ff8ce269ae0706d9d39d74646f1e5d92d963d7a5ff7a1125fc5df8f263ecc21ee544f5e63cebf8ed391bf0c2df49ccfa3a0e9dd714b8e6a2476164e67872149526910489dc525a149e079074a557c3acface20f1502a0787b89381d7877e74ba310a91c93143e717659c04c64296ad5a2e5f5d975eaaf7b4779e466a6e27d312b6f6a1306021efc0c68ae8448c390e01909d502eab93bcd52cac5d3d3247000665493069da12ac3b84908244bf663b072f4134ad9540bb655baec434c564807b0efb861d4c38c69ff1dc5eb02322bcba0b3d7c88eaac7523c4a8dfba28fe74eb5c2e56541df2e99ae18fbbd8e4e4889d2dc4cb933d14e0cc1215f3ee06b479b2e004671bef4a0ef94b12bee76fc353d43dd328a787e520ac541c1105813ac0715c179e17d953095cf8e774064ba05d2d297993a0721ab5231b429ec42085142eb060f4124b05cb6a9d05f462838879f48a753fca7bd815bdbb040525334cf66f22eb347d307d3fbe6d4d1b29f7dd000675b4af7fcd13fe425909a745f9dc6611ae830b17a5264490754f6848e44b635c4d04fb243afdece767a4a70a412fc55b5f902ccf5e4877b6e0037c51c66fea58202a0bfcb8dd9e8c96634e3245717119f6ed1e5b6c89ef7e753b7e0d545bbc4ecb4cc048e1c59b517254f5ae02795e99e336d709b79b5aa1781117cd4b97e9626029c28058753587ebec3f4618cd1a3e641cf892856786b20cb82b8bfb156549fe702fed35680d43e49667f2cb123eba009cb5c1f99fd6eb3fcc805896a03ce49c676e45d8570523a00a802da5b794d29882caaaa668c9dc26360";
const MLDSA_SK_HEX: &str = "473570fd15836e8a522351e76dd57286e07c78d68ec5a64ccedaa729c6ec211ef45e04342d2f6a051ee7fb4774831f519728512dc1b7c0a1a61285378e5700c50c0a6ed9ca3eecfafc2bad18f15e857d730b5b6b13b9b6beb1395abba0c4ede6adb371ae3bf652f7f56fecdc3aea3ad4296fe609e0bd78dc1b8d3e85034b13e5576448284178168578342661337437827423155801322130756872472455570446606856182137558254434083504816246373442368818615645258008824448741853134106442040530482212217402878832384550245017723821654218563107237705474774778743754710351722226507465775022668235764155121654474588238251405402787312107548771576581055762035114435058638374606874867074013060633311818476224665807546810701384221884256286541415606280333055611034872864531251032217016313252832048071506545836163674564561643331110448126353044077440272327025582771716707628101074706514785546132357633583464130864332284711003086837010357106834267013076848520607682167818875324230312350665106503174460705060036435678032033658411344757023786748730605534606130403167887867772684446082423443152312113458160315615630142026728714158880612070530058301842010704644616311857576123146851321476148616738184233338726826830830120106372583718058303033830205787726452750510481264174144887056680880777351553602537763574226433153842036722765351383411834723047377861000620844202468185345750003756684143277157757882003181210783166682773377008057727175445543518020435477144210445070148700032818515123045878171874151360506666054726446781533126665431277348564227485565777448324262176527221168762486135517142135804670271353464800143806806738653023380520835713458180735282128155423743332210775377378754401327304345283717130485525422446025221242851546567805262626480136407024235230811735413870074060815128533375821204418882503204563322445158620825207725082055357462008202484330306374082035720320861501528475241656483116445467640076616300532421037770783365516052088427661783333046807140212378230836530675784636661347577037187714038635013471220781670172138317153021522020018506502556354387832136082337120204077588310052288380003404668525428148320365016348363502501542447886052328428653413688857150468021006287245166280523525443176722444725852533660643465267718140684663312442461602816522281683687286842463106346616860561051050251051758254387828864473034153723801387417034805174175158033286245440477515281616826073354163520054650402514610272675574227552507654526386727224618846352770270032138005621847822120576668351866830730250736636713523748501067710708471612301567884720048084587168228202122031017268255241084885622650080725308412882886708633234223611342203506061756815784522270324387545066564804036772002410200062157652851881772060417565781265685276610583343242207588750740265266401638174587836752346416448650730072844108155220358708012553550084651521866851204133424514506127347626517058808116410850611600764588750118768464588700141870317456113172211814282802135431163741280047306620172382141666070330260634403357677070664276132806317007384262377725315570267011211742604843605388784860782710026246343832082062032863536340813415481240853870454754335620161787070240264058142182583747772001456676518ad7f6f299be3ff5e3a4fed8fa45664d4c59b5e723e0c940ba379ee1e93c3569506d7447b5fbf39051111166b592928e220b68cf3ef31e40fb371b6459126308541d84cdfedf2cb24bc4cdf0f1589f94e4bf76f786450ac716e17927419ea862bf3f2db6d0a7617112f76d7039994e828682a265e072032313495f86283432377771f02c99787289715a29c0bd5cae6d8bbc98c51ee18a2d36a153da7bd05e84d83082160efb20a8702acc46e56242f67fb4d97f88311c8f34ae08454692b79da86ad2fc9b9cdf77b4e8ff25c9550de22189ff9e0510c92aab7d9e0d8265bafa373e5541c184665b88ad845fd5fd1fcde89a4e81f9b626359deebb02be33033b53c72beda6d99c85b40dba84e8bed9a86929aa609f823a17ea480d3523739b85cb00b2a7618433110eb69f416059fae33bbc86cc5bf4b58b710e98610979050279191f70fc9c733ad5b227a5eff31a5b75ddb50397aceeb7f27def05b0de67c6ec2a0e5056d1954eea0d2898b85954d96e08e2d3c3b312a0831f4b5271a1fd96f8b5f85ea2382ab282268f5385687aa15a7125f7309819b69e6a211d8ee2d7f066e3930d0e868b3e3d447f145d585e4da1b388c6885d182b8c8663cfb085bab4c4a46cadab3d1ba284756eb7d3832abce6aa7344ed803301f80b577289ba10a6f6b97a4447833abef7d08654bf54bac990a6e4b5db6b846b456caf0f3bce38d0a91dcb4604e3da8b5183e1b3206c40e7f54bd8661d6b067318bc653f5e4a2e94dcb90603180eb5b3bc93945094c3e7d675d24ed6540658c963a648831c11421a8fb83073a12436adf8e9aeebf7e0ebcd6f82127c5cf0115993571ea7461633e3381e9ea64fb396cab4157e702cefede98cb4672c9ee7f823386f81a2824c74ca431d1ade40696280a65a7d1e8f0d72d8b2d5f0a661004bd5ddabb12e2194eaf38244357e19f645d53032641788186a934359397f3b8072ea6986fc79b6b7f8af5e4f7a9cb4e930f13bddeaeb1415d25e4e143e28561fc37b2e162b04e9c31914b1d6ce4fbf97874cc0cebe494e1a80ebb67a655276ebb96ed91ad0059ce776bf0323848cf4de6efc9f973cd16f91de5df7f112806f59c11617e5cff607c557f87b39f735468883d21738e7760358ecc5b57872efad8f8fdfbba95f8cbea7583f222fa124da7be1b40b4a87cb921a3396b917138f3be6007f6b82770396be0850ede7955be6094cdf15525dbda2f1f2eda4a6dbab8c2fb8e0c9807dc43194af7feaf37f9750464c4a0471cf8c2f5bd7c18c5a1b838e733bbc9dd486495a978fcde0a1fc77440cb64aa7921bfee63f2762ff9706b544385370e91b795fa44cb86fe8dcc1039929eb4e0a109a4ce53dbdc44f501dfe3e921ad864cdfcd6ce721284ebfe39cd18776dc6a0e297d264a678deed657a751924c26b9748f5d80eb50d2ac20e3cefad4aef1aed7e7e32f6c3a7394c377af046e0c82faff789cef122ad0e2156bbde83f6517497d62ae0f4bd28b4ef9a13575130867fc0b95f318eebecca6a35cade212f653c827ad23d5f6696e8386fead884fe7e8bb7f62f51706a402055940150110b55801314e103ab5a8702e284de554d8dbb59d9c648665321532508dc9cbb8d505553146bc115dcb94ebbc9c2ddc3b6f8bd7ce66f8fcf6ebf2e57fa912882dcac70c3b8452b4541e0fc59be0b06ed0e9ba99232fdabebb87352ad9fb73900b777dc6470508666e11b91173c5f76902eb05f5c98bbd3615dff375a3ceca09306df81276ba005b0dd5277c81d981ade22d3746a4ca45ded5cce13d7c88bd29cf126575b5ca388ef07b19f61b15cddadf1de6d79e624b829777ab73845f2006192e5f18e281718f7edb92d72c85503e4d7c769de34f617e216101da960f43bb483dbecfc2009e565daa5cdf1b016e467a6a972d96b3d52f01f7b577b88bb3b5612afd42557a1da8c350c40b0429badb91f7f7cab72b55a1dec78e1dcaab30110862e0c0bb842582aadd2c05bd66da78dc36ec66a0a72d4112b3acf7c6bd48deff8836e4166850016765407aa4f4b7b626c766625b06220e2a4d7132759cb7c02a315257b87f59e175433628899b88f4a950abd1b877965a207c27dabb6cefaa957076240dfc5fe8c120af9d212cd127595edd61b662d275bd9c6441b4092922eed9e15ae21820860ee0cf1e0665cab8c139b5f0295722f8bdbe1765354926fdba1d2f4de1c39a34cfc41bae4a822f814b7b8d534126b42f73c28ba50c17a38ccd092945c80049dc956c29e0d0d987ef628ee9a7eac574524eaec70787e4f1cd967daa49aa3d29db7a80b3b02cdaca8523dc70b2a10704314369b1f69927080d34d89ab54546637e3853acdc8ab22af59272e17c4dcfcb5a72af71c39fb18e5f433594254c67ba714d213b993b635892f54588bf762e1414a200a50725f4c4de844f21014cec32b50fbaaa6ffc8ece133da953b47ee80364ef65703d555d3ba2169c5b019eec79db09d9a40a5da1d96971a53b1be4dbf67b33f4ce5874a43641400b7f79028bde64da4a27f1959f3c1c3efba7024f0c5fa83af7886ee7fc7c9b40da0069e2b3d8539347b1563bbdaea4bd455bf566591bd9c12633e28a068533ea56b490175778a1c7fb3a3d323849daa94306984faf574f9ff7bc1f3e889e2b5ba070f338ff050d25395c82537cd215f81437d10af54159d33eb8c9a310d477c3f057258862562aea8f2a5350fcc4182d8a6cd2f7b8111d3f8a16f777b7b7daa44b0a98ae6db7ec5f18b2cecc3ec96be9ae90eb066bb42fe642d348ae72411464ca03c620d6dd002333fa497193a36b6e77cd31b7152b34e5f9d4573acf5c603c38b6fdaec167989ba65cfbd9ae37aeb4fcc7598de0074633baf943ab433ead82480261c56cb95daf765f51b6278d9c6bbbfebdf7a2de77f04d1a2e576081438eea6d598869be9413038e1055b2681bde875377acec108c3c507ea18681a27744286113a67a9674016f7381a4b195f421a9abb34f7df0543f4283aae6f94d9863d8e38f1b32ddc573663f70fb926bfdfbdd4089be78dbccabeebd2e62860025b1f7c22a24d01a5568d7e21e1d3a72f137d97db2aba633f1f05e07c051a472f4b89ac3ee367d7aa063e42681a7aa98c9a3352b7b2c9383562dd3c81e61454b1cb158370f202286cf40371d3adc2dcc6173f00837fcc6013e3c1e7d45eef0032ccb1ffad71d56e365941c21d69cc939a827492aaff580890502350e020a07f143d65abf2a0ad4aa5838b74f5486b68c9e8cbe7857ba2d599f773a47d6b4387c44d44044ff76739d70b89f3e9274f8b8b23f7baa8c774d7c3e8efcd75872f0dac328e9844b34e4fceef478abc23ddaee3dec03ed97e91e675af0068e8e7d74cf25047bd2657483810c7b199305813b102164837fa8ac8cd66cbe34a66a0d694b7c827e0b336cb9d2f649cdc79d01dcf6dc2d997979beadb70502060ae2ffbb9781d95e216f0fa65ecc7ad7e0d18bb843f46b3a3e50d133af5a84df3a503";
fn write_vec(name: &str, value: serde_json::Value) {
    let dir = Path::new("vectors");
    create_dir_all(dir).expect("create vectors dir");
    let path = dir.join(name);
    let mut f = File::create(&path).expect("create vector file");
    let s = serde_json::to_string_pretty(&value).expect("serialize json");
    f.write_all(s.as_bytes()).expect("write json");
}

fn load_mldsa_keys() -> (Vec<u8>, Vec<u8>) {
    let pk = decode(MLDSA_PK_HEX.trim()).expect("pk hex");
    let sk = decode(MLDSA_SK_HEX.trim()).expect("sk hex");
    (pk, sk)
}

fn p2qpkh_vectors() {
    let (pk_bytes, sk_bytes) = load_mldsa_keys();
    let sk_obj = dilithium3::SecretKey::from_bytes(&sk_bytes).expect("sk bytes");
    let mut pk_ser = Vec::with_capacity(1 + pk_bytes.len());
    pk_ser.push(0x11);
    pk_ser.extend_from_slice(&pk_bytes);

    let prevout = OutPoint {
        txid: [1u8; 32],
        vout: 0,
    };
    let spk = build_p2qpkh(qpkh32(&pk_ser));
    let prevouts = vec![Prevout {
        value: 50_0000_0000,
        script_pubkey: spk.clone(),
    }];

    let base_tx = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout,
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1_0000,
            script_pubkey: spk.clone(),
        }],
        lock_time: 0,
    };

    let sighash_type = 0x01u8;
    let msg = qpb_sighash(&base_tx, 0, &prevouts, sighash_type, 0x00, None).unwrap();
    let msg_hex = hex_encode(msg);
    let sig = dilithium3::detached_sign(&msg, &sk_obj);
    let mut sig = sig.as_bytes().to_vec();
    sig.push(sighash_type);

    let mut tx_valid = base_tx.clone();
    tx_valid.vin[0].witness = vec![sig.clone(), pk_ser.clone()];
    let tx_hex = hex_encode(tx_valid.serialize(true));

    let valid = json!({
        "description": "P2QPKH valid spend",
        "tx_hex": tx_hex,
        "input_index": 0,
        "prevouts": [
            {
                "value": prevouts[0].value,
                "script_pubkey_hex": hex_encode(&prevouts[0].script_pubkey),
            }
        ],
        "expected": {
            "valid": true,
            "msg32_hex": msg_hex,
        }
    });
    write_vec("p2qpkh_valid.json", valid);

    // Invalid sig: flip one byte in sig body (not state bytes)
    let mut sig_bad = sig.clone();
    sig_bad[10] ^= 0x01;
    let mut tx_bad = base_tx.clone();
    tx_bad.vin[0].witness = vec![sig_bad, pk_ser.clone()];
    let bad = json!({
        "description": "P2QPKH invalid signature (tampered byte)",
        "tx_hex": hex_encode(tx_bad.serialize(true)),
        "input_index": 0,
        "prevouts": [
            {
                "value": prevouts[0].value,
                "script_pubkey_hex": hex_encode(&prevouts[0].script_pubkey),
            }
        ],
        "expected": {
            "valid": false,
            "msg32_hex": msg_hex,
        }
    });
    write_vec("p2qpkh_invalid_sig.json", bad);

    // Invalid pk_ser length (truncate)
    let mut bad_pk_len = pk_ser.clone();
    bad_pk_len.truncate(10);
    let mut tx_bad_len = base_tx.clone();
    tx_bad_len.vin[0].witness = vec![sig.clone(), bad_pk_len];
    let bad_len = json!({
        "description": "P2QPKH invalid pk_ser length",
        "tx_hex": hex_encode(tx_bad_len.serialize(true)),
        "input_index": 0,
        "prevouts": [
            {
                "value": prevouts[0].value,
                "script_pubkey_hex": hex_encode(&prevouts[0].script_pubkey),
            }
        ],
        "expected": {"valid": false}
    });
    write_vec("p2qpkh_invalid_pkser.json", bad_len);

    // Invalid alg_id 0x21 (reserved)
    let mut pk_alg21 = pk_ser.clone();
    pk_alg21[0] = 0x21;
    let mut tx_alg21 = base_tx.clone();
    tx_alg21.vin[0].witness = vec![sig.clone(), pk_alg21];
    let bad_alg21 = json!({
        "description": "P2QPKH invalid pk_ser alg_id 0x21 (reserved)",
        "tx_hex": hex_encode(tx_alg21.serialize(true)),
        "input_index": 0,
        "prevouts": [
            {
                "value": prevouts[0].value,
                "script_pubkey_hex": hex_encode(&prevouts[0].script_pubkey),
            }
        ],
        "expected": {"valid": false}
    });
    write_vec("p2qpkh_invalid_alg21.json", bad_alg21);

    // Invalid alg_id 0x30 (reserved)
    let mut pk_alg30 = pk_ser.clone();
    pk_alg30[0] = 0x30;
    let mut tx_alg30 = base_tx.clone();
    tx_alg30.vin[0].witness = vec![sig, pk_alg30];
    let bad_alg30 = json!({
        "description": "P2QPKH invalid pk_ser alg_id 0x30 (reserved)",
        "tx_hex": hex_encode(tx_alg30.serialize(true)),
        "input_index": 0,
        "prevouts": [
            {
                "value": prevouts[0].value,
                "script_pubkey_hex": hex_encode(&prevouts[0].script_pubkey),
            }
        ],
        "expected": {"valid": false}
    });
    write_vec("p2qpkh_invalid_alg30.json", bad_alg30);
}

fn p2qtsh_vectors() {
    let leaf_script = vec![0x51]; // OP_1
    let control_block = vec![0x01]; // parity=1, leaf_version=0x00, no merkle path
    let leaf_hash = qtap_leaf_hash(0x00, &leaf_script);
    let qroot = qtap_reconstruct_root(leaf_hash, &[]);
    let spk = build_p2qtsh(qroot);

    let prevouts = [Prevout {
        value: 10_0000,
        script_pubkey: spk.clone(),
    }];

    let tx_valid = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [2u8; 32],
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
            witness: vec![leaf_script.clone(), control_block.clone()],
        }],
        vout: vec![TxOut {
            value: 5_0000,
            script_pubkey: {
                let (pkb, _skb) = load_mldsa_keys();
                let mut pkser = Vec::with_capacity(1 + pkb.len());
                pkser.push(0x11);
                pkser.extend_from_slice(&pkb);
                build_p2qpkh(qpkh32(&pkser))
            },
        }],
        lock_time: 0,
    };

    let tx_hex = hex_encode(tx_valid.serialize(true));
    let valid = json!({
        "description": "P2QTSH valid simple true leaf",
        "tx_hex": tx_hex,
        "input_index": 0,
        "prevouts": [
            {
                "value": prevouts[0].value,
                "script_pubkey_hex": hex_encode(&prevouts[0].script_pubkey),
            }
        ],
        "expected": {"valid": true}
    });
    write_vec("p2qtsh_valid.json", valid);

    // Invalid control block: bad length (not 1 mod 32)
    let bad_control = vec![0x01, 0x02];
    let mut tx_bad = tx_valid.clone();
    tx_bad.vin[0].witness = vec![leaf_script, bad_control];
    let bad = json!({
        "description": "P2QTSH invalid control block length",
        "tx_hex": hex_encode(tx_bad.serialize(true)),
        "input_index": 0,
        "prevouts": [
            {
                "value": prevouts[0].value,
                "script_pubkey_hex": hex_encode(&prevouts[0].script_pubkey),
            }
        ],
        "expected": {"valid": false}
    });
    write_vec("p2qtsh_invalid_control.json", bad);
}

fn main() {
    p2qpkh_vectors();
    p2qtsh_vectors();
}
