use secp256k1::key::SecretKey;
use ssz_rs::Root;
use std::env;
use std::str::FromStr;
use web3::{
    contract::{Contract, Options},
    transports,
    types::{Address, BlockNumber, TransactionParameters, H256, U256},
    Web3,
};

pub async fn sign_and_send(
    web3: &Web3<transports::Http>,
    transaction: TransactionParameters,
    secret_key: SecretKey,
) -> web3::Result<H256> {
    let signed = web3
        .accounts()
        .sign_transaction(transaction, &secret_key)
        .await?;
    let result = web3
        .eth()
        .send_raw_transaction(signed.raw_transaction)
        .await?;
    Ok(result)
}

pub fn eth_to_wei(eth: f64) -> U256 {
    let res = eth * 1_000_000_000_000_000_000.0;
    let res = res as u128;
    U256::from(res)
}

struct Validator {
    validator_public_key: String,
    validator_signature: String,
    withdrawal_credentials: String,
    deposit_data_root: String,
    deposit_message_root: String,
    fork_version: String,
}

struct DepositParams {
    pubkey: Vec<u8>,
    withdrawal_credentials: Vec<u8>,
    signature: Vec<u8>,
    deposit_data_root: Root, //FixedBytes32,
}

// struct ReconstructedKeyFile {
//     pubkey: Vec<u8>,
//     withdrawal_credentials: Vec<u8>,
//     signature: Vec<u8>,
//     amount: U256,
// }

#[tokio::main]
async fn main() -> web3::Result<()> {
    dotenv::dotenv().ok();
    let from_address = Address::from_str("0x36b28dd1Bf3a9328b0Ce8b4E376FD1C4C99d23ba").unwrap();
    //TODO:get url from cli
    let endpoint = env::var("INFURA_RINKEBY_URL").unwrap();
    let transport = web3::transports::Http::new(&endpoint)?;
    let web3 = web3::Web3::new(transport);
    let contract_address =
        Address::from_str(&env::var("CONTRACT_ADDRESS_PRATER").unwrap()).unwrap();
    let contract =
        Contract::from_json(web3.eth(), contract_address, include_bytes!("./abi.json")).unwrap();

    //TODO: get the validator from the cli
    let validator = Validator {
        validator_public_key:"0x90c533f363a7fd67273c6844db18aedb6070a0663cef3424feff056475c4eae6507a02dfee9cb2701830fe0582ec4eab",
        validator_signature:"0x8b79d369d47a02a50311545fe85f0f93cd4f37bfe58fb0a528d1b2860017eaee6a7a401df2bdbfc4762f2ec5f73d24ff1669cbd602f196cec0c5177c7d9f90db44a95329ed7da9ee60d8a7c5ac0e3d66558641ace757f107a355c6de95e5d57a",
        withdrawal_credentials:"0x010000000000000000000000d4bb555d3b0d7ff17c606161b44e372689c14f4b",
        deposit_data_root:"0x9bfd5d69bad9fff557a28a34d0672a2fcef58048144f39057b3bca08b9adf530",
        deposit_message_root: "0xb2edac150b2beb5511b16b7db9230e6ff68e92999e28f05ea855c4fe1b76f7e7",
        fork_version: "0x00001020"
    };

    let reconstructed_key_file = ReconstructedKeyFile {
        pubkey: hex::decode(validator.validator_public_key).unwrap(),
        withdrawal_credentials: hex::decode(validator.withdrawal_credentials).unwrap(),
        signature: hex::decode(validator.validator_signature).unwrap(),
        amount: eth_to_wei(&env::var("PRICE_PER_VALIDATOR").unwrap()).unwrap(),
    };
    let byteRoot = ssz_rs::Merkleized::hash_tree_root(&reconstructed_key_file, context).unwrap();

    // println!("{:?}", byteRoot);

    let params = DepositParams {
        pubkey: reconstructed_key_file.pubkey,
        withdrawal_credentials: reconstructed_key_file.withdrawal_credentials,
        signature: reconstructed_key_file.signature,
        deposit_data_root: byteRoot,
    };

    let depositMethod = contract
        .call("deposit", params, from_address, Options::default())
        .await
        .unwrap();

    // println!("{:#?}", contract);
    let prvk = SecretKey::from_str(&env::var("PRIVATE_KEY").unwrap()).unwrap();

    //addresses of validators that need to be deposited
    let validator_accounts = vec![
        "0x36b28dd1Bf3a9328b0Ce8b4E376FD1C4C99d23ba",
        "0xDD423b7B8f22E890571863e1360B1D704c4Bb01B",
    ];
    let nonce = web3
        .eth()
        .transaction_count(from_address, Some(BlockNumber::Latest))
        .await?;
    let mut transaction_hash = Vec::new();
    for (index, account) in validator_accounts.iter().enumerate() {
        let value = eth_to_wei(0.01);
        let to = Address::from_str(account).unwrap();

        let tx_object = TransactionParameters {
            to: Some(to),
            nonce: Some(nonce + index),
            value,
            ..Default::default()
        };

        let tx_result = sign_and_send(&web3, tx_object, prvk).await?;
        transaction_hash.push(tx_result);
    }

    // println!("Result {:?}", transaction_hash);
    Ok(())
}
