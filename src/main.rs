use std::str::FromStr;

use tss_esapi::{
    abstraction::{ak, cipher::Cipher, ek, DefaultKey},
    attributes::session::SessionAttributesBuilder,
    constants::{
        session_type::SessionType,
        tss::{TPM2_ALG_NULL, TPM2_ST_ATTEST_QUOTE},
    },
    handles::{AuthHandle, KeyHandle, PcrHandle, SessionHandle},
    interface_types::{
        algorithm::{AsymmetricAlgorithm, HashingAlgorithm, SignatureScheme},
        session_handles::AuthSession,
    },
    structures::{
        Digest, DigestValues, EncryptedSecret, IDObject, Name,
        PcrSelectionList, PcrSelectionListBuilder, PcrSlot,
    },
    tcti_ldr::TctiNameConf,
    tss2_esys::{
        Tss2_MU_TPM2B_PUBLIC_Marshal, Tss2_MU_TPMS_ATTEST_Unmarshal,
        Tss2_MU_TPMT_SIGNATURE_Marshal, TPM2B_ATTEST, TPM2B_PUBLIC,
        TPML_DIGEST, TPML_PCR_SELECTION, TPMS_ATTEST, TPMS_SCHEME_HASH,
        TPMT_SIGNATURE, TPMT_SIG_SCHEME, TPMU_SIG_SCHEME,
    },
    utils::{PcrData, Signature},
    Context,
};

const TSS_MAGIC: u32 = 3135029470;

fn create_empty_session(
    ctx: &mut Context,
    ses_type: SessionType,
) -> AuthSession {
    let session = ctx.start_auth_session(
        None,
        None,
        None,
        ses_type,
        Cipher::aes_128_cfb().try_into().unwrap(),
        HashingAlgorithm::Sha256,
    ).unwrap();
    let (ses_attrs, ses_attrs_mask) = SessionAttributesBuilder::new()
        .with_encrypt(true)
        .with_decrypt(true)
        .build();
    ctx.tr_sess_set_attributes(session.unwrap(), ses_attrs, ses_attrs_mask).unwrap();
    session.unwrap()
}

pub(crate) fn activate_credential(
    ctx: &mut Context,
    keyblob: Vec<u8>,
    ak: KeyHandle,
    ek: KeyHandle,
) -> Digest {
    let (credential, secret) = parse_cred_and_secret(keyblob);

    let ek_auth = create_empty_session(ctx, SessionType::Policy);

    // We authorize ses2 with PolicySecret(ENDORSEMENT) as per PolicyA
    let _ = ctx.execute_with_nullauth_session(|context| {
        context.policy_secret(
            ek_auth.try_into().unwrap(),
            AuthHandle::Endorsement,
            Default::default(),
            Default::default(),
            Default::default(),
            None,
        )
    }).unwrap();

 let resp = ctx
        .execute_with_sessions(
            (Some(AuthSession::Password), Some(ek_auth), None),
            |context| context.activate_credential(ak, ek, credential, secret),
        ).unwrap();

    ctx.flush_context(ek.into()).unwrap();

    resp
}

fn parse_cred_and_secret(
    keyblob: Vec<u8>
) -> (IDObject, EncryptedSecret) {
    let magic = u32::from_be_bytes(keyblob[0..4].try_into().unwrap());
    let version = u32::from_be_bytes(keyblob[4..8].try_into().unwrap());

    if magic != TSS_MAGIC {
        panic!("Error parsing cred and secret; TSS_MAGIC number does not match expected value");
    }
    if version != 1 {
        panic!("Error parsing cred and secret; version is not 1");
    }

    let credsize = u16::from_be_bytes(keyblob[8..10].try_into().unwrap());
    let secretsize = u16::from_be_bytes(
        keyblob[(10 + credsize as usize)..(12 + credsize as usize)]
            .try_into()
            .unwrap(),
    );

    let credential = &keyblob[10..(10 + credsize as usize)];
    let secret = &keyblob[(12 + credsize as usize)..];

    let credential = IDObject::try_from(credential).unwrap();
    let secret = EncryptedSecret::try_from(secret).unwrap();

    (credential, secret)
}

fn main() {
    let tcti = TctiNameConf::from_str("/dev/tpmrm0").unwrap();
    let mut context = Context::new(tcti).unwrap();

    let ek_rsa = ek::create_ek_object(&mut context, AsymmetricAlgorithm::Rsa, DefaultKey).unwrap();
    let att_key = ak::create_ak(
        &mut context,
        ek_rsa,
        HashingAlgorithm::Sha256,
        SignatureScheme::RsaSsa, // changed from RsaPsa
        None, // changed from Some(&ak_auth)
        DefaultKey,
    )
    .unwrap();

    let loaded_ak = ak::load_ak(
        &mut context,
        ek_rsa,
        None, // changed from Some(&ak_auth)
        att_key.out_private,
        att_key.out_public,
    )
    .unwrap();

    let (_, key_name, _) = context.read_public(loaded_ak).unwrap();
    let cred = vec![1, 2, 3, 4, 5];
//    let expected = Digest::try_from(vec![1, 2, 3, 4, 5]).unwrap();

     let (credential_blob, secret) = context
        .execute_without_session(|ctx| {
            ctx.make_credential(ek_rsa, cred.try_into().unwrap(), key_name)
        })
        .unwrap();

    // keyblob is a vec<u8>
    let _ = activate_credential(
            &mut context, credential_blob.to_vec(), loaded_ak, ek_rsa,
    );

}
