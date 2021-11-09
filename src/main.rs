use std::str::FromStr;

use tss_esapi::{
    abstraction::{ak, cipher::Cipher, ek, DefaultKey},
    attributes::session::SessionAttributesBuilder,
    constants::session_type::SessionType,
    handles::AuthHandle,
    interface_types::{
        algorithm::{AsymmetricAlgorithm, HashingAlgorithm, SignatureScheme},
        session_handles::AuthSession,
    },
    tcti_ldr::TctiNameConf,
    Context,
};

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

fn main() {
    let tcti = TctiNameConf::from_str("device:/dev/tpmrm0").unwrap();
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

     let (credential_blob, secret) = context
        .execute_without_session(|ctx| {
            ctx.make_credential(ek_rsa, cred.try_into().unwrap(), key_name)
        })
        .unwrap();

    let ek_auth = create_empty_session(&mut context, SessionType::Policy);

    let _ = context.execute_with_nullauth_session(|ctx| {
        ctx.policy_secret(
            ek_auth.try_into().unwrap(),
            AuthHandle::Endorsement,
            Default::default(),
            Default::default(),
            Default::default(),
            None,
        )
    }).unwrap();

    let _ = context
        .execute_with_sessions(
            (Some(AuthSession::Password), Some(ek_auth), None),
            |context| context.activate_credential(loaded_ak, ek_rsa, credential_blob, secret),
        ).unwrap();

    println!("Success!");
}
