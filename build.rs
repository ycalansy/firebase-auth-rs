fn main() {
    tonic_build::compile_protos("proto/appengine/app_identity_service.proto").unwrap();
    tonic_build::compile_protos("proto/remote/remote_api.proto").unwrap();
}
