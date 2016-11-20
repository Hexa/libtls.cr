@[Link("tls")]
lib LibTls
  alias Int = LibC::Int
  alias SizeT = LibC::SizeT
  alias SSizeT = LibC::SSizeT

  type Tls = Void*
  type TlsConfig = Void*

  TLS_PROTOCOL_TLSv1_0 = 1 << 1
  TLS_PROTOCOL_TLSv1_1 = 1 << 2
  TLS_PROTOCOL_TLSv1_2 = 1 << 3
  TLS_PROTOCOL_ALL = (TLS_PROTOCOL_TLSv1_0 | TLS_PROTOCOL_TLSv1_1 | TLS_PROTOCOL_TLSv1_2)

  TLS_WANT_POLLIN = -2
  TLS_WANT_POLLOUT = -3

  fun tls_init : Int
  fun tls_config_error(config: TlsConfig) : UInt8*
  fun tls_error(ctx: Tls) : UInt8*
  fun tls_config_new : TlsConfig
  fun tls_config_free(config: TlsConfig)

  fun tls_config_set_ca_file(config: TlsConfig, ca_file: UInt8*) : Int
  fun tls_config_set_ca_path(config: TlsConfig, ca_path: UInt8*) : Int
  fun tls_config_set_ca_mem(config: TlsConfig, ca: UInt8*, len: SizeT) : Int

  fun tls_config_set_cert_file(config: TlsConfig, cert_file: UInt8*) : Int
  fun tls_config_set_cert_mem(config: TlsConfig, cert: UInt8*, len: SizeT) : Int
  fun tls_config_set_ciphers(config: TlsConfig, ciphers: UInt8*) : Int
  fun tls_config_set_dheparams(config: TlsConfig, params: UInt8*) : Int
  fun tls_config_set_ecdhecurve(config: TlsConfig, name: UInt8*) : Int
  fun tls_config_set_key_file(config: TlsConfig, key_file: UInt8*) : Int
  fun tls_config_set_key_mem(config: TlsConfig, key: UInt8*, len: SizeT) : Int
  fun tls_config_set_keypair_file(config: TlsConfig, cert_file: UInt8*, key_file: UInt8*) : Int
  fun tls_config_set_keypair_mem(config: TlsConfig, cert: UInt8*, cert_len: SizeT, key: UInt8*, key_len: SizeT) : Int
  fun tls_config_set_protocols(config: TlsConfig, protocols: UInt32)
  fun tls_config_set_verify_depth(config: TlsConfig, verify_depth: Int)

  fun tls_config_prefer_ciphers_client(config: TlsConfig)
  fun tls_config_prefer_ciphers_server(config: TlsConfig)

  fun tls_config_insecure_noverifycert(config: TlsConfig)
  fun tls_config_insecure_noverifyname(config: TlsConfig)
  fun tls_config_insecure_noverifytime(config: TlsConfig)
  fun tls_config_verify(config: TlsConfig)

  fun tls_config_verify_client(config: TlsConfig)
  fun tls_config_verify_client_optional(config: TlsConfig)

  fun tls_config_clear_keys(config: TlsConfig)
  fun tls_config_parse_protocols(protocol: UInt32, protostr: UInt8*) : Int

  fun tls_client : Tls
  fun tls_server : Tls
  fun tls_configure(ctx: Tls, config: TlsConfig) : Int
  fun tls_reset(ctx: Tls)
  fun tls_free(ctx: Tls)

  fun tls_accept_fds(ctx: Tls, cctx: Tls*, fd_read: Int, fd_write: Int) : Int
  fun tls_accept_socket(ctx: Tls, cctx: Tls*, socket: Int) : Int
  fun tls_connect(ctx: Tls, host: UInt8*, port: UInt8*) : Int
  fun tls_connect_fds(ctx: Tls, fd_read: Int, fd_write: Int, servername: UInt8*) : Int
  fun tls_connect_servername(ctx: Tls, host: UInt8*, port: UInt8*, servername: UInt8*) : Int
  fun tls_connect_socket(ctx: Tls, s: Int, servername: UInt8*) : Int
  fun tls_handshake(ctx: Tls) : Int
  fun tls_read(ctx: Tls, buf: UInt8*, buflen: SizeT) : SSizeT
  fun tls_write(ctx: Tls, buf: UInt8*, buflen: SizeT) : SSizeT
  fun tls_close(ctx: Tls) : Int

  fun tls_peer_cert_provided(ctx: Tls) : Int
  fun tls_peer_cert_contains_name(ctx: Tls, name: UInt8*) : Int

  fun tls_peer_cert_hash(ctx: Tls) : UInt8*
  fun tls_peer_cert_issuer(ctx: Tls) : UInt8*
  fun tls_peer_cert_subject(ctx: Tls) : UInt8*

  fun tls_peer_cert_notbefore(ctx: Tls) : Int64
  fun tls_peer_cert_notafter(ctx: Tls) : Int64

  fun tls_conn_version(ctx: Tls) : UInt8*
  fun tls_conn_cipher(ctx: Tls) : UInt8*

  fun tls_load_file(file: UInt8*, len: SizeT, password: UInt8*) : UInt8*
end
